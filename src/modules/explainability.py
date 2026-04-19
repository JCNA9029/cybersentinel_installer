# modules/explainability.py

import os
import json
import sqlite3
import datetime
import warnings
import numpy as np

from . import utils
from . import colors

# ── SHAP availability guard ──────────────────────────────────────────────────

try:
    import shap as _shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE LABEL CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Key diagnostic byte values in the 256-byte histogram
_NOTABLE_BYTES = {
    0x00: "Null byte (0x00) — packing/padding density",
    0x0A: "Line Feed (0x0A) — text/script content indicator",
    0x0D: "Carriage Return (0x0D) — Windows text line endings",
    0x20: "Space (0x20) — human-readable string density",
    0x2E: "Period (0x2E) — file extension / domain string indicator",
    0x2F: "Forward slash (0x2F) — URL or Unix path presence",
    0x3A: "Colon (0x3A) — Windows drive path / protocol prefix",
    0x5C: "Backslash (0x5C) — Windows file path presence",
    0x68: "ASCII 'h' — part of 'http' / 'hkey' strings",
    0x90: "NOP instruction (0x90) — shellcode sled indicator",
    0xCC: "INT3 breakpoint (0xCC) — debug trap / shellcode padding",
    0xE8: "CALL opcode (0xE8) — call instruction density (code richness)",
    0xFF: "0xFF byte — high-byte density (native code / DWORD masks)",
    0xFE: "0xFE byte — high-byte density (native code)",
    0x4D: "ASCII 'M' — part of MZ / memory-mapped file strings",
    0x5A: "ASCII 'Z' — part of MZ DOS header signature",
}

# Entropy histogram zone descriptions
_ENTROPY_ZONES = [
    (0,   31,  "Very low entropy band — highly repetitive or null-heavy content"),
    (32,  95,  "Low entropy band — structured but repetitive data"),
    (96,  159, "Medium entropy band — normal compiled code distribution"),
    (160, 223, "High entropy band — compressed or partially encrypted content"),
    (224, 255, "Very high entropy band — packed/encrypted section signature"),
]

# PE Optional Header fields in EMBER2024/thrember order (~62 total)
_PE_HEADER_FIELD_NAMES = [
    # ── COFF Header (7 fields) ────────────────────────────────────────────
    "COFF: compile timestamp — future or epoch-0 timestamps are common in malware",
    "COFF: machine = x86 (one-hot) — 32-bit executable",
    "COFF: machine = x64 (one-hot) — 64-bit executable",
    "COFF: machine = other (one-hot)",
    "COFF: number of sections",
    "COFF: size of optional header",
    "COFF: characteristics bitmask — executable/DLL/stripped flags",
    # ── Optional Header magic (3 fields) ─────────────────────────────────
    "Opt: PE magic = PE32 (32-bit) one-hot",
    "Opt: PE magic = PE32+ (64-bit) one-hot",
    "Opt: PE magic = other one-hot",
    # ── Optional Header scalar fields (26 fields) ─────────────────────────
    "Opt: major linker version",
    "Opt: minor linker version",
    "Opt: size of .text / code section",
    "Opt: size of initialized data sections",
    "Opt: size of uninitialized data (BSS)",
    "Opt: entry point RVA — non-.text EP location suggests packer/injector",
    "Opt: base of code RVA",
    "Opt: base of data RVA",
    "Opt: preferred image base — non-standard base can indicate tampering",
    "Opt: section alignment in memory",
    "Opt: file alignment on disk",
    "Opt: required OS major version",
    "Opt: required OS minor version",
    "Opt: image version (major)",
    "Opt: image version (minor)",
    "Opt: subsystem major version",
    "Opt: subsystem minor version",
    "Opt: total image size in memory",
    "Opt: size of PE headers on disk",
    "Opt: image checksum — zero or invalid is normal in malware",
    "Opt: stack reserve size",
    "Opt: stack commit size",
    "Opt: heap reserve size",
    "Opt: heap commit size",
    "Opt: loader flags",
    "Opt: number of RVA and size entries",
    # ── Subsystem one-hot (11 fields) ────────────────────────────────────
    "Subsystem: unknown — unrecognised subsystem value",
    "Subsystem: native/kernel-mode — uncommon outside drivers (T1014 Rootkit)",
    "Subsystem: Windows GUI — standard desktop application",
    "Subsystem: Windows console (CUI) — command-line application",
    "Subsystem: OS/2 CUI",
    "Subsystem: POSIX CUI",
    "Subsystem: native Win9x driver",
    "Subsystem: Windows CE GUI",
    "Subsystem: EFI application",
    "Subsystem: EFI boot service driver",
    "Subsystem: EFI runtime driver",
    # ── DllCharacteristics one-hot (8 fields) ────────────────────────────
    "DllChar: DYNAMIC_BASE — ASLR enabled (absent = easier to exploit)",
    "DllChar: FORCE_INTEGRITY — code integrity enforcement",
    "DllChar: NX_COMPAT — DEP/NX enabled (absent = shellcode-friendly T1059)",
    "DllChar: NO_ISOLATION — manifest isolation disabled",
    "DllChar: NO_SEH — structured exception handling disabled (shellcode-friendly)",
    "DllChar: NO_BIND — no bound import table",
    "DllChar: WDM_DRIVER — kernel-mode WDM driver flag (T1014 Rootkit)",
    "DllChar: TERMINAL_SERVER_AWARE",
]
# Pad to exactly 62 if the list is shorter due to version differences
while len(_PE_HEADER_FIELD_NAMES) < 62:
    _PE_HEADER_FIELD_NAMES.append(
        f"PE header extended field [{len(_PE_HEADER_FIELD_NAMES) - 55}]"
    )

# First 10 section slots have known conventional names
_KNOWN_SECTION_NAMES = {
    0: ".text (code)",
    1: ".data (initialized data)",
    2: ".rdata (read-only data / imports)",
    3: ".bss (uninitialized data)",
    4: ".rsrc (resources)",
    5: ".reloc (base relocations)",
    6: ".idata (import address table)",
    7: ".edata (export directory)",
    8: ".pdata (exception data)",
    9: ".debug (debug symbols)",
}

# Maps SHAP feature groups to their most relevant MITRE ATT&CK technique
_GROUP_MITRE_MAP = {
    "Byte Frequency Distribution":  ("T1027",     "Obfuscated Files or Information"),
    "Entropy / Packing Indicators": ("T1027.002", "Software Packing"),
    "String Content Analysis":      ("T1071",     "Application Layer Protocol / C2 strings"),
    "General File Properties":      ("T1036",     "Masquerading / Unsigned PE"),
    "PE Header Fields":             ("T1055",     "Process Injection / PE Manipulation"),
    "Section Structure":            ("T1027.002", "Software Packing / Section Encryption"),
    "Import Table (DLLs)":          ("T1059",     "Command and Scripting Interpreter"),
    "Import Table (Functions)":     ("T1106",     "Native API Abuse"),
    "Export Table":                 ("T1129",     "Shared Module Loading"),
    "Extended Features":            ("T1027",     "Obfuscated Files or Information"),
}

# ─────────────────────────────────────────────────────────────────────────────
#  ANALYST NOTE ENGINE
#  Maps feature names + SHAP direction to plain-English analyst interpretations
# ─────────────────────────────────────────────────────────────────────────────

def _get_analyst_note(feature: str, shap_val: float) -> str:
    """
    Returns a plain-English analyst interpretation of a SHAP feature contribution.
    Covers the major EMBER2024 feature groups and maps to MITRE ATT&CK where relevant.
    """
    push_malicious = shap_val > 0
    f = feature.lower()

    # ── Byte frequency features ──────────────────────────────────────────
    if f.startswith("byte freq:"):
        if "nop" in f or "0x90" in f:
            return ("Elevated NOP sled frequency — shellcode padding or ROP chain. "
                    "MITRE T1059: Command and Scripting Interpreter") if push_malicious \
                else "Normal NOP instruction frequency"
        if "int3" in f or "0xcc" in f:
            return ("High INT3 breakpoint density — shellcode padding or anti-debug trick. "
                    "MITRE T1622: Debugger Evasion") if push_malicious \
                else "Normal INT3 frequency"
        if "null byte" in f or "0x00" in f:
            return ("High null-byte density — padded/packed binary or overlay data. "
                    "MITRE T1027: Obfuscated Files or Information") if push_malicious \
                else "Low null density — consistent with native code structure"
        if "backslash" in f:
            return ("High backslash density — many hardcoded Windows file paths. "
                    "Possible dropper or file-based persistence") if push_malicious \
                else "Low file-path density"
        if "call opcode" in f or "0xe8" in f:
            return ("High CALL instruction density — code-rich section (normal in unpacked code)"
                    ) if push_malicious \
                else "Low CALL density — possible data-heavy or compressed section"
        if "0xff" in f or "0xfe" in f:
            return ("High upper-byte density — native code or wide-string heavy binary"
                    ) if push_malicious \
                else "Low upper-byte density"
        # Printable ASCII range heuristic
        if "printable ascii" in f:
            return ("Anomalous printable character frequency — can indicate embedded scripts "
                    "or text payload") if push_malicious \
                else "Normal printable character distribution"
        return ("Byte distribution anomaly detected in this range"
                ) if push_malicious else "Normal byte distribution"

    # ── Entropy histogram features ───────────────────────────────────────
    if f.startswith("entropy hist"):
        if "very high entropy" in f:
            return ("Very high entropy byte pattern — packed, encrypted, or compressed content. "
                    "MITRE T1027.002: Software Packing") if push_malicious \
                else "Low presence of very-high-entropy byte patterns (plaintext-like)"
        if "high entropy" in f:
            return ("High entropy byte distribution — obfuscated or compressed section content. "
                    "MITRE T1027: Obfuscated Files or Information") if push_malicious \
                else "Low high-entropy pattern presence — consistent with normal code"
        if "low entropy" in f or "very low" in f:
            return ("Elevated low-entropy (repetitive/null) byte patterns — "
                    "padding regions typical of packed PE stubs") if push_malicious \
                else "Normal low-entropy pattern presence"
        return ("Entropy distribution anomaly in this band") if push_malicious \
            else "Normal entropy distribution"

    # ── String feature analysis ──────────────────────────────────────────
    if "url string" in f:
        return ("Embedded URL strings present — C2 beaconing or payload download. "
                "MITRE T1071: Application Layer Protocol") if push_malicious \
            else "No embedded URL strings"
    if "registry path" in f:
        return ("Registry path strings present — persistence or config modification. "
                "MITRE T1547: Boot/Logon Autostart | T1112: Modify Registry") if push_malicious \
            else "No registry path strings"
    if "ip address string" in f:
        return ("Hardcoded IP address strings — network IOC, possible C2 infrastructure. "
                "MITRE T1071: Application Layer Protocol") if push_malicious \
            else "No hardcoded IP address strings"
    if "crypto address" in f:
        return ("Cryptocurrency address strings — ransomware payment indicator. "
                "MITRE T1486: Data Encrypted for Impact") if push_malicious \
            else "No cryptocurrency address strings"
    if "file path string" in f:
        return ("Hardcoded file paths — dropper IOC or targeted system path. "
                "MITRE T1036: Masquerading") if push_malicious \
            else "No hardcoded file path strings"
    if "mz" in f and "string" in f:
        return ("MZ/PE header strings present — PE-aware packer or dropper payload"
                ) if push_malicious else "No embedded MZ/PE header strings"
    if "printable char ratio" in f:
        return ("Low printable-character ratio — binary-heavy / packed content. "
                "MITRE T1027: Obfuscated Files or Information") if push_malicious \
            else "High printable ratio — mostly readable string content (normal code)"

    # ── General file properties ──────────────────────────────────────────
    if "digital signature" in f:
        return ("No digital signature — unsigned PE has significantly higher malware base rate. "
                "MITRE T1036.001: Invalid Code Signature") if push_malicious \
            else "Digital signature present — signed binary has lower malware probability"
    if "debug info" in f:
        return ("No debug information — stripped binary typical of release-build malware"
                ) if push_malicious \
            else "Debug information present — less common in production malware"
    if "import count" in f:
        return ("Very low import count — packed/handcrafted PE hiding its API surface. "
                "MITRE T1027: Obfuscated Files or Information") if push_malicious \
            else "Normal imported function count"
    if "export count" in f:
        return ("Exported functions present in non-DLL context — unusual for EXE, "
                "common in shellcode loaders") if push_malicious \
            else "No export anomaly"
    if "tls section" in f:
        return (".tls section present — common in packer stubs and C++ runtime init. "
                "MITRE T1055: Process Injection") if push_malicious \
            else "No .tls section detected"
    if "section count" in f:
        return ("Abnormal section count — very few (packed stub) or many (obfuscated binary). "
                "MITRE T1027.002: Software Packing") if push_malicious \
            else "Normal PE section count"
    if "has relocations" in f:
        return ("Relocation table present — normal for DLLs, unusual anomaly if missing in DLL"
                ) if push_malicious else "No relocation table (normal for position-fixed EXEs)"
    if "file size" in f:
        return ("File size anomaly — extremely small (shellcode dropper) or "
                "large (trojanized installer)") if push_malicious \
            else "File size within normal range for this PE type"

    # ── PE header fields ─────────────────────────────────────────────────
    if "compile timestamp" in f:
        return ("Suspicious compile timestamp — future date, epoch-0, or "
                "deliberately faked timestamp. MITRE T1036: Masquerading") if push_malicious \
            else "Plausible compile timestamp range"
    if "entry point rva" in f:
        return ("Entry point lands outside expected .text region — "
                "packer stub or injected shellcode. MITRE T1055: Process Injection") if push_malicious \
            else "Entry point within expected code section range"
    if "no_seh" in f:
        return ("SEH disabled (NO_SEH) — structured exception handling absent, "
                "shellcode-friendly build. MITRE T1059") if push_malicious \
            else "SEH enabled — normal exception handling"
    if "dynamic_base" in f or "aslr" in f:
        return ("ASLR disabled (no DYNAMIC_BASE) — fixed image base makes exploitation easier. "
                "MITRE T1203: Exploitation for Client Execution") if not push_malicious \
            else "ASLR enabled — expected in modern legitimate software"
    if "nx_compat" in f or "dep" in f:
        return ("DEP/NX disabled — shellcode execution in data pages becomes possible. "
                "MITRE T1059: Command and Scripting Interpreter") if not push_malicious \
            else "DEP/NX enabled — normal for modern executables"
    if "wdm_driver" in f or "kernel" in f and "subsystem" in f:
        return ("Kernel/WDM driver subsystem flag — uncommon in user-mode software. "
                "MITRE T1014: Rootkit") if push_malicious \
            else "Not a kernel/WDM driver"
    if "native" in f and "subsystem" in f:
        return ("Native subsystem (kernel-mode) — bypasses Win32 API layer. "
                "MITRE T1014: Rootkit | T1055: Process Injection") if push_malicious \
            else "Not a native-mode executable"
    if "checksum" in f:
        return ("Invalid or zero PE checksum — most legitimate system files have valid checksums. "
                "MITRE T1036: Masquerading") if push_malicious \
            else "Valid PE checksum present"
    if "image base" in f:
        return ("Non-standard preferred image base — packer or deliberately crafted PE"
                ) if push_malicious else "Standard preferred image base"

    # ── Section structure ────────────────────────────────────────────────
    if "entropy" in f and ("section" in f or any(
            s in f for s in [".text", ".data", ".rdata", ".bss", ".rsrc",
                             ".reloc", ".idata", ".edata", ".pdata", ".debug"])):
        if push_malicious:
            return ("High section entropy — encrypted or packed content in this section. "
                    "MITRE T1027.002: Software Packing")
        return "Low section entropy — consistent with normal uncompressed content"

    if "characteristics" in f and ("section" in f or any(
            s in f for s in [".text", ".data", ".rdata"])):
        return ("Suspicious section memory permissions — RWX sections allow shellcode injection. "
                "MITRE T1055: Process Injection") if push_malicious \
            else "Normal section memory permissions (no RWX anomaly)"

    if "raw size" in f or "virtual size" in f:
        return ("Section size mismatch — large virtual/raw discrepancy suggests "
                "packing or overlay data") if push_malicious \
            else "Section size ratio within normal range"

    # ── Import / Export table hashes ─────────────────────────────────────
    if "dll import hash bucket" in f:
        return ("Unusual DLL import fingerprint — non-standard library combination detected. "
                "MITRE T1106: Native API") if push_malicious \
            else "Common DLL import pattern (matches benign software)"
    if "function import hash bucket" in f:
        return ("Unusual API import fingerprint — rare function combination in this bucket. "
                "MITRE T1106: Native API") if push_malicious \
            else "Common API function import pattern"
    if "export hash bucket" in f:
        return ("Exported function fingerprint matches malware family profile"
                ) if push_malicious else "Export fingerprint consistent with benign DLL"

    # Generic fallback
    return ("Feature contributed to malicious classification — "
            "inspect SHAP magnitude for significance") if push_malicious \
        else "Feature contributed toward benign classification"


# ─────────────────────────────────────────────────────────────────────────────
#  DYNAMIC FEATURE LABEL BUILDER
#
#  Generates analyst-readable labels for any EMBER feature vector length.
#  Covers thrember 0.x (2381 features) and thrember 1.x (2568 features).
# ─────────────────────────────────────────────────────────────────────────────

def _build_feature_labels(n_features: int) -> list[str]:
    """
    Returns a list of human-readable feature label strings, one per feature index.
    Labels are designed to be immediately meaningful to malware analysts.
    """
    labels: list[str] = []

    # ── Group 1: Byte Histogram (256 features) ───────────────────────────
    for i in range(256):
        if i in _NOTABLE_BYTES:
            labels.append(f"Byte freq: {_NOTABLE_BYTES[i]}")
        elif 0x21 <= i <= 0x7E:
            labels.append(f"Byte freq: printable ASCII 0x{i:02X} ('{chr(i)}')")
        elif i <= 0x1F:
            labels.append(f"Byte freq: control character 0x{i:02X}")
        else:
            labels.append(f"Byte freq: binary/high byte 0x{i:02X}")

    # ── Group 2: Byte Entropy Histogram (256 features) ───────────────────
    for i in range(256):
        for lo, hi, desc in _ENTROPY_ZONES:
            if lo <= i <= hi:
                labels.append(f"Entropy hist[{i}]: {desc}")
                break

    # ── Group 3: String Features (~104 features) ─────────────────────────
    for i in range(96):
        labels.append(
            f"String length {i+1} count — short string density" if i < 8
            else f"String length {i+1} count"
        )
    labels += [
        "URL string count — embedded URL / C2 address indicator",
        "Registry path count — persistence or config modification indicator",
        "File path count — hardcoded file path / IOC indicator",
        "MZ/PE header string count — PE-aware packer or dropper indicator",
        "Average string length — longer = more readable content",
        "Printable char ratio — low ratio = packed / binary-heavy PE",
        "IP address string count — hardcoded network IOC",
        "Crypto address string count — ransomware / cryptocurrency indicator",
    ]

    # ── Group 4: General File Info (~10 features) ─────────────────────────
    labels += [
        "File size — very small (shellcode dropper) or large (trojanized installer) is suspicious",
        "Virtual size — total memory footprint when loaded",
        "Has debug info — absent in most stripped/compiled malware",
        "Has relocations — relocation table presence (normal for DLLs)",
        "Has resources — .rsrc section present",
        "Has digital signature — unsigned PE has higher malware probability",
        "Has .tls section — common in packer stubs and C++ runtime initializers",
        "Import count — very low count suggests packed PE hiding its API surface",
        "Export count — exports in non-DLL context is unusual",
        "Section count — abnormal count (too few = packed, too many = layered obfuscation)",
    ]

    # ── Group 5: PE Header Fields (~62 features) ─────────────────────────
    labels += _PE_HEADER_FIELD_NAMES[:62]
    # Defensive padding if label list is behind the expected group start
    while len(labels) < 688:
        labels.append(f"PE header field [{len(labels) - 626}]")

    # ── Group 6: Section Features (51 sections × 5 fields = 255) ─────────
    for s in range(51):
        sname = _KNOWN_SECTION_NAMES.get(s, f"section[{s}]")
        labels.append(f"{sname}: name hash — unusual names may indicate packer-generated sections")
        labels.append(f"{sname}: raw size — size on disk")
        labels.append(f"{sname}: virtual size — size in memory (large gap = overlay/packing)")
        labels.append(f"{sname}: entropy — >7.0 indicates encryption or packing (T1027.002)")
        labels.append(f"{sname}: characteristics — RWX memory permissions (RWX = injection risk)")

    # ── Group 7: Import Table (256 DLL + 1024 function hashes) ──────────
    for i in range(256):
        labels.append(f"DLL import hash bucket[{i}] — imported library fingerprint (T1106)")
    for i in range(1024):
        labels.append(f"Function import hash bucket[{i}] — imported API fingerprint (T1106)")

    # ── Group 8: Export Table (128 function hashes) ───────────────────────
    for i in range(128):
        labels.append(f"Export hash bucket[{i}] — exported function fingerprint")

    # ── Group 9: Extended / Data Directory features ───────────────────────
    ext_start = len(labels)
    for i in range(max(0, n_features - ext_start)):
        labels.append(f"Extended EMBER feature[{i}] — data directory / header ratio field")

    # Defensive pad (should not be needed)
    while len(labels) < n_features:
        labels.append(f"Feature[{len(labels)}]")

    return labels[:n_features]


def _build_group_ranges(n_features: int) -> dict:
    """
    Builds feature group boundary ranges for the actual feature count.
    Boundaries are fixed by the EMBER2024 spec.
    """
    known_groups = {
        "Byte Frequency Distribution":   (0,    255),
        "Entropy / Packing Indicators":  (256,  511),
        "String Content Analysis":       (512,  615),
        "General File Properties":       (616,  625),
        "PE Header Fields":              (626,  687),
        "Section Structure":             (688,  942),
        "Import Table (DLLs)":           (943,  1198),
        "Import Table (Functions)":      (1199, 2222),
        "Export Table":                  (2223, 2350),
    }
    ranges = {}
    last_end = 0
    for name, (start, end) in known_groups.items():
        if start >= n_features:
            break
        actual_end = min(end, n_features - 1)
        ranges[name] = (start, actual_end)
        last_end = actual_end + 1
    if last_end < n_features:
        ranges["Extended Features"] = (last_end, n_features - 1)
    return ranges


# ── DATABASE SCHEMA ──────────────────────────────────────────────────────────

_CREATE_SHAP_TABLE = """
CREATE TABLE IF NOT EXISTS shap_explanations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL,
    filename        TEXT,
    verdict         TEXT,
    score           REAL,
    n_features      INTEGER,
    top_features    TEXT,
    group_summary   TEXT,
    timestamp       TEXT    NOT NULL
)
"""

def _ensure_table():
    """Creates the SHAP explanations table if it does not exist."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(_CREATE_SHAP_TABLE)
            cols = {r[1] for r in conn.execute(
                "PRAGMA table_info(shap_explanations)"
            ).fetchall()}
            if "n_features" not in cols:
                conn.execute(
                    "ALTER TABLE shap_explanations ADD COLUMN n_features INTEGER"
                )
    except sqlite3.Error as e:
        print(f"[-] Explainability: Table creation failed: {e}")


# ── CORE CLASS ───────────────────────────────────────────────────────────────

class SHAPExplainer:
    """
    Computes and stores SHAP feature attributions for every LightGBM verdict.

    Uses TreeExplainer (exact, not approximate) for tree-based models.
    Dynamically adapts to the feature vector dimension produced by the installed
    thrember version — no hardcoded feature count assumptions.
    """

    def __init__(self):
        self._explainer   = None
        self._n_features  = None
        self._feat_labels = None
        self._grp_ranges  = None
        _ensure_table()

    def _get_explainer(self, model) -> object | None:
        """
        Lazily initializes the SHAP TreeExplainer on first use.
        """
        if not _SHAP_AVAILABLE:
            return None
        if self._explainer is None:
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message=".*LightGBM binary classifier.*",
                        category=UserWarning,
                    )
                    self._explainer = _shap.TreeExplainer(model)
            except Exception as e:
                print(f"[-] SHAP: Explainer initialization failed: {e}")
                return None
        return self._explainer

    def _init_labels(self, n_features: int):
        """
        Builds the analyst-readable feature label map and group ranges.
        Called once on first explain() and cached for all subsequent scans.
        """
        if self._n_features == n_features:
            return
        self._n_features  = n_features
        self._feat_labels = _build_feature_labels(n_features)
        self._grp_ranges  = _build_group_ranges(n_features)
        print(f"[*] SHAP: Initialized for {n_features}-dimensional feature vectors.")

    def explain(
        self,
        model,
        features:  np.ndarray,
        sha256:    str,
        filename:  str,
        verdict:   str,
        score:     float,
        top_n:     int = 10,
    ) -> dict | None:
        """
        Runs SHAP TreeExplainer on a single PE feature vector.

        Returns a dict with keys:
            top_features  — list of dicts (feature, feature_idx, shap_value,
                            direction, magnitude, analyst_note)
            group_summary — dict mapping group names to total |SHAP| contribution
            narrative     — multi-line analyst-readable explanation string
            n_features    — detected feature vector dimension
        Returns None if SHAP is unavailable or computation fails.
        """
        if not _SHAP_AVAILABLE:
            return None

        explainer = self._get_explainer(model)
        if explainer is None:
            return None

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=".*LightGBM binary classifier.*",
                    category=UserWarning,
                )
                shap_values = explainer.shap_values(features)

            # ── Normalise output to a flat 1D array ──────────────────────
            if isinstance(shap_values, list):
                if len(shap_values) == 2:
                    sv = np.array(shap_values[1]).flatten()
                else:
                    sv = np.array(shap_values[0]).flatten()
            elif hasattr(shap_values, "values"):
                sv = np.array(shap_values.values).flatten()
            else:
                sv = np.array(shap_values).flatten()

            if sv.ndim > 1:
                sv = sv[0]

            n_features = len(sv)

            if n_features < 100:
                print(f"[-] SHAP: Feature vector too short ({n_features}) — skipping.")
                return None

            self._init_labels(n_features)

            # ── Rank features by absolute SHAP value ─────────────────────
            abs_sv  = np.abs(sv)
            top_idx = np.argsort(abs_sv)[::-1][:top_n]

            top_features = []
            for idx in top_idx:
                shap_val  = float(sv[idx])
                feat_name = self._feat_labels[idx]
                top_features.append({
                    "feature":      feat_name,
                    "feature_idx":  int(idx),
                    "shap_value":   round(shap_val, 4),
                    "direction":    "toward malicious" if shap_val > 0 else "toward safe",
                    "magnitude":    round(float(abs_sv[idx]), 4),
                    "analyst_note": _get_analyst_note(feat_name, shap_val),
                })

            # ── Aggregate by feature group ────────────────────────────────
            group_summary = {}
            for group_name, (start, end) in self._grp_ranges.items():
                contribution = float(np.sum(np.abs(sv[start:end + 1])))
                group_summary[group_name] = round(contribution, 4)

            group_summary = dict(
                sorted(group_summary.items(), key=lambda x: x[1], reverse=True)
            )

            narrative = self._build_narrative(
                top_features[:5], verdict, score, group_summary
            )

            result = {
                "top_features":  top_features,
                "group_summary": group_summary,
                "narrative":     narrative,
                "n_features":    n_features,
            }

            self._persist(sha256, filename, verdict, score,
                          n_features, top_features, group_summary)

            return result

        except Exception as e:
            print(f"[-] SHAP: Explanation failed: {e}")
            return None

    def _build_narrative(
        self,
        top_features:  list,
        verdict:       str,
        score:         float,
        group_summary: dict | None = None,
    ) -> str:
        """
        Builds a structured, analyst-readable explanation of the SHAP verdict.
        Includes feature context, group-level MITRE ATT&CK mapping, and
        a plain-English interpretation of the top drivers.
        """
        if not top_features:
            return "No SHAP explanation available."

        sep = "─" * 62

        # ── Verdict header ───────────────────────────────────────────────
        if "CRITICAL" in verdict:
            verdict_label = f"⚠  CRITICAL RISK  —  {score:.1%} malicious confidence"
        elif "SUSPICIOUS" in verdict:
            verdict_label = f"⚡  SUSPICIOUS  —  {score:.1%} malicious confidence"
        else:
            verdict_label = f"✔  SAFE  —  {score:.1%} malicious confidence"

        lines = [
            sep,
            f"  SHAP ANALYSIS: {verdict_label}",
            sep,
            "",
            "  TOP CONTRIBUTING FEATURES:",
            "",
        ]

        # ── Per-feature breakdown ────────────────────────────────────────
        for i, feat in enumerate(top_features, 1):
            push = feat["shap_value"] > 0
            arrow   = "▲ MALICIOUS" if push else "▼ BENIGN"
            impact  = feat["magnitude"]
            fname   = feat["feature"]
            note    = feat.get("analyst_note", "")

            lines.append(f"  [{i}] {fname}")
            lines.append(f"       {arrow}  |  SHAP impact: {impact:.4f}")
            if note:
                lines.append(f"       💡 {note}")
            lines.append("")

        # ── Group-level MITRE summary ────────────────────────────────────
        if group_summary:
            lines += [sep, "  FEATURE GROUP BREAKDOWN (by total SHAP contribution):", ""]
            for grp, total in list(group_summary.items())[:4]:
                mitre_id, mitre_name = _GROUP_MITRE_MAP.get(grp, ("—", "—"))
                lines.append(
                    f"  • {grp:<38}  Σ={total:.4f}  [{mitre_id}]"
                )
            lines.append("")

        # ── Plain-English interpretation ─────────────────────────────────
        lines += [sep, "  ANALYST INTERPRETATION:", ""]

        malicious_feats = [f for f in top_features if f["shap_value"] > 0]
        safe_feats      = [f for f in top_features if f["shap_value"] < 0]

        if "CRITICAL" in verdict or "SUSPICIOUS" in verdict:
            if malicious_feats:
                top_push = malicious_feats[0]
                lines.append(
                    f"  Primary malicious driver: {top_push['feature'][:55]}"
                )
                note = top_push.get("analyst_note", "")
                if note:
                    lines.append(f"  → {note}")
            if safe_feats:
                top_pull = safe_feats[0]
                lines.append(
                    f"\n  Strongest benign indicator: {top_pull['feature'][:55]}"
                )
        else:
            if safe_feats:
                top_pull = safe_feats[0]
                lines.append(
                    f"  Primary safe indicator: {top_pull['feature'][:55]}"
                )
                note = top_pull.get("analyst_note", "")
                if note:
                    lines.append(f"  → {note}")

        lines += ["", sep]
        return "\n".join(lines)

    def _persist(
        self,
        sha256:        str,
        filename:      str,
        verdict:       str,
        score:         float,
        n_features:    int,
        top_features:  list,
        group_summary: dict,
    ):
        """Stores the SHAP explanation in the database for later retrieval."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """
                    INSERT INTO shap_explanations
                        (sha256, filename, verdict, score, n_features,
                         top_features, group_summary, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256, filename, verdict, score, n_features,
                        json.dumps(top_features),
                        json.dumps(group_summary),
                        now,
                    )
                )
        except sqlite3.Error as e:
            print(f"[-] SHAP: Persist failed: {e}")

    def get_explanation(self, sha256: str) -> dict | None:
        """Retrieves a previously computed SHAP explanation from the database."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    """
                    SELECT sha256, filename, verdict, score,
                           top_features, group_summary, timestamp
                    FROM   shap_explanations
                    WHERE  sha256 = ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (sha256,)
                ).fetchone()
            if not row:
                return None
            return {
                "sha256":        row[0],
                "filename":      row[1],
                "verdict":       row[2],
                "score":         row[3],
                "top_features":  json.loads(row[4]),
                "group_summary": json.loads(row[5]),
                "timestamp":     row[6],
            }
        except Exception:
            return None

    def get_recent_explanations(self, limit: int = 50) -> list:
        """Returns recent SHAP explanations for the GUI history table."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    """
                    SELECT sha256, filename, verdict, score,
                           top_features, group_summary, timestamp
                    FROM   shap_explanations
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [
                {
                    "sha256":        r[0],
                    "filename":      r[1],
                    "verdict":       r[2],
                    "score":         r[3],
                    "top_features":  json.loads(r[4]),
                    "group_summary": json.loads(r[5]),
                    "timestamp":     r[6],
                }
                for r in rows
            ]
        except Exception:
            return []


# ── MODULE-LEVEL SINGLETON ───────────────────────────────────────────────────

_instance: SHAPExplainer | None = None

def get_explainer() -> SHAPExplainer:
    """Returns the module-level SHAPExplainer singleton."""
    global _instance
    if _instance is None:
        _instance = SHAPExplainer()
    return _instance
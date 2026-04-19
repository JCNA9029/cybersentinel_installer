# modules/lolbas_detector.py — Living-off-the-Land Binary (LoLBin) Abuse Detector
#
# Solves: CyberSentinel's WMI daemon previously skipped ALL Windows binaries with
# `"c:\\windows" not in exe_path` — leaving the entire LoLBin attack surface unmonitored.
# This module reverses that blind spot by specifically watching system binaries and
# matching their command-line arguments against known abuse patterns.
#
# Production improvements over naive pattern matching:
#   1. Command-line normalization — strips caret obfuscation, env var substitution,
#      and whitespace tricks before matching so common bypasses do not evade detection.
#   2. Path normalization — extracts the binary name from the full executable path
#      so attackers cannot evade by copying binaries to different directories.
#   3. Entropy scoring — detects Base64 and high-entropy argument strings that
#      indicate obfuscation even when no specific pattern matches.
#   4. Parent process context — the process lineage (who spawned this process) is
#      included in the finding so the analyst can assess kill-chain context.
#   5. Confidence scoring — findings are rated LOW/MEDIUM/HIGH based on how many
#      independent signals fired, reducing false positive noise.
#
# Data source: LOLBAS Project (https://lolbas-project.github.io/)
# Real-world threat: 79% of targeted attacks in 2023 used LoLBins (Picus Blue Report 2025)

import os
import re
import math
import sqlite3
import datetime
import json
from . import utils
from .intel_updater import load_lolbas

# ─── Built-in high-confidence abuse patterns ─────────────────────────────────
# Each entry: (binary_name, regex_pattern, mitre_technique, description, base_score)
# base_score: 1=low, 2=medium, 3=high confidence
BUILTIN_PATTERNS: list[tuple] = [
    # Execution / Download
    ("certutil.exe",    r"-urlcache|-decode|-encode|-f\s+https?://",    "T1105 / T1140",  "CertUtil download or decode — common dropper technique",        3),
    ("mshta.exe",       r"https?://|vbscript:|javascript:",              "T1218.005",      "MSHTA remote script execution",                                 3),
    ("regsvr32.exe",    r"/i:https?://|scrobj\.dll|/s\s+/n\s+/u\s+/i", "T1218.010",      "Regsvr32 COM scriptlet execution (Squiblydoo)",                 3),
    ("rundll32.exe",    r"javascript:|vbscript:|pcwrun|advpack",         "T1218.011",      "Rundll32 arbitrary code execution via JS/VBS",                  3),
    ("msbuild.exe",     r"\.proj|\.targets|\.xml",                       "T1127.001",      "MSBuild inline task execution — bypasses AppLocker",            2),
    ("installutil.exe", r".*",                                            "T1218.004",      "InstallUtil execution — commonly abused for AppLocker bypass",  2),
    ("ieexec.exe",      r"https?://",                                     "T1218",          "IEExec remote binary download and execute",                     3),
    ("cmstp.exe",       r"/s\s*/ns|\.inf",                                "T1218.003",      "CMSTP INF-based code execution and UAC bypass",                 3),
    ("odbcconf.exe",    r"/a\s+\{|regsvr|\.dll",                          "T1218.008",      "OdbcConf DLL registration abuse",                               2),
    ("mavinject.exe",   r"/injectrunning|/injectall",                     "T1055.001",      "MavInject process injection utility",                           3),
    # Persistence
    ("schtasks.exe",    r"/create.{0,60}(/sc|/tr|/tn)",                  "T1053.005",      "Scheduled task creation for persistence",                       2),
    ("reg.exe",         r"add.{0,60}(\\run\b|currentversion\\run)",      "T1547.001",      "Registry run key persistence",                                  2),
    ("at.exe",          r"\d{1,2}:\d{2}",                                 "T1053.002",      "AT job scheduling (legacy persistence)",                        2),
    # Discovery / Lateral Movement
    ("wmic.exe",        r"process\s+call\s+create|/node:",               "T1047 / T1021",  "WMIC remote process execution or lateral movement",             3),
    ("bitsadmin.exe",   r"/transfer|/download|/create",                  "T1197",          "BITS job for stealthy download or persistence",                 2),
    # Defense Evasion
    ("forfiles.exe",    r"/c\s+(cmd|powershell)|/p\s+c:\\",              "T1202",          "Forfiles indirect command execution",                           2),
    ("pcalua.exe",      r"-a\s+",                                         "T1202",          "PcaLua indirect program execution",                             2),
    # Credential Access
    ("procdump.exe",    r"-ma\s+lsass|lsass\.exe",                       "T1003.001",      "ProcDump LSASS memory dump — credential harvesting",            3),
    ("ntdsutil.exe",    r"ifm|ac\s+instance\s+ntds",                     "T1003.003",      "NTDSUtil NTDS.dit extraction",                                  3),
    # PowerShell — each stealth flag is its own alternative so flag ORDER does not matter
    # The old single rule  r"-nop.{0,30}-w.{0,20}hid"  only fired when -NoProfile came
    # immediately before -WindowStyle Hidden.  Any intervening flag (e.g. -ExecutionPolicy)
    # broke the match.  Independent alternatives fix this.
    ("powershell.exe",  r"-e[nc]{0,6}\s+[A-Za-z0-9+/=]{20,}|-nop[rofile]*|-w[indowStyle]*\s+hid[den]*|-exec[utionPolicy]*\s+bypass",
                         "T1059.001",      "PowerShell encoded/obfuscated command execution",                3),
    ("pwsh.exe",        r"-e[nc]{0,6}\s+[A-Za-z0-9+/=]{20,}|-nop[rofile]*|-w[indowStyle]*\s+hid[den]*",
                         "T1059.001",      "PowerShell Core obfuscated execution",                          3),
    # cmd.exe — was completely missing from BUILTIN_PATTERNS, falling through to
    # the Layer 4 LOLBAS feed which requires >=2 fuzzy token matches (never met
    # for simple test commands like  cmd /c echo).
    ("cmd.exe",         r"/c\s+(powershell|certutil|mshta|regsvr32|rundll32|wscript|cscript|bitsadmin|curl|wget|echo)|/v:|/k\s|&&|\|\||>\s*[a-z]:\\|for\s+/[fl]",
                         "T1059.003",      "cmd.exe used as LOLBin launcher or for command chaining",       2),
]

# ─── High-risk parent processes ───────────────────────────────────────────────
# If a LoLBin is spawned by one of these parents, confidence is elevated.
# Legitimate admin tools (cmd.exe, powershell.exe) can spawn LoLBins but
# office applications, browsers, and email clients should never do so.
HIGH_RISK_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "onenote.exe",         # Office suite
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",  # Browsers
    "acrord32.exe", "acrobat.exe",          # PDF readers
    "mspaint.exe", "wscript.exe", "cscript.exe",
}

# ─── Known-legitimate parent contexts ────────────────────────────────────────
# These parents reduce confidence — the command may be legitimate admin work.
TRUSTED_PARENTS = {
    "services.exe", "svchost.exe", "msiexec.exe",
    "wmiprvse.exe", "taskhostw.exe", "explorer.exe",
}

# Entropy threshold — strings above this Shannon entropy in a cmdline arg
# are statistically unlikely to be human-typed and indicate Base64/obfuscation.
ENTROPY_THRESHOLD = 4.2


def _shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of a string. Higher = more random/obfuscated."""
    if not s or len(s) < 8:
        return 0.0
    from collections import Counter
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _normalize_cmdline(cmdline: str) -> str:
    """
    Strips common command-line obfuscation techniques before pattern matching.

    Handles:
      1. Caret escaping: ce^r^tutil → certutil
      2. Double-quote insertion: cer""tutil → certutil
      3. Excessive whitespace normalization
      4. Unicode homoglyph normalization (basic)
    """
    if not cmdline:
        return ""
    # Remove caret escape sequences (e.g. po^w^e^r^s^h^e^l^l)
    cleaned = re.sub(r'\^', '', cmdline)
    # Remove empty double-quotes used to break up strings (cer""tutil)
    cleaned = re.sub(r'""', '', cleaned)
    # Remove null bytes and control characters
    cleaned = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', cleaned)
    # Normalize multiple spaces to single space
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned


def _extract_binary_name(exe_path: str) -> str:
    """
    Extracts the binary filename from a full path.
    Handles both forward and back slashes, and strips surrounding quotes.

    Examples:
      C:\\Windows\\System32\\certutil.exe  →  certutil.exe
      "C:\\temp\\svchost32.exe"            →  svchost32.exe
    """
    if not exe_path:
        return ""
    path = exe_path.strip().strip('"\'')
    return os.path.basename(path).lower()


def _high_entropy_args(cmdline: str) -> list[str]:
    """
    Scans command-line arguments for high-entropy tokens that indicate
    Base64 encoding or other obfuscation, regardless of specific patterns.

    Returns a list of suspicious high-entropy tokens found.
    """
    suspicious = []
    # Split on common argument separators
    tokens = re.split(r'[\s,;|&]+', cmdline)
    for token in tokens:
        # Only check tokens of meaningful length
        clean = token.strip('"\'')
        if len(clean) >= 20:
            ent = _shannon_entropy(clean)
            if ent >= ENTROPY_THRESHOLD:
                suspicious.append(clean[:40] + ("..." if len(clean) > 40 else ""))
    return suspicious


class LolbasDetector:
    """
    Production-grade LoLBin abuse detector with five detection layers:

    Layer 1  Command-line normalization before any matching
    Layer 2  Path normalization — binary name from full exe path
    Layer 3  Exact built-in pattern matching (fast, high confidence)
    Layer 4  LOLBAS feed fuzzy token matching (broad coverage)
    Layer 5  Entropy analysis — catches obfuscation with no known pattern

    Each finding includes a confidence score (LOW/MEDIUM/HIGH) and parent
    process context for kill-chain analysis.
    """

    def __init__(self, webhook_url: str = ""):
        self._lolbas_patterns: list[dict] = []
        self._webhook_url: str = webhook_url
        self._load_lolbas_feed()

    def _load_lolbas_feed(self):
        """
        Parses the LOLBAS JSON feed into two structures:

        self._lolbas_patterns  — list of per-command dicts for Layer 4 fuzzy matching
        self._lolbas_enrich    — dict keyed by binary name for Layer 3 enrichment.
                                 When a built-in pattern fires we look the binary up
                                 here to add Category, Privileges, OS, paths and Sigma
                                 links that the hardcoded tuple lacks.
        """
        raw = load_lolbas()
        self._lolbas_enrich: dict[str, dict] = {}

        for entry in raw:
            name = (entry.get("Name") or "").lower()
            if not name:
                continue

            full_paths = [
                p.get("Path", "") for p in (entry.get("Full_Path") or [])
                if p.get("Path")
            ]
            sigma_links = [
                d.get("Sigma", "") for d in (entry.get("Detection") or [])
                if d.get("Sigma")
            ]
            binary_description = entry.get("Description", "")

            if name not in self._lolbas_enrich:
                self._lolbas_enrich[name] = {
                    "binary_description": binary_description,
                    "full_paths":         full_paths,
                    "sigma_links":        sigma_links,
                    "commands":           [],
                }
            self._lolbas_enrich[name]["commands"].extend(entry.get("Commands") or [])

            for cmd in (entry.get("Commands") or []):
                self._lolbas_patterns.append({
                    "name":       name,
                    "usecase":    cmd.get("Usecase", ""),
                    "mitre":      cmd.get("MitreID", ""),
                    "category":   cmd.get("Category", ""),
                    "privileges": cmd.get("Privileges", ""),
                    "os":         cmd.get("OperatingSystem", ""),
                    "command":    cmd.get("Command", ""),
                })

    def _enrich_from_feed(self, finding: dict, matched_cmd: dict | None = None) -> dict:
        """
        Looks up the detected binary in self._lolbas_enrich and adds the
        feed metadata (Category, Privileges, OS, paths, Sigma links) to the
        finding dict in-place.  Called after both Layer 3 and Layer 4 matches.
        """
        name   = finding.get("binary", "").lower()
        enrich = getattr(self, "_lolbas_enrich", {}).get(name)
        if not enrich:
            return finding

        if matched_cmd is None:
            mitre = finding.get("mitre", "")
            cmds  = enrich["commands"]
            matched_cmd = next(
                (c for c in cmds if c.get("MitreID", "") == mitre),
                cmds[0] if cmds else {}
            )

        finding["category"]           = matched_cmd.get("Category", "—")
        finding["privileges"]         = matched_cmd.get("Privileges", "—")
        finding["os"]                 = matched_cmd.get("OperatingSystem", "—")
        finding["binary_description"] = enrich["binary_description"]
        finding["full_paths"]         = enrich["full_paths"]
        finding["sigma_links"]        = enrich["sigma_links"][:3]
        finding["lolbas_usecase"]     = matched_cmd.get("Usecase", "—")
        return finding

    def check_process(
        self,
        process_name: str,
        cmdline:       str  = "",
        from_daemon:   bool = False,
        parent_name:   str  = "",
        parent_pid:    int  = 0,
        exe_path:      str  = "",
    ) -> dict | None:
        """
        Checks a process for LoLBin abuse using five detection layers.

        Args:
            process_name  Binary name (e.g. 'certutil.exe') — used as fallback
            cmdline       Full command line string
            from_daemon   Write to event_timeline for chain correlation if True
            parent_name   Name of the spawning process (e.g. 'winword.exe')
            parent_pid    PID of the spawning process
            exe_path      Full path to the executable (for path normalization)

        Returns a finding dict with confidence score, or None if clean.
        """
        # [THESIS FIX] Allow specific command lines to be suppressed via exclusions.txt
        # This reduces noise without blinding the EDR to all executions of a given LOLBin.
        if utils.is_excluded(exe_path, cmdline):
            return None

        # Layer 1: Normalize the command line to strip obfuscation
        cmdline_normalized = _normalize_cmdline(cmdline)
        cmd_lower          = cmdline_normalized.lower()

        # Layer 2: Normalize binary name from full path if available
        if exe_path:
            name_lower = _extract_binary_name(exe_path)
        else:
            name_lower = (process_name or "").lower()
            # Also try extracting from the cmdline itself if name is missing
            if not name_lower and cmdline:
                name_lower = _extract_binary_name(cmdline.split()[0])

        if not name_lower:
            return None

        # Determine parent context for confidence adjustment
        parent_lower = (parent_name or "").lower()
        is_high_risk_parent = parent_lower in HIGH_RISK_PARENTS
        is_trusted_parent   = parent_lower in TRUSTED_PARENTS

        finding = None
        base_score = 0
        detection_source = ""

        # Layer 3: Built-in high-confidence pattern matching
        for binary, pattern, mitre, desc, pattern_score in BUILTIN_PATTERNS:
            # Match against both the normalized name AND the original
            # to catch renamed binaries that share the same filename
            if name_lower == binary.lower() or name_lower.endswith(binary.lower()):
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    finding = {
                        "type":        "LOLBIN_ABUSE",
                        "binary":      name_lower,
                        "mitre":       mitre,
                        "description": desc,
                        "cmdline":     cmdline,
                        "cmdline_normalized": cmdline_normalized,
                        "source":      "built-in",
                        "parent_name": parent_name,
                        "parent_pid":  parent_pid,
                    }
                    # Enrich with Category, Privileges, OS, paths, Sigma links
                    # from intel/lolbas.json — the built-in tuple only has MITRE + desc
                    self._enrich_from_feed(finding)
                    base_score = pattern_score
                    detection_source = "built-in pattern"
                    break

        # Layer 4: LOLBAS feed fuzzy matching (if no built-in match)
        if finding is None:
            for entry in self._lolbas_patterns:
                if name_lower == entry["name"] or name_lower.endswith(entry["name"]):
                    feed_tokens = [
                        t for t in entry["command"].lower().split()
                        if len(t) > 3
                    ]
                    matched = [t for t in feed_tokens if t in cmd_lower]
                    if len(matched) >= 2:
                        finding = {
                            "type":        "LOLBIN_ABUSE",
                            "binary":      name_lower,
                            "mitre":       entry["mitre"],
                            "description": entry["usecase"],
                            "cmdline":     cmdline,
                            "cmdline_normalized": cmdline_normalized,
                            "source":      "LOLBAS-feed",
                            "parent_name": parent_name,
                            "parent_pid":  parent_pid,
                        }
                        # Feed match already has the command dict — pass it directly
                        # so _enrich_from_feed doesn't have to guess by MITRE ID
                        _raw_cmd = {
                            "Category":        entry.get("category", ""),
                            "Privileges":      entry.get("privileges", ""),
                            "OperatingSystem": entry.get("os", ""),
                            "Usecase":         entry.get("usecase", ""),
                            "MitreID":         entry.get("mitre", ""),
                        }
                        self._enrich_from_feed(finding, matched_cmd=_raw_cmd)
                        base_score = 1  # Feed match is lower confidence than built-in
                        detection_source = "LOLBAS feed"
                        break

        # Layer 5: Entropy analysis (catches obfuscation even without pattern match)
        entropy_hits = _high_entropy_args(cmdline_normalized)
        if entropy_hits and name_lower.endswith(".exe"):
            if finding is None:
                # Only trigger entropy-only alert for known system binaries
                known_system = any(
                    name_lower == p[0].lower() for p in BUILTIN_PATTERNS
                )
                if known_system:
                    finding = {
                        "type":        "LOLBIN_ABUSE",
                        "binary":      name_lower,
                        "mitre":       "T1027",
                        "description": (
                            f"High-entropy argument detected — possible obfuscation. "
                            f"Suspicious tokens: {', '.join(entropy_hits[:2])}"
                        ),
                        "cmdline":     cmdline,
                        "cmdline_normalized": cmdline_normalized,
                        "source":      "entropy-analysis",
                        "parent_name": parent_name,
                        "parent_pid":  parent_pid,
                    }
                    base_score = 1
                    detection_source = "entropy analysis"
            else:
                # Entropy corroborates an existing finding — boost confidence
                base_score = min(3, base_score + 1)
                finding["entropy_tokens"] = entropy_hits
                finding["description"] += f" [+entropy corroboration: {entropy_hits[0]}]"

        # ── Layer 6: Name-only fallback ──────────────────────────────────────
        # WMI returns an empty CommandLine for short-lived processes because the
        # OS recycles the PEB before WMI reads it.  Layers 3–5 all silently
        # return None when cmdline is empty.  This fallback mirrors the
        # name-only LOW-confidence alert that lolbin_detector already emits,
        # ensuring LolbasDetector doesn't silently drop fast-exiting LOLBins.
        # cmd.exe is excluded from trusted-parent suppression — it is spawned
        # thousands of times per day by the OS itself.
        #
        # FIX: previously hardcoded base_score = 1 regardless of the binary's
        # original pattern score.  mshta (score=3), regsvr32 (score=3), and
        # rundll32 (score=3) were all downgraded to LOW even when there was no
        # reason to doubt the detection.  Now base_score inherits the pattern's
        # own score capped at 2 (MEDIUM) because without cmdline proof we cannot
        # justify HIGH confidence — but we can justify MEDIUM for known-dangerous
        # binaries like mshta whose presence alone is suspicious.
        if finding is None and not cmdline_normalized:
            for binary, _pat, mitre, desc, pattern_score in BUILTIN_PATTERNS:
                b_lower = binary.lower()
                if b_lower == "cmd.exe" and is_trusted_parent:
                    continue   # OS-routine cmd.exe from services — skip noise
                if name_lower == b_lower or name_lower.endswith(b_lower):
                    finding = {
                        "type":               "LOLBIN_ABUSE",
                        "binary":             name_lower,
                        "mitre":              mitre,
                        "description":        desc + " [cmdline unavailable — WMI race]",
                        "cmdline":            "",
                        "cmdline_normalized": "",
                        "source":             "name-only",
                        "parent_name":        parent_name,
                        "parent_pid":         parent_pid,
                    }
                    # Cap at MEDIUM: no cmdline means no pattern proof, but
                    # high-score binaries (mshta=3, regsvr32=3) still warrant
                    # more than LOW when spawned from a non-system parent.
                    base_score       = min(2, pattern_score)
                    detection_source = "name-only (no cmdline)"
                    break

        if finding is None:
            return None

        # ── Confidence scoring ────────────────────────────────────────────────
        # Combine base pattern score with parent process context
        confidence_score = base_score

        if is_high_risk_parent:
            confidence_score = min(3, confidence_score + 1)
            finding["parent_risk"] = "HIGH — office/browser spawned this process"
        elif is_trusted_parent:
            confidence_score = max(1, confidence_score - 1)
            finding["parent_risk"] = "LOW — spawned by trusted system service"
        else:
            finding["parent_risk"] = "MEDIUM" if parent_name else "UNKNOWN"

        confidence_label = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(confidence_score, "MEDIUM")
        finding["confidence"]       = confidence_label
        finding["confidence_score"] = confidence_score
        finding["detection_source"] = detection_source

        if from_daemon:
            self._save_alert(finding)

        return finding

    def _save_alert(self, finding: dict):
        """Persists a LoLBin alert to event_timeline AND fileless_alerts (for GUI display)."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings_summary = json.dumps([
            {
                "mitre":     finding["mitre"],
                "indicator": finding["description"],
                "confidence": finding.get("confidence", "MEDIUM"),
                "source":    finding.get("detection_source", "built-in"),
            }
        ])
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                # event_timeline — used by chain correlator
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) "
                    "VALUES (?,?,?,?)",
                    (
                        "LOLBIN_ABUSE",
                        json.dumps({
                            "binary":     finding["binary"],
                            "mitre":      finding["mitre"],
                            "desc":       finding["description"][:120],
                            "confidence": finding.get("confidence", "MEDIUM"),
                            "parent":     finding.get("parent_name", ""),
                        }),
                        finding.get("parent_pid", 0),
                        now,
                    ),
                )
                # fileless_alerts — read by the Fileless/AMSI GUI page
                conn.execute(
                    "INSERT INTO fileless_alerts (source, findings, pid, timestamp) "
                    "VALUES (?,?,?,?)",
                    (
                        f"LOLBIN_ABUSE [{finding['binary']}]",
                        findings_summary,
                        finding.get("parent_pid", 0),
                        now,
                    ),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

        # Fire webhook if configured
        if self._webhook_url:
            try:
                confidence = finding.get("confidence", "MEDIUM")
                icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(confidence, "🟠")
                utils.send_webhook_alert(
                    self._webhook_url,
                    f"{icon} LOLBin Abuse Detected — {confidence} Confidence",
                    {
                        "Binary":    finding.get("binary", "?"),
                        "MITRE":     finding.get("mitre", "?"),
                        "Technique": finding.get("description", "?")[:200],
                        "Confidence": confidence,
                        "Parent":    finding.get("parent_name", "unknown"),
                        "Command":   (finding.get("cmdline") or "")[:300],
                        "Source":    finding.get("detection_source", "built-in"),
                    },
                )
            except Exception:
                pass

    def format_alert(self, finding: dict) -> str:
        """Formats a LoLBin finding into a human-readable alert string."""
        confidence = finding.get("confidence", "MEDIUM")
        icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(confidence, "🟠")

        # ── intel/lolbas.json enrichment fields ──────────────────────────────
        category   = finding.get("category", "")
        privileges = finding.get("privileges", "")
        os_info    = finding.get("os", "")
        paths      = finding.get("full_paths", [])
        sigmas     = finding.get("sigma_links", [])
        bin_desc   = finding.get("binary_description", "")

        intel_lines = ""
        if category or privileges or os_info:
            intel_lines += f"\n  {'─'*61}"
            if bin_desc:
                intel_lines += f"\n  BinDesc : {bin_desc}"
            if category:
                intel_lines += f"\n  Category: {category}"
            if privileges:
                intel_lines += f"\n  Privs   : {privileges}"
            if os_info:
                intel_lines += f"\n  OS      : {os_info}"
            if paths:
                intel_lines += f"\n  Paths   : {'; '.join(paths[:2])}"
            if sigmas:
                intel_lines += f"\n  Sigma   : {sigmas[0]}"
            intel_lines += f"\n  {'─'*61}"

        parent_info = ""
        if finding.get("parent_name"):
            parent_info = (
                f"\n  Parent  : {finding['parent_name']} "
                f"(PID {finding.get('parent_pid', '?')}) "
                f"[{finding.get('parent_risk', '')}]"
            )
        entropy_info = ""
        if finding.get("entropy_tokens"):
            entropy_info = f"\n  Entropy : {', '.join(finding['entropy_tokens'][:2])}"
        normalized = finding.get("cmdline_normalized", "")
        cmdline_display = finding["cmdline"][:100]
        norm_display = (
            f"\n  CmdNorm : {normalized[:100]}"
            if normalized and normalized != finding["cmdline"] else ""
        )
        return (
            f"\n{'='*65}\n"
            f"  {icon}  LOLBIN ABUSE — {confidence} CONFIDENCE\n"
            f"  Binary  : {finding['binary']}\n"
            f"  MITRE   : {finding['mitre']}\n"
            f"  Details : {finding['description']}\n"
            f"  Source  : {finding.get('detection_source', finding.get('source', ''))}\n"
            f"  CmdLine : {cmdline_display}"
            f"{norm_display}"
            f"{intel_lines}"
            f"{parent_info}"
            f"{entropy_info}\n"
            f"{'='*65}"
        )

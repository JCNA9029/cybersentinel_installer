# modules/amsi_hook.py — Feature 6: Fileless / In-Memory Attack Detection

import ctypes
import ctypes.wintypes
import os
import re
import time
import threading
import sqlite3
import datetime
from . import colors, utils
from .chain_correlator import ChainCorrelator


# ─────────────────────────────────────────────────────────────────────────────
#  SUSPICIOUS CONTENT PATTERNS (Approach A)
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_PATTERNS = [
    # AMSI / Defender bypass
    (r"(?i)(amsiutils|amsi\.dll|amsibuffer|amsicontext|amsiresult)",
     "AMSI bypass attempt detected — T1562.001"),
    (r"(?i)\[ref\]\.\w+\.getfield.*nonpublic",
     "Reflection-based AMSI bypass — T1562.001"),
    (r"(?i)set-mppreference.*(disablerealtimemonitoring|disableioavprotection|"
     r"disableantivirus|exclusionpath)",
     "Windows Defender disablement — T1562.001"),
    # Credential theft
    (r"(?i)(sekurlsa|lsass|mimikatz|invoke-mimikatz|dcsync|kerberoast)",
     "Credential dumping keyword — T1003"),
    # PowerShell cradles
    (r"(?i)(new-object\s+net\.webclient).*download(string|file|data)",
     "PowerShell download cradle — T1059.001 / T1105"),
    (r"(?i)invoke-expression\s*[\(\$]",
     "IEX execution — T1059.001"),
    (r"(?i)(iex|invoke-expression).*downloadstring",
     "IEX+DownloadString combo — T1059.001"),
    (r"(?i)-exec(utionpolicy)?\s+(bypass|unrestricted|remotesigned)",
     "ExecutionPolicy bypass — T1059.001"),
    (r"(?i)\[system\.convert\]::frombase64string",
     "Base64 decode in memory — T1027"),
    (r"(?i)-e(?:nc(?:oded(?:command)?)?)?\s+[A-Za-z0-9+/=]{20,}",
     "Encoded PowerShell command — T1027"),
    # mshta / script hosts
    (r"(?i)mshta.*vbscript\s*:",
     "mshta VBScript execution cradle — T1218.005"),
    (r"(?i)<\s*script[^>]*language\s*=\s*['\"]?vbscript",
     "HTA VBScript payload — T1218.005"),
    (r"(?i)wscript\s*\.\s*shell.*exec",
     "WScript.Shell execution — T1059.005"),
    (r"(?i)createobject\s*\(\s*['\"]wscript\.shell['\"]",
     "WScript.Shell object creation — T1059.005"),
    (r"(?i)cscript.*\.(vbs|js|wsf)\b",
     "CScript script execution — T1059.005 / T1059.007"),
    # Process injection via script
    (r"(?i)(virtualalloc|virtualallocex)\s*[\(\$]",
     "VirtualAlloc in script context — shellcode staging — T1055"),
    (r"(?i)(writeprocessmemory|zwwritevirtualmemory)\s*[\(\$]",
     "WriteProcessMemory in script — injection staging — T1055"),
    (r"(?i)createremotethread\s*[\(\$]",
     "CreateRemoteThread in script — injection execution — T1055"),
    # WMI persistence
    (r"(?i)eventtrigger.*commandlinetemplate",
     "WMI subscription persistence — T1546.003"),
    (r"(?i)__eventfilter.*__commandlineeventconsumer",
     "WMI event consumer persistence — T1546.003"),
    # .NET reflection
    (r"(?i)\[reflection\.assembly\]::load(file|bytes|from)\b",
     "Reflective .NET assembly load — T1620"),
    # COM abuse
    (r"(?i)shell\.application.*shellexecute",
     "Shell.Application ShellExecute — T1059"),
    (r"(?i)new-object\s+-com(object)?\s+shell\.application",
     "Shell.Application COM instantiation — T1059"),
]

_COMPILED_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p), desc) for p, desc in _SUSPICIOUS_PATTERNS
]


# ─────────────────────────────────────────────────────────────────────────────
#  WINDOWS MEMORY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_MEM_COMMIT             = 0x00001000
_MEM_PRIVATE            = 0x00020000
_PAGE_EXECUTE_READWRITE = 0x00000040
_PAGE_EXECUTE_WRITECOPY = 0x00000080
_WRITABLE_EXEC_PROTECTIONS = frozenset({_PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY})
_USER_SPACE_LIMIT          = (1 << 47) - 1
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ           = 0x0010

# ─────────────────────────────────────────────────────────────────────────────
#  JIT HOST FILTER — Dynamic loading from jit_exclusions.txt
#
#  The base set covers well-known JIT runtimes. Additional process names
#  can be added at runtime via the CLI command or GUI settings page by
#  writing to jit_exclusions.txt in the project root.
#
#  File format: one process name per line (case-insensitive), # = comment.
#  Example:   myapp.exe
# ─────────────────────────────────────────────────────────────────────────────
_JIT_BASE = frozenset({
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    "electron.exe", "code.exe", "slack.exe", "discord.exe",
    "teams.exe", "notion.exe", "figma.exe",
    "node.exe",
    "rsappui.exe", "cncmd.exe", "amdow.exe",
    "dotnet.exe", "onedrive.exe",
    "java.exe", "javaw.exe", "javaws.exe",
    "firefox.exe",
    "explorer.exe",
})

_JIT_EXCLUSIONS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "jit_exclusions.txt",
)


def _load_jit_exclusions() -> frozenset:
    """
    Reads jit_exclusions.txt and merges with the base set.
    Called once at module import and on-demand via reload_jit_exclusions().
    """
    extra: set[str] = set()
    if not os.path.exists(_JIT_EXCLUSIONS_FILE):
        # Create empty template on first run
        try:
            with open(_JIT_EXCLUSIONS_FILE, "w") as f:
                f.write(
                    "# CyberSentinel JIT Process Exclusions\n"
                    "# One process name per line (case-insensitive).\n"
                    "# Processes listed here are excluded from RWX memory scanning\n"
                    "# because they host JIT compilers (V8, .NET CLR, JVM) that\n"
                    "# legitimately allocate anonymous RWX memory.\n"
                    "# Add a process name here when FILELESS-DEBUG tells you to.\n"
                    "# Example:\n"
                    "#   myapp.exe\n"
                )
        except Exception:
            pass
        return _JIT_BASE
    names: set[str] = set()
    try:
        with open(_JIT_EXCLUSIONS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.add(line.lower())
    except Exception:
        pass
    return _JIT_BASE | frozenset(names)


# Module-level set — mutable so reload_jit_exclusions() can replace it
_JIT_PROCESS_NAMES: frozenset = _load_jit_exclusions()
_jit_debug_printed: set[str] = set()  # dedup guard — print each process name once only


def reload_jit_exclusions() -> frozenset:
    """
    Re-reads jit_exclusions.txt and updates the active filter set.
    Call this after the CLI or GUI writes a new entry to the file.
    Returns the updated set.
    """
    global _JIT_PROCESS_NAMES
    _JIT_PROCESS_NAMES = _load_jit_exclusions()
    return _JIT_PROCESS_NAMES


_jit_exclusion_lock = threading.Lock()

def add_jit_exclusion(process_name: str) -> bool:
    """
    Appends a process name to jit_exclusions.txt and reloads the active set.
    Returns True on success. Thread-safe.
    Called by both the CLI command and the GUI settings page.
    """
    name = process_name.strip().lower()
    if not name or not name.endswith(".exe"):
        return False
    _load_jit_exclusions()  # Initialise file if missing
    with _jit_exclusion_lock:
        try:
            with open(_JIT_EXCLUSIONS_FILE, "r", encoding="utf-8") as f:
                existing = {
                    l.strip().lower() for l in f
                    if l.strip() and not l.startswith("#")
                }
            if name in existing or name in _JIT_BASE:
                reload_jit_exclusions()
                return True
            with open(_JIT_EXCLUSIONS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{name}\n")
            reload_jit_exclusions()
            return True
        except Exception:
            return False
# ─────────────────────────────────────────────────────────────────────────────
#  NON-JIT PROCESSES (HIGH VALUE TARGETS)
#
#  These processes should NEVER have anonymous RWX regions under normal
#  operation. An anonymous RWX page inside any of these is a very high
#  confidence indicator of shellcode injection.
#
#  This is where your scanner provides real SOC value. Real attackers inject
#  into these processes specifically because they are trusted by AV:
#    - Cobalt Strike default: inject into svchost.exe
#    - Meterpreter default:   inject into notepad.exe or explorer.exe
#    - PlugX:                 inject into iexplore.exe or svchost.exe
#
#  The scanner is most effective when focused here rather than scanning
#  every process indiscriminately.
# ─────────────────────────────────────────────────────────────────────────────
_HIGH_VALUE_NON_JIT = frozenset({
    "notepad.exe", "calc.exe", "mspaint.exe",
    "svchost.exe", "lsass.exe", "explorer.exe",
    "winlogon.exe", "csrss.exe", "spoolsv.exe",
    "taskhost.exe", "taskhostw.exe", "runtimebroker.exe",
    "dllhost.exe", "regsvr32.exe", "rundll32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
    "iexplore.exe", "wmiprvse.exe", "services.exe",
})

# ─────────────────────────────────────────────────────────────────────────────
#  SCANNING MODE
#
#  HIGH_VALUE_ONLY = True  (recommended for SOC deployment):
#    Only scan processes in _HIGH_VALUE_NON_JIT. Zero false positives from JIT.
#    Misses injection into JIT-hosting processes (chrome, teams, etc.) — known
#    limitation, documented in thesis.
#
#  HIGH_VALUE_ONLY = False (research / lab mode):
#    Scan all non-JIT processes. More coverage, more noise from unlisted
#    processes. Use during controlled testing with known process sets.
# ─────────────────────────────────────────────────────────────────────────────
HIGH_VALUE_ONLY = True


class _MemoryBasicInfo(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_size_t),
        ("AllocationBase",    ctypes.c_size_t),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             ctypes.wintypes.DWORD),
        ("Protect",           ctypes.wintypes.DWORD),
        ("Type",              ctypes.wintypes.DWORD),
    ]


def _scan_process_memory_windows(pid: int, process_name: str = "") -> list[str]:
    """
    Enumerates a process's virtual address space for anonymous RWX regions.

    Universal count filter — applied to ALL processes including high-value:
      Modern Windows embeds JIT runtimes (WebView2/V8) in explorer.exe,
      notepad.exe (Windows 11), and svchost.exe (.NET services). No process
      can be assumed JIT-free. The count filter is the only reliable
      discriminator between shellcode staging and JIT compilation at
      user-mode without kernel callbacks.

      1–2 regions  → HIGH CONFIDENCE if high-value, MEDIUM otherwise
      3–5 regions  → MEDIUM CONFIDENCE (analyst review)
      >5 regions   → suppressed (JIT signature)

    JIT-listed processes (_JIT_PROCESS_NAMES) are skipped before any
    handle is opened.
    """
    findings:  list[str] = []
    name_lower = process_name.lower()

    # Filter 1: known JIT hosts — skip entirely
    if name_lower in _JIT_PROCESS_NAMES:
        return findings

    # Filter 2: HIGH_VALUE_ONLY mode — skip non-targeted processes
    is_high_value = name_lower in _HIGH_VALUE_NON_JIT
    if HIGH_VALUE_ONLY and not is_high_value:
        return findings

    k32    = ctypes.windll.kernel32
    handle = k32.OpenProcess(
        _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ,
        False,
        pid,
    )
    if not handle:
        return findings

    mbi      = _MemoryBasicInfo()
    mbi_size = ctypes.sizeof(mbi)
    address  = 0
    raw_hits: list[str] = []

    try:
        while address <= _USER_SPACE_LIMIT:
            queried = k32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                mbi_size,
            )
            if not queried:
                break

            if (mbi.State   == _MEM_COMMIT
                    and mbi.Type    == _MEM_PRIVATE
                    and mbi.Protect in _WRITABLE_EXEC_PROTECTIONS):
                size_kb = mbi.RegionSize // 1024 or 1
                raw_hits.append(
                    f"Anonymous RWX region @ 0x{mbi.BaseAddress:016x} "
                    f"({size_kb} KB, {process_name}) (T1055)"
                )

            next_addr = mbi.BaseAddress + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr

    finally:
        k32.CloseHandle(handle)

    total = len(raw_hits)
    if total == 0:
        return findings

    # ── Universal count filter ────────────────────────────────────────────────
    # Applied to ALL processes — high-value and generic alike.
    # explorer.exe (WebView2), notepad.exe (Win11), svchost.exe (.NET) all
    # produce 6+ regions legitimately. Real stagers produce 1–2.

    if total > 5:
        # JIT signature — suppress, log for tuning (print once per process name)
        if process_name not in _jit_debug_printed:
            _jit_debug_printed.add(process_name)
            print(
                f"[FILELESS-DEBUG] {process_name} (PID {pid}): "
                f"{total} RWX regions suppressed (JIT heuristic). "
                f"If this process is a known JIT host, add it to _JIT_PROCESS_NAMES."
            )
        return findings

    if total > 2:
        # Ambiguous count — flag for analyst review, do not auto-escalate
        findings.append(
            f"[MEDIUM CONFIDENCE] {total} anonymous RWX regions in "
            f"{process_name} — analyst review recommended (T1055)"
        )
        return findings

    # 1–2 regions: strong shellcode stager fingerprint
    # High-value process = HIGH, everything else = MEDIUM
    confidence = "HIGH" if is_high_value else "MEDIUM"
    findings.extend(f"[{confidence} CONFIDENCE] {h}" for h in raw_hits)
    return findings


def _scan_process_memory(pid: int, process_name: str = "") -> list[str]:
    """Dispatcher: VirtualQueryEx on Windows, psutil on Linux/macOS."""
    if os.name == "nt":
        return _scan_process_memory_windows(pid, process_name)
    try:
        import psutil
        proc     = psutil.Process(pid)
        findings = []
        for mmap in proc.memory_maps():
            perms = (mmap.perms or "").lower()
            if "r" in perms and "w" in perms and "x" in perms and not mmap.path:
                findings.append(
                    f"Anonymous RWX region at {mmap.addr} — shellcode staging (T1055)"
                )
        return findings
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  AMSI COM BRIDGE
# ─────────────────────────────────────────────────────────────────────────────

class AmsiScanner:
    """
    Thin wrapper around amsi.dll for scanning script blobs.
    Thread-safe: scan_buffer() can be called from any thread.
    """

    AMSI_RESULT_DETECTED = 32768

    def __init__(self):
        self._amsi      = None
        self._context   = ctypes.c_void_p()
        self._session   = ctypes.c_void_p()
        self._available = False
        self._lock      = threading.Lock()
        self._init_amsi()

    def _init_amsi(self):
        if os.name != "nt":
            return
        try:
            self._amsi = ctypes.WinDLL("amsi.dll")
            hr = self._amsi.AmsiInitialize(
                ctypes.c_wchar_p("CyberSentinel"),
                ctypes.byref(self._context),
            )
            if hr == 0:
                hr2 = self._amsi.AmsiOpenSession(
                    self._context,
                    ctypes.byref(self._session),
                )
                self._available = (hr2 == 0)
                if self._available:
                    colors.success(
                        "[+] AMSI bridge initialized — script content scanning active."
                    )
        except Exception as e:
            colors.warning(f"[!] AMSI bridge unavailable: {e} — heuristic mode only.")

    def scan_buffer(self, content: str, source_name: str = "script") -> tuple[bool, list[str]]:
        """
        Scans a script string through AMSI provider chain + heuristics.
        Returns (is_malicious: bool, findings: list[str]).
        Thread-safe.
        """
        findings:     list[str] = []
        amsi_flagged: bool      = False

        if self._available and self._amsi:
            with self._lock:
                try:
                    result  = ctypes.c_uint(0)
                    encoded = content.encode("utf-16-le")
                    self._amsi.AmsiScanBuffer(
                        self._context,
                        ctypes.c_char_p(encoded),
                        ctypes.c_uint(len(encoded)),
                        ctypes.c_wchar_p(source_name[:260]),
                        self._session,
                        ctypes.byref(result),
                    )
                    if result.value >= self.AMSI_RESULT_DETECTED:
                        findings.append(
                            "AMSI_PROVIDER_DETECTION: Windows AV provider flagged content"
                        )
                        amsi_flagged = True
                except Exception:
                    pass

        for pattern, description in _COMPILED_PATTERNS:
            if pattern.search(content):
                findings.append(description)

        return (amsi_flagged or bool(findings)), findings

    def __del__(self):
        if self._available and self._amsi:
            try:
                self._amsi.AmsiCloseSession(self._context, self._session)
                self._amsi.AmsiUninitialize(self._context)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  FILELESS MONITOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class FilelessMonitor:
    """
    Combines the AMSI scanner and memory injection detector.
    The background memory monitor thread is stoppable via stop().
    """

    def __init__(self, correlator: ChainCorrelator = None, webhook_url: str = ""):
        self.scanner          = AmsiScanner()
        self.correlator       = correlator
        self.webhook_url      = webhook_url
        self._stop_event      = threading.Event()
        self._monitor_running = False   # guard against duplicate start_memory_monitor calls

    def scan_script(self, content: str, source_name: str = "script", pid: int = 0) -> bool:
        is_mal, findings = self.scanner.scan_buffer(content, source_name)
        if not findings:
            return False

        sep = "=" * 64
        colors.critical(f"\n{sep}")
        colors.critical(f"  [FILELESS ALERT] Malicious Script Content Detected!")
        colors.critical(f"{sep}")
        colors.warning(f"  Source : {source_name}  (PID: {pid})")
        for f in findings:
            print(f"    \u2717 {f}")
        colors.critical(f"{sep}\n")

        # Write to event_timeline so the GUI Live Feed and chain correlator see it.
        # Uses FILELESS_AMSI to match the "Fileless Execution → C2" chain definition.
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    ("FILELESS_AMSI", findings[0][:256], pid,
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except Exception:
            pass

        if self.correlator:
            try:
                self.correlator.run_correlation()
            except Exception:
                pass

        self._log_to_db(source_name, "\n".join(findings), pid)

        if self.webhook_url:
            utils.send_webhook_alert(
                self.webhook_url,
                "Fileless Script Threat",
                {"Source": source_name, "Findings": "\n".join(findings[:5])},
            )
        return True

    def scan_process_memory(self, pid: int, process_name: str = "") -> bool:
        findings = _scan_process_memory(pid, process_name)
        if not findings:
            return False

        colors.critical(
            f"\n[FILELESS] Memory injection pattern — PID {pid} ({process_name}):"
        )
        for f in findings:
            colors.warning(f"  \u2717 {f}")

        # Write to event_timeline so the GUI Live Feed and chain correlator see it.
        # Uses FILELESS_AMSI to match the "Fileless Execution → C2" chain definition.
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    ("FILELESS_AMSI", findings[0][:256], pid,
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except Exception:
            pass

        if self.correlator:
            try:
                self.correlator.run_correlation()
            except Exception:
                pass

        self._log_to_db(f"PID:{pid}:{process_name}", "\n".join(findings), pid)

        if self.webhook_url:
            utils.send_webhook_alert(
                self.webhook_url,
                "Memory Injection Detected",
                {"PID": pid, "Process": process_name, "Findings": findings[0]},
            )
        return True

    def start_memory_monitor(self, scan_interval: int = 30):
        """
        Background thread scanning non-JIT processes for anonymous RWX regions.
        First scan runs immediately. Call stop() to terminate cleanly.
        """
        if self._monitor_running:
            print("[FILELESS] Memory monitor already running — ignoring duplicate start.")
            return
        self._monitor_running = True
        self._stop_event.clear()

        def _scan_all():
            try:
                import psutil as _ps
            except ImportError:
                print("[FILELESS] psutil not installed — memory monitor unavailable.")
                return

            while not self._stop_event.is_set():
                try:
                    for proc in list(_ps.process_iter(["pid", "name", "exe"])):
                        if self._stop_event.is_set():
                            break
                        try:
                            name = proc.info.get("name") or ""
                            pid  = proc.info.get("pid")  or 0
                            if not pid:
                                continue
                            self.scan_process_memory(pid, name)
                        except Exception:
                            pass
                except Exception:
                    pass

                self._stop_event.wait(scan_interval)

        t = threading.Thread(
            target=_scan_all, daemon=True, name="FilelessMemMonitor"
        )
        t.start()
        mode = "HIGH_VALUE_ONLY" if HIGH_VALUE_ONLY else "ALL_NON_JIT"
        print(
            f"[+] Fileless Monitor: memory scanner active "
            f"(interval={scan_interval}s, mode={mode})."
        )

    def stop(self):
        self._stop_event.set()
        self._monitor_running = False

    def _log_to_db(self, source: str, findings: str, pid: int):
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO fileless_alerts (source, findings, pid, timestamp) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        source[:256],
                        findings[:1024],
                        pid,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
        except sqlite3.Error:
            pass
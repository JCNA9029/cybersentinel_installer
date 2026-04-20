# modules/daemon_monitor.py — Headless Daemon: WMI hook + watchdog + all detectors

import os
import sys
import time
import threading
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .analysis_manager import ScannerLogic
from .lolbas_detector  import LolbasDetector
from .byovd_detector   import ByovdDetector
from .c2_fingerprint   import FeodoMonitor, DgaMonitor, Ja3Monitor
from .chain_correlator import ChainCorrelator, ATTACK_CHAINS
from .baseline_engine  import BaselineEngine
from .amsi_monitor     import AmsiMonitor
from .amsi_hook        import AmsiScanner, FilelessMonitor, _JIT_PROCESS_NAMES
from .lolbin_detector  import LolbinDetector
from . import colors, utils
from .network_isolation import isolate_network as _isolate_network

WATCHED_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".apk", ".elf",
    ".pdf", ".bat", ".ps1", ".vbs", ".hta",
)

# Binaries whose command-line content is worth routing through AMSI heuristics.
# mshta is included because it executes VBScript/JavaScript inline — the same
# threat surface as PowerShell and WScript.
_SCRIPT_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe",
})

# Parents that legitimately spawn encoded PowerShell (Windows Update, Task
# Scheduler, WMI providers, etc.).  Script-host processes whose direct parent
# is in this set are skipped by the fileless scanner to eliminate the most
# common source of false-positive FILELESS ALERTs when running as admin.
_TRUSTED_SYSTEM_PARENTS = frozenset({
    "services.exe", "svchost.exe", "wininit.exe", "winlogon.exe",
    "trustedinstaller.exe", "taskeng.exe", "taskhost.exe", "taskhostw.exe",
    "wmiprvse.exe", "tiworker.exe", "msiexec.exe", "searchindexer.exe",
    "sppsvc.exe", "wuauclt.exe", "usoclient.exe",
    # Add these:
    "python.exe", "python3.exe",   # CyberSentinel itself
    "cmd.exe",                      # Admin terminal sessions
    "conhost.exe",                  # Console host
    "vscode.exe", "code.exe",       # VS Code extensions
})

_RECENTLY_ALERTED_PIDS = set()
_LOCK = threading.Lock()

def _check_and_register_alert(pid):
    """Returns True if the PID hasn't been alerted on in the last 5s."""
    with _LOCK:
        if pid in _RECENTLY_ALERTED_PIDS:
            return False
        _RECENTLY_ALERTED_PIDS.add(pid)
        # Clear after 5 seconds
        threading.Timer(5.0, lambda: _clear_pid(pid)).start()
        return True

def _clear_pid(pid):
    with _LOCK:
        _RECENTLY_ALERTED_PIDS.discard(pid)

class ThreatHandler(FileSystemEventHandler):
    def __init__(self, logic: ScannerLogic):
        self.logic = logic

    def on_created(self, event):
        """Watchdog callback — triggered when a new file lands in the watched folder."""
        if event.is_directory:
            return
        if not event.src_path.lower().endswith(WATCHED_EXTENSIONS):
            return
        print(f"\n[DAEMON] 🚨 File drop intercepted: {event.src_path}")
        time.sleep(2)
        try:
            self.logic.scan_file(event.src_path)
        except Exception as e:
            print(f"[DAEMON] ⚠  Scanner error on {os.path.basename(event.src_path)}: {e}")

# ── ETW / Security Event 4688 monitor

# Bounded seen-record tracker for the ETW loop.
# The original implementation used a plain set[int] that grew indefinitely.
# On a busy machine (hundreds of process creations per minute) this consumed
# hundreds of MB over a multi-day daemon run.
# A deque-backed ring buffer keeps membership O(1) while capping memory.
_ETW_SEEN_MAX = 200000

class _BoundedSeen:
    """O(1) membership test with a fixed memory ceiling."""
    __slots__ = ("_dq", "_s", "_max")

    def __init__(self, maxlen: int):
        self._dq: deque[int] = deque()
        self._s:  set[int]   = set()
        self._max = maxlen

    def already_seen(self, rec: int) -> bool:
        if rec in self._s:
            return True
        self._s.add(rec)
        self._dq.append(rec)
        if len(self._dq) > self._max:
            self._s.discard(self._dq.popleft())
        return False

def _parse_hex_pid(s: str) -> int:
    """Parse a hex PID string like '0x1A3C' from Event 4688 StringInserts[4]."""
    try:
        return int(s, 16) if s and s.startswith("0x") else int(s or "0")
    except (ValueError, TypeError):
        return 0

def _monitor_processes_etw(lolbas: LolbasDetector, lolbin, fileless: FilelessMonitor, self_pid: int = 0, self_exe: str = ""):
    """
    Reads Windows Security Event Log for Event ID 4688 (Process Creation).

    4688 events are written synchronously by the kernel at process creation —
    before the process executes a single instruction. This means the cmdline
    is captured even for sub-100ms processes like mshta that exit before the
    WMI watcher can read the PEB.

    Prerequisites (both required):
      auditpol /set /subcategory:"Process Creation" /success:enable
      Group Policy: Administrative Templates → System → Audit Process Creation
                    → Include command line in process creation events → Enabled

    Without both, Event ID 4688 fires but StringInserts[8] (cmdline) is empty.
    """
    print("[ETW] thread started.")
    try:
        import win32evtlog
        import win32con
        print("[ETW] win32evtlog imported OK.")
    except ImportError as e:
        print(f"[ETW] FAILED — win32evtlog import error: {e}")
        return

    LOG_NAME   = "Security"
    EVENT_4688 = 4688
    POLL_SECS  = 0.5

    try:
        handle = win32evtlog.OpenEventLog(None, LOG_NAME)
        print("[ETW] Security log opened OK.")
        
        # Fast-forward instantly to the end of the log
        num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
        if num_records > 0:
            newest_record = oldest_record + num_records - 1
            seek_flags = win32con.EVENTLOG_SEEK_READ | win32con.EVENTLOG_FORWARDS_READ
            win32evtlog.ReadEventLog(handle, seek_flags, newest_record)
            
            # Clear any remaining buffered events to ensure we are at EOF
            seq_flags = win32con.EVENTLOG_SEQUENTIAL_READ | win32con.EVENTLOG_FORWARDS_READ
            while win32evtlog.ReadEventLog(handle, seq_flags, 0):
                pass
    except Exception as e:
        print(f"[ETW] FAILED — cannot open Security log: {e}")
        print("[ETW] Run: auditpol /set /subcategory:\"Process Creation\" /success:enable")
        return

    seen = _BoundedSeen(_ETW_SEEN_MAX)
    print("[ETW] entering event loop.")

    while True:
        try:
            events = win32evtlog.ReadEventLog(
                handle,
                win32con.EVENTLOG_SEQUENTIAL_READ | win32con.EVENTLOG_FORWARDS_READ,
                0,
            )
            for evt in (events or []):
                if evt.EventID != EVENT_4688:
                    continue
                rec = evt.RecordNumber
                if seen.already_seen(rec):
                    continue

                inserts     = evt.StringInserts or []
                pid         = _parse_hex_pid(inserts[4]  if len(inserts) > 4  else "")
                exe_path    = inserts[5]  if len(inserts) > 5  else ""
                cmdline     = inserts[8]  if len(inserts) > 8  else ""
                parent_path = inserts[13] if len(inserts) > 13 else ""
                # inserts[7] is the Creator (parent) Process ID in hex.
                # Use it as fallback when inserts[13] (ParentProcessName) is
                # absent — common on older Windows builds and domain policies
                # that do not populate the extended 4688 fields. Without this,
                # parent_name stays "" which silently bypasses _TRUSTED_SYSTEM_PARENTS.
                parent_pid  = _parse_hex_pid(inserts[7] if len(inserts) > 7 else "")

                name        = os.path.basename(exe_path).lower() if exe_path else ""
                parent_name = os.path.basename(parent_path).lower() if parent_path else ""

                # Fallback: resolve parent name from PID when inserts[13] is empty.
                if not parent_name and parent_pid:
                    try:
                        import psutil as _ps
                        parent_name = _ps.Process(parent_pid).name().lower()
                    except Exception:
                        parent_name = ""

                if not name:
                    continue

                # Skip the daemon's own process creation event.
                if pid == self_pid:
                    continue
                if self_exe and exe_path and exe_path.lower() == self_exe:
                    continue

                # ── LoLBin checks ─────────────────────────────────────────────
                hit = lolbas.check_process(
                    name, cmdline,
                    from_daemon=True,
                    parent_name=parent_name,
                    exe_path=exe_path,
                )
                if hit and _check_and_register_alert(pid):
                    colors.critical(lolbas.format_alert(hit))
                    lolbas.save_alert(hit)

                # Route script host cmdlines through AMSI heuristics.
                # This mirrors the WMI path and was missing from the ETW path,
                # meaning mshta/wscript content was never AMSI-scanned from 4688.
                # Guard against trusted system parents — same logic as WMI path.
                if name in _SCRIPT_HOSTS and cmdline:
                    if parent_name.lower() not in _TRUSTED_SYSTEM_PARENTS:
                        # Import the module-level compiled patterns directly
                        from .amsi_hook import _COMPILED_PATTERNS
                        _hits = sum(1 for pat, _ in _COMPILED_PATTERNS if pat.search(cmdline))
                        if _hits >= 2:
                            fileless.scan_script(
                                cmdline,
                                source_name=f"ETW:{name}",
                                pid=pid,
                            )

        except Exception as _etw_err:
            print(f"[ETW] loop error: {_etw_err}")

        time.sleep(POLL_SECS)

# ── WMI process creation monitor

def _monitor_processes(logic, lolbas, byovd, baseline, dga, lolbin, fileless, self_pid=0, self_exe=""):
    try:
        import wmi, pythoncom
        pythoncom.CoInitialize()
        c       = wmi.WMI()
        watcher = c.Win32_Process.watch_for("creation")

        while True:
            proc     = watcher()
            exe_path = proc.ExecutablePath or ""
            name     = proc.Name          or ""
            pid      = proc.ProcessId     or 0

            # Skip the daemon's own process — WMI fires for every new process
            # including the one that just launched us, which causes CyberSentinel
            # to scan and potentially flag itself on startup.
            if pid == self_pid:
                continue
            if self_exe and exe_path and exe_path.lower() == self_exe:
                continue

            # ── CommandLine: Optimized capture
            # WMI watcher 'proc' object is live at moment of creation.
            # We must access it immediately before it is garbage collected.
            cmdline = proc.CommandLine or ""

            # If empty, the OS likely already recycled the PEB.
            # We attempt one final aggressive retrieval via psutil
            if not cmdline and pid:
                try:
                    import psutil
                    proc_handle = psutil.Process(pid)
                    # Use cmdline() list join — this is much faster than WMI
                    cmdline = " ".join(proc_handle.cmdline())
                except:
                    pass

            if not cmdline and pid:
                try:
                    import psutil
                    cmdline = " ".join(psutil.Process(pid).cmdline())
                except Exception:
                    pass

            # Resolve parent process name for kill-chain context
            parent_name = ""
            parent_pid  = proc.ParentProcessId or 0
            if parent_pid:
                try:
                    parent_list = c.Win32_Process(ProcessId=parent_pid)
                    if parent_list:
                        parent_name = parent_list[0].Name or ""
                except Exception:
                    pass
            # ── LoLBin checks ─────────────────────────────────────────────────
            hit = lolbas.check_process(
                name,
                cmdline,
                from_daemon  = True,
                parent_name  = parent_name,
                parent_pid   = parent_pid,
                exe_path     = exe_path,
            )
            if hit and _check_and_register_alert(pid):
                colors.critical(lolbas.format_alert(hit))
                lolbas.save_alert(hit)
                # [THESIS FIX] User-Mode Active Blocking
                if hit.get("confidence") == "HIGH" and pid:
                    utils.terminate_process(pid, name)

            # ── BYOVD ─────────────────────────────────────────────────────────
            if exe_path.lower().endswith(".sys"):
                hit = byovd.check_driver(exe_path)
                if hit:
                    colors.critical(byovd.format_alert(hit))

            # ── Baseline deviation ────────────────────────────────────────────
            if not baseline.is_learning() and exe_path:
                if not utils.is_excluded(exe_path) and not utils.is_excluded(name):
                    sha = utils.get_sha256(exe_path) or ""
                    if baseline.get_trust_score(sha, exe_path) >= 1.0:
                        colors.warning(
                            f"[BASELINE] ⚠  Unknown binary: {name} ({exe_path})"
                        )

            # ── AMSI / fileless script scanning ───────────────────────────────
            # mshta is now included — it executes VBScript/JavaScript inline,
            # the same threat surface as PowerShell and WScript.
            # Skip script hosts spawned by trusted Windows system parents —
            # svchost, services, TrustedInstaller etc. legitimately use
            # -EncodedCommand for scheduled tasks and update pipelines.
            if name.lower() in _SCRIPT_HOSTS and cmdline:
                if parent_name.lower() not in _TRUSTED_SYSTEM_PARENTS:
                    fileless.scan_script(
                        cmdline,
                        source_name=f"{name}[PID:{pid}]",
                        pid=pid,
                    )

            # ── Standard PE scan (non-Windows binaries only) ─────────────────
            if exe_path and "c:\\windows" not in exe_path.lower():
                # Skip known JIT hosts (browsers, Electron apps, runtimes).
                # These are already in _JIT_PROCESS_NAMES for memory-scan
                # suppression — reuse the same set to avoid redundant PE scans.
                if name.lower() not in _JIT_PROCESS_NAMES:
                    # Pre-check exclusions before invoking scan_file so that
                    # allowlisted processes produce zero console output in daemon mode.
                    if not utils.is_excluded(exe_path):
                        _sha = utils.get_sha256(exe_path) or ""
                        if not utils.is_excluded(exe_path, file_hash=_sha):
                            try:
                                logic.scan_file(exe_path)
                            except Exception as e:
                                print(f"[DAEMON] ⚠  Scanner skipped {name}: {e}")

    except ImportError:
        print("[DAEMON] ⚠  WMI unavailable — install wmi + pywin32.")
    except Exception as e:
        print(f"[DAEMON] ✖  WMI hook terminated: {e}")

def _run_correlator(correlator):
    while True:
        time.sleep(60)
        try:
            correlator.run_correlation()
        except Exception:
            pass

def _monitor_dns(dga: DgaMonitor):
    """
    Sniffs UDP port 53 via scapy and feeds every outbound DNS query name into
    DgaMonitor.analyse(). This is the missing link that connects live DNS
    activity to the DGA entropy detector.

    Requires scapy + Npcap. Silently exits if either is unavailable.
    MITRE: T1568.002 (Dynamic Resolution: Domain Generation Algorithms)
    """
    try:
        from scapy.all import sniff, DNS, DNSQR, IP, conf
        conf.use_pcap = True  # Force Npcap backend — required on Windows
    except Exception as e:
        print(f"[!] DGA DNS monitor disabled — scapy/Npcap unavailable: {e}")
        return

    def cb(pkt):
        if not dga._running:
            return
        # Only process outbound DNS queries (QR bit == 0), not responses
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return
        try:
            raw = pkt[DNSQR].qname
            qname = raw.decode("utf-8", errors="ignore").rstrip(".")
            if not qname:
                return
            result = dga.analyse(qname)
            if result:
                print(dga.format_alert(result))
        except Exception:
            pass

    try:
        print("[*] 🔁  DGA DNS sniffer active (UDP/53 via Npcap)")
        sniff(
            filter="udp port 53",
            prn=cb,
            store=False,
            stop_filter=lambda _: not dga._running,
        )
    except Exception as e:
        print(f"[-] DGA DNS monitor error: {e}")

# ── Entry point

def start_daemon(target_dir: str, webhook_url: str = "", webhooks: dict | None = None):
    """Starts the headless daemon monitor on the specified folder path."""
    if not os.path.exists(target_dir):
        print(f"\n[-] CRITICAL: Folder '{target_dir}' does not exist.")
        time.sleep(5)
        return
    
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute("DELETE FROM event_timeline")
            conn.execute("DELETE FROM chain_alerts")
        print("[*] Event timeline cleared — fresh session started.")
    except Exception:
        pass

    logic = ScannerLogic()
    logic.headless_mode = True

    lolbas     = LolbasDetector(webhook_url=webhook_url)
    byovd      = ByovdDetector()
    feodo      = FeodoMonitor(auto_isolate_cb=_isolate_network)
    dga        = DgaMonitor(auto_isolate_cb=_isolate_network)
    ja3        = Ja3Monitor(auto_isolate_cb=_isolate_network)
    correlator = ChainCorrelator(webhook_url=webhook_url, webhooks=webhooks or {})
    baseline   = BaselineEngine()
    amsi       = AmsiMonitor()
    lolbin     = LolbinDetector(webhook_url=webhook_url)
    fileless   = FilelessMonitor(correlator=correlator)

    print(f"\n[+] CyberSentinel Daemon v1 Active")
    print(f"[*] 📂  Watching     : {os.path.abspath(target_dir)}")
    print(f"[*] ⚙️   WMI          : process + driver interception (100 ms polling)")
    print(f"[*] ⚡  ETW/4688     : kernel-synchronous process creation (catches sub-100ms LOLBins)")
    print(f"[*] 🌐  Feodo        : {len(feodo._blocklist)} C2 IPs loaded")
    print(f"[*] 🔁  DGA          : entropy analysis active")
    print(f"[*] 🔗  Chains       : {len(ATTACK_CHAINS)} signatures loaded")
    print(f"[*] 🔍  LolbinDetect : pattern DB loaded")
    print(f"[*] 💀  BYOVD        : kernel driver monitor active (live feed + static DB)")
    print(f"[*] 🪤  AMSI Hook    : FilelessMonitor + AmsiScanner active")

    feodo.start()
    ja3.start()
    dga.start()  # Mark DGA monitor active before DNS sniff thread begins
    amsi.start()
    # Lowered from 120s. 30s gives meaningful coverage while not hammering
    # the scheduler. The first scan now runs immediately (no initial sleep).
    fileless.start_memory_monitor(scan_interval=30)
    byovd.start_realtime_monitor()
    if not baseline.is_learning():
        baseline.start_detection()

    # Capture daemon's own identity so both monitor threads can skip self-detection.
    _self_pid = os.getpid()
    _self_exe = os.path.abspath(sys.executable).lower()

    threading.Thread(
        target=_monitor_processes,
        args=(logic, lolbas, byovd, baseline, dga, lolbin, fileless, _self_pid, _self_exe),
        daemon=True,
    ).start()
    # fileless is now passed to the ETW thread so it can AMSI-scan script hosts
    threading.Thread(
        target=_monitor_processes_etw,
        args=(lolbas, lolbin, fileless, _self_pid, _self_exe),
        daemon=True,
    ).start()
    threading.Thread(target=_run_correlator, args=(correlator,), daemon=True).start()
    # Fix: DNS sniffer thread feeds DgaMonitor.analyse() — previously DGA was
    # instantiated but never connected to any live data source.
    threading.Thread(target=_monitor_dns, args=(dga,), daemon=True).start()

    handler  = ThreatHandler(logic)
    observer = Observer()
    observer.schedule(handler, target_dir, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        byovd.stop_realtime_monitor()
        fileless.stop()
        feodo.stop()
        ja3.stop()
        dga.stop()  # signals _monitor_dns thread to exit
        amsi.stop()
        print("\n[*] Daemon shutdown complete.")
    observer.join()
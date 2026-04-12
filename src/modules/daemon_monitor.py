# modules/daemon_monitor.py — Headless Daemon: WMI hook + watchdog + all detectors
#
# Thread map:
#   Thread 1 (main)    — watchdog folder observer
#   Thread 2 (daemon)  — WMI process/driver hook (LoLBin + BYOVD + baseline)
#   Thread 3 (daemon)  — ETW / Security Event 4688 process-creation monitor
#   Thread 4 (daemon)  — Feodo C2 IP monitor
#   Thread 5 (daemon)  — JA3 TLS sniffer (optional, scapy)
#   Thread 6 (daemon)  — AMSI ScriptBlock event-log monitor (optional, pywin32)
#   Thread 7 (daemon)  — Chain correlator sweep every 60 s

import os
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
from .amsi_hook        import AmsiScanner, FilelessMonitor
from .lolbin_detector  import LolbinDetector
from . import colors, utils

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


# ─────────────────────────────────────────────────────────────────────────────
#  ETW / Security Event 4688 monitor
# ─────────────────────────────────────────────────────────────────────────────

# Bounded seen-record tracker for the ETW loop.
# The original implementation used a plain set[int] that grew indefinitely.
# On a busy machine (hundreds of process creations per minute) this consumed
# hundreds of MB over a multi-day daemon run.
# A deque-backed ring buffer keeps membership O(1) while capping memory.
_ETW_SEEN_MAX = 50_000


class _BoundedSeen:
    """O(1) membership test with a fixed memory ceiling."""
    __slots__ = ("_dq", "_s")

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


def _monitor_processes_etw(lolbas: LolbasDetector, lolbin, fileless: FilelessMonitor):
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
                exe_path    = inserts[5]  if len(inserts) > 5  else ""
                cmdline     = inserts[8]  if len(inserts) > 8  else ""
                parent_path = inserts[13] if len(inserts) > 13 else ""

                name        = os.path.basename(exe_path).lower() if exe_path else ""
                parent_name = os.path.basename(parent_path).lower() if parent_path else ""

                print(
                    f"[ETW-DEBUG] 4688: name={name!r} "
                    f"inserts_len={len(inserts)} cmdline={cmdline!r}"
                )

                if not name:
                    continue

                # ── LoLBin checks ─────────────────────────────────────────────
                hit = lolbas.check_process(
                    name, cmdline,
                    from_daemon=True,
                    parent_name=parent_name,
                    exe_path=exe_path,
                )
                if hit:
                    colors.critical(lolbas.format_alert(hit))

                lolbin_hit = lolbin.check(name, cmdline)
                if lolbin_hit:
                    lolbin.print_alert(lolbin_hit)

                # ── AMSI / fileless script scanning ───────────────────────────
                # Route script host cmdlines through AMSI heuristics.
                # This mirrors the WMI path and was missing from the ETW path,
                # meaning mshta/wscript content was never AMSI-scanned from 4688.
                if name in _SCRIPT_HOSTS and cmdline:
                    fileless.scan_script(
                        cmdline,
                        source_name=f"ETW:{name}",
                        pid=0,
                    )

        except Exception as _etw_err:
            print(f"[ETW] loop error: {_etw_err}")

        time.sleep(POLL_SECS)


# ─────────────────────────────────────────────────────────────────────────────
#  WMI process creation monitor
# ─────────────────────────────────────────────────────────────────────────────

def _monitor_processes(logic, lolbas, byovd, baseline, dga, lolbin, fileless):
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

            # ── CommandLine: read immediately then retry if empty ──────────────
            # WMI returns None for short-lived processes because the OS recycles
            # the PEB before WMI can read it.  Strategy:
            #   1. Use what WMI already gave us.
            #   2. If empty, sleep 80 ms and re-query Win32_Process by PID.
            #   3. If still empty, try psutil.
            #   4. Fall back to empty string — lolbas_detector Layer 6 still
            #      emits a name-only confidence-adjusted alert for known LOLBins.
            cmdline = proc.CommandLine or ""
            if not cmdline and pid:
                time.sleep(0.08)
                try:
                    procs = c.Win32_Process(ProcessId=pid)
                    if procs:
                        cmdline = procs[0].CommandLine or ""
                except Exception:
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
            if hit:
                colors.critical(lolbas.format_alert(hit))

            lolbin_hit = lolbin.check(name, cmdline, pid=pid)
            if lolbin_hit:
                lolbin.print_alert(lolbin_hit)

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
            if name.lower() in _SCRIPT_HOSTS and cmdline:
                fileless.scan_script(
                    cmdline,
                    source_name=f"{name}[PID:{pid}]",
                    pid=pid,
                )

            # ── Standard PE scan (non-Windows binaries only) ─────────────────
            if exe_path and "c:\\windows" not in exe_path.lower():
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


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def start_daemon(target_dir: str, webhook_url: str = ""):
    """Starts the headless daemon monitor on the specified folder path."""
    if not os.path.exists(target_dir):
        print(f"\n[-] CRITICAL: Folder '{target_dir}' does not exist.")
        time.sleep(5)
        return

    logic = ScannerLogic()
    logic.headless_mode = True

    lolbas     = LolbasDetector(webhook_url=webhook_url)
    byovd      = ByovdDetector()
    feodo      = FeodoMonitor()
    dga        = DgaMonitor()
    ja3        = Ja3Monitor()
    correlator = ChainCorrelator()
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
    amsi.start()
    # Lowered from 120s. 30s gives meaningful coverage while not hammering
    # the scheduler. The first scan now runs immediately (no initial sleep).
    fileless.start_memory_monitor(scan_interval=30)
    byovd.start_realtime_monitor()
    if not baseline.is_learning():
        baseline.start_detection()

    threading.Thread(
        target=_monitor_processes,
        args=(logic, lolbas, byovd, baseline, dga, lolbin, fileless),
        daemon=True,
    ).start()
    # fileless is now passed to the ETW thread so it can AMSI-scan script hosts
    threading.Thread(
        target=_monitor_processes_etw,
        args=(lolbas, lolbin, fileless),
        daemon=True,
    ).start()
    threading.Thread(target=_run_correlator, args=(correlator,), daemon=True).start()

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
        amsi.stop()
        print("\n[*] Daemon shutdown complete.")
    observer.join()
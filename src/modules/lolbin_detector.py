# modules/lolbin_detector.py — Feature 1: Living-off-the-Land Binary Abuse Detection

import json
import os
import re
from dataclasses import dataclass, field
from . import colors
import sqlite3
import datetime
from . import utils

from .intel_updater import load_lolbas

# Dev tool parents that legitimately spawn LoLBins (e.g. node.exe → powershell -enc).
# Imported from lolbas_detector to keep the definition in one place.
# Falls back to a local copy if the import fails (e.g. circular import edge-case).
try:
    from .lolbas_detector import DEV_TOOL_PARENTS as _DEV_TOOL_PARENTS
except ImportError:
    _DEV_TOOL_PARENTS: frozenset[str] = frozenset({
        "node.exe", "code.exe", "electron.exe",
        "npm.cmd", "npm", "yarn.cmd", "yarn",
        "python.exe", "python3.exe", "git.exe", "java.exe",
    })

@dataclass
class LolbinAlert:
    binary:       str
    mitre:        str
    tactic:       str
    matched_args: list[str]
    description:  str
    command_line: str
    pid:          int = 0

class LolbinDetector:
    """
    Loads LOLBAS abuse patterns once at startup and provides O(1) binary-name
    lookups for every process creation event in the WMI daemon.
    """

    def __init__(self, webhook_url: str = ""):
        self._patterns: dict[str, dict] = {}   # binary_name_lower → pattern entry
        self._webhook_url: str = webhook_url
        self._load()

    def _load(self):
        try:
            raw = load_lolbas()
            for entry in raw:
                name = (entry.get("Name") or "").lower().strip()
                if not name:
                    continue

                commands = entry.get("Commands") or []

                mitre  = next((c.get("MitreID",  "") for c in commands if c.get("MitreID")),  "")
                tactic = next((c.get("Category", "") for c in commands if c.get("Category")), "")

                patterns: list[str] = []
                for cmd in commands:
                    for token in (cmd.get("Command") or "").split():
                        if token.startswith(("-", "/")) and len(token) > 1:
                            flag = token.rstrip(".,;:").lower()
                            if flag not in patterns:
                                patterns.append(flag)

                self._patterns[name] = {
                    "name":        name,
                    "mitre":       mitre,
                    "tactic":      tactic,
                    "description": entry.get("Description", ""),
                    "patterns":    patterns,
                }

            print(f"[+] LolbinDetector: {len(self._patterns)} LOLBAS entries loaded from intel feed.")
        except Exception as e:
            print(f"[!] LolbinDetector: failed to load intel feed — {e}")

    def check(self, process_name: str, command_line: str, pid: int = 0,
              parent_name: str = "") -> LolbinAlert | None:
        if not process_name:
            return None

        raw = os.path.basename(process_name).lower().strip()
        if not raw.endswith(".exe"):
            raw += ".exe"

        entry = self._patterns.get(raw)
        if not entry:
            return None

        # Suppress lolbin_detector alerts when a known dev tool is the parent.
        # lolbas_detector will still fire at MEDIUM confidence with full context,
        # so the analyst is informed — we just avoid the duplicate lower-quality alert.
        if parent_name and parent_name.lower() in _DEV_TOOL_PARENTS:
            return None

        # WMI Win32_Process.CommandLine is often None for short-lived processes
        # because the OS recycles the PEB before WMI reads it.  When that happens
        # we still know the binary name is a known LOLBin, so we emit a
        # LOW-confidence alert rather than silently dropping the event.
        if not command_line:
            return LolbinAlert(
                binary       = raw,
                mitre        = entry["mitre"],
                tactic       = entry["tactic"],
                matched_args = ["<cmdline unavailable — WMI race>"],
                description  = entry["description"] + " [cmdline not captured by WMI]",
                command_line = "",
                pid          = pid,
            )

        cmd_lower = command_line.lower()
        matched = [p for p in entry.get("patterns", []) if p.lower() in cmd_lower]

        if matched:
            return LolbinAlert(
                binary       = raw,
                mitre        = entry["mitre"],
                tactic       = entry["tactic"],
                matched_args = matched,
                description  = entry["description"],
                command_line = command_line,
                pid          = pid,
            )
        return None

    def print_alert(self, alert: LolbinAlert):
        colors.critical(f"\n{'='*62}")
        colors.critical(f"  [LOLBIN ALERT] Living-off-the-Land Abuse Detected!")
        colors.critical(f"{'='*62}")
        colors.warning(f"  Binary     : {alert.binary}  (PID: {alert.pid})")
        colors.warning(f"  MITRE      : {alert.mitre}  —  {alert.tactic}")
        print(        f"  Description: {alert.description}")
        print(        f"  Matched Args: {', '.join(alert.matched_args)}")
        print(        f"  Command Line: {alert.command_line[:200]}")
        colors.critical(f"{'='*62}\n")
        self._save_to_db(alert)

    def format_alert(self, alert: LolbinAlert) -> str:
        """Returns a plain-text formatted alert string for GUI display."""
        return (
            f"{'='*62}\n"
            f"  [LOLBIN ALERT] Living-off-the-Land Abuse Detected!\n"
            f"{'='*62}\n"
            f"  Binary      : {alert.binary}  (PID: {alert.pid})\n"
            f"  MITRE       : {alert.mitre}  —  {alert.tactic}\n"
            f"  Description : {alert.description}\n"
            f"  Matched Args: {', '.join(alert.matched_args)}\n"
            f"  Command Line: {alert.command_line[:200]}\n"
            f"{'='*62}"
        )

    def _save_to_db(self, alert: LolbinAlert):
        """Persists a LolbinAlert to fileless_alerts so the GUI page shows it."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = json.dumps([
            {
                "mitre":     alert.mitre,
                "indicator": f"{alert.tactic} — matched: {', '.join(alert.matched_args)}",
            }
        ])
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO fileless_alerts (source, findings, pid, timestamp) "
                    "VALUES (?,?,?,?)",
                    (
                        f"LOLBIN_DETECTOR [{alert.binary}]",
                        findings,
                        alert.pid,
                        now,
                    ),
                )
        except Exception:
            pass

        # Fire webhook if configured
        if self._webhook_url:
            try:
                utils.send_webhook_alert(
                    self._webhook_url,
                    "🟠 LOLBin Detector Alert",
                    {
                        "Binary":   alert.binary,
                        "MITRE":    alert.mitre,
                        "Tactic":   alert.tactic,
                        "Matched":  ", ".join(alert.matched_args),
                        "Command":  alert.command_line[:300],
                        "PID":      str(alert.pid),
                    },
                )
            except Exception:
                pass

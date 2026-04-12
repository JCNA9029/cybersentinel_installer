# modules/lolbin_detector.py — Feature 1: Living-off-the-Land Binary Abuse Detection
#
# Closes the most critical blind spot in the WMI daemon: CyberSentinel previously
# excluded ALL c:\windows binaries. Attackers leverage this exclusion intentionally —
# 79% of targeted attacks in 2023 used LOLBins (Picus Blue Report 2025).
#
# This module loads the LOLBAS project pattern database (data/lolbas_patterns.json)
# and checks every new process name + command line against known abuse argument patterns.
# It is purely a static lookup — zero network calls, negligible CPU cost.

import json
import os
import re
from dataclasses import dataclass, field
from . import colors
import sqlite3
import datetime
from . import utils

_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "lolbas_patterns.json")

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
        if not os.path.exists(_DATA_PATH):
            print(f"[!] LolbinDetector: pattern database not found at {_DATA_PATH}")
            return
        try:
            with open(_DATA_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("binaries", []):
                key = entry["name"].lower()
                self._patterns[key] = entry
            print(f"[+] LolbinDetector: {len(self._patterns)} LOLBAS patterns loaded.")
        except Exception as e:
            print(f"[!] LolbinDetector: failed to load patterns — {e}")

    def check(self, process_name: str, command_line: str, pid: int = 0) -> LolbinAlert | None:
        if not process_name:
            return None

        # Normalise: strip path prefix, ensure .exe suffix
        raw = os.path.basename(process_name).lower().strip()
        if not raw.endswith(".exe"):
            raw += ".exe"

        entry = self._patterns.get(raw)
        if not entry:
            return None

        # ── WMI CommandLine fallback ──────────────────────────────────────────
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

        # Case-insensitive pattern match on the command line
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

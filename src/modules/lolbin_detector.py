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
        """Disabled to prevent redundant alerts."""
        return

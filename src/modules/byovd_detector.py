# modules/byovd_detector.py — Bring Your Own Vulnerable Driver (BYOVD) Detector
#
# Merged module combining ByovdDetector and DriverGuard.
#
# Solves: Attackers load legitimate, Microsoft-signed drivers that contain known
# vulnerabilities to gain kernel-level code execution and kill EDR processes.
# This module monitors driver load events via WMI and cross-references each
# driver's SHA256 hash against the LOLDrivers community database.
#
# Data source: LOLDrivers Project (https://www.loldrivers.io/)
# Real-world threat: CSA Singapore Advisory AD-2025-018 explicitly flags BYOVD
# as the primary EDR-killer mechanism used in ransomware pre-deployment.
#
# Detection strategy:
#   1. Live LOLDrivers feed via intel_updater (SHA256 + filename dual lookup)
#   2. Static local loldrivers.json fallback
#   3. Real-time WMI background monitor (polls Win32_SystemDriver every 10s)
#   4. Webhook alerts on detection
#   5. SQLite persistence for dashboard and audit trail

import os
import json
import hashlib
import threading
import sqlite3
import datetime
from . import colors, utils
from .intel_updater import load_loldrivers

_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "loldrivers.json")

DRIVERS_DIR = r"C:\Windows\System32\drivers"


class ByovdDetector:
    """
    Unified BYOVD detector combining live feed + static fallback + real-time WMI monitor.

    Lookup is O(1) via pre-built hash sets — zero performance impact on the daemon.
    Exposes check_driver(path) for both real-time monitoring and on-demand manual scans.
    """

    def __init__(self, webhook_url: str = "", headless: bool = False):
        self.webhook_url = webhook_url
        self.headless    = headless

        # Primary lookup: SHA256 → driver metadata (from live feed)
        self._sha256_map: dict[str, dict] = {}
        # Secondary lookup: lowercase filename → metadata (fallback)
        self._name_map: dict[str, dict] = {}

        self._load_live_feed()
        self._load_static_fallback()

    # ─────────────────────────────────────────────
    #  DATABASE LOADING
    # ─────────────────────────────────────────────

    def _load_live_feed(self):
        """
        Parses the live LOLDrivers JSON feed via intel_updater into O(1) lookup structures.
        Covers SHA256 exact match and filename fallback.
        """
        try:
            raw = load_loldrivers()
            loaded = 0
            for driver in raw:
                name        = (driver.get("Tags") or [""])[0] if driver.get("Tags") else ""
                category    = driver.get("Category", "")
                cve_list  = driver.get("CVE") or []
                mitre_id  = driver.get("MitreID", "")
                cves        = ", ".join(cve_list) if isinstance(cve_list, list) else str(cve_list)
                cmds = driver.get("Commands") or {}
                description = cmds.get("Usecase") or cmds.get("Description") or "Known vulnerable driver"
                filename = (driver.get("Tags") or [""])[0] 
                vendor      = driver.get("Vendor", "Unknown")
                known_tools = driver.get("KnownMalware", [])

                metadata = {
                    "name":        name or filename,
                    "filename":    filename,
                    "category":    category,
                    "cves":        cves,
                    "cve":         cves,
                    "description": description,
                    "vendor":      vendor,
                    "known_tools": known_tools if isinstance(known_tools, list) else [],
                }

                for sample in driver.get("KnownVulnerableSamples") or []:
                    sha256 = (sample.get("SHA256") or "").lower().strip()
                    if sha256 and len(sha256) == 64:
                        self._sha256_map[sha256] = metadata
                        loaded += 1

                if filename:
                    self._name_map[filename.lower()] = metadata

            if loaded:
                print(f"[*] BYOVD: Loaded {loaded} vulnerable driver hashes from live LOLDrivers feed.")
        except Exception as e:
            print(f"[!] BYOVD: Live feed load failed — {e}. Falling back to static database.")

    def _load_static_fallback(self):
        """
        Loads the bundled local loldrivers.json as a fallback / supplement.
        Entries already present from the live feed are not overwritten.
        """
        if not os.path.exists(_DATA_PATH):
            return
        try:
            with open(_DATA_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            added = 0
            for entry in data.get("drivers", []):
                key = (entry.get("sha256") or "").lower()
                if key and key not in self._sha256_map:
                    self._sha256_map[key] = {
                        "name":        entry.get("name", ""),
                        "filename":    entry.get("name", ""),
                        "category":    "",
                        "cves":        entry.get("cve", "N/A"),
                        "cve":         entry.get("cve", "N/A"),
                        "description": entry.get("description", ""),
                        "vendor":      entry.get("vendor", "Unknown"),
                        "known_tools": entry.get("known_tools", []),
                    }
                    added += 1
            if added:
                print(f"[*] BYOVD: Added {added} additional signatures from static fallback database.")
        except Exception as e:
            print(f"[!] BYOVD: Static fallback load failed — {e}")

    # ─────────────────────────────────────────────
    #  DETECTION
    # ─────────────────────────────────────────────

    def check_driver(self, driver_path: str) -> dict | None:
        """
        Checks a driver file for known vulnerabilities.

        Strategy:
          1. Hash the file (SHA256) → exact match against LOLDrivers
          2. If unreadable, fall back to filename match (lower confidence)

        Returns:
            Finding dict if vulnerable driver detected, None if clean.
        """
        if not driver_path or not os.path.exists(driver_path):
            return None

        finding = None

        # Step 1: SHA256 exact match (highest confidence)
        sha256 = self._hash_file(driver_path)
        if sha256:
            meta = self._sha256_map.get(sha256)
            if meta:
                finding = self._build_finding(driver_path, sha256, meta, "SHA256-exact")

        # Step 2: Filename fallback (medium confidence)
        if finding is None:
            fname = os.path.basename(driver_path).lower()
            meta  = self._name_map.get(fname)
            if meta:
                finding = self._build_finding(driver_path, sha256 or "N/A", meta, "filename-match")

        if finding:
            self._handle_detection(finding)

        return finding

    def _build_finding(self, path: str, sha256: str, meta: dict, match_type: str) -> dict:
        return {
            "type":        "BYOVD",
            "driver_path": path,
            "driver_name": meta.get("name", os.path.basename(path)),
            "sha256":      sha256,
            "cves":        meta.get("cves", "N/A"),
            "cve":         meta.get("cve",  "N/A"),
            "category":    meta.get("category", ""),
            "description": meta.get("description", ""),
            "vendor":      meta.get("vendor", "Unknown"),
            "known_tools": meta.get("known_tools", []),
            "match_type":  match_type,
        }

    def _handle_detection(self, finding: dict):
        """Fires alerts on a BYOVD match — screen, SQLite, event timeline, and webhook."""
        name    = finding["driver_name"]
        path    = finding["driver_path"]
        sha256  = finding["sha256"]
        cve     = finding["cves"]
        vendor  = finding["vendor"]
        tools   = ", ".join(finding["known_tools"]) if finding["known_tools"] else "N/A"
        desc    = finding["description"]

        confidence = "HIGH" if finding["match_type"] == "SHA256-exact" else "MEDIUM"

        colors.critical(f"\n{'='*64}")
        colors.critical(f"  [BYOVD ALERT] Vulnerable Kernel Driver Loaded! [{confidence}]")
        colors.critical(f"{'='*64}")
        colors.warning(f"  Driver    : {name}")
        colors.warning(f"  Path      : {path}")
        colors.warning(f"  SHA-256   : {sha256}")
        colors.warning(f"  CVE       : {cve}   Vendor: {vendor}")
        print(         f"  Risk      : {desc}")
        print(         f"  Used by   : {tools}")
        colors.critical(f"  ACTION    : Investigate immediately — kernel-level EDR bypass risk.")
        colors.critical(f"{'='*64}\n")

        self._save_alert(finding)

        if self.webhook_url:
            utils.send_webhook_alert(
                self.webhook_url,
                title="BYOVD — Vulnerable Driver Loaded",
                details={
                    "Driver":        name,
                    "Path":          path,
                    "SHA-256":       sha256,
                    "CVE":           cve,
                    "Vendor":        vendor,
                    "Known malware": tools,
                    "Risk":          desc,
                    "Confidence":    confidence,
                },
            )

    def _save_alert(self, finding: dict):
        """Persists a BYOVD alert to both driver_alerts and event_timeline tables."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO driver_alerts
                       (sha256, driver_name, path, cve, description, timestamp)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        finding["sha256"],
                        finding["driver_name"],
                        finding["driver_path"],
                        finding["cves"],
                        finding["description"],
                        now,
                    ),
                )
                conn.execute(
                    "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                    (
                        "BYOVD_LOAD",
                        json.dumps({
                            "driver": finding["driver_name"],
                            "cves":   finding["cves"],
                        }),
                        0,
                        now,
                    ),
                )
        except Exception:
            pass

    # ─────────────────────────────────────────────
    #  FORMATTING
    # ─────────────────────────────────────────────

    def format_alert(self, finding: dict) -> str:
        """Formats a BYOVD finding dict into a human-readable alert string."""
        confidence = "HIGH" if finding["match_type"] == "SHA256-exact" else "MEDIUM"
        return (
            f"\n{'='*60}\n"
            f"  🔴  BYOVD — VULNERABLE DRIVER LOADED  [{confidence} CONFIDENCE]\n"
            f"  Driver   : {finding['driver_name']}\n"
            f"  Path     : {finding['driver_path']}\n"
            f"  CVE(s)   : {finding['cves']}\n"
            f"  Category : {finding['category']}\n"
            f"  Details  : {finding['description']}\n"
            f"  SHA256   : {finding['sha256'][:32]}...\n"
            f"  Match    : {finding['match_type']}\n"
            f"  ACTION   : Investigate immediately — kernel-level EDR bypass risk\n"
            f"{'='*60}"
        )

    # ─────────────────────────────────────────────
    #  SCANNING
    # ─────────────────────────────────────────────

    def scan_loaded_drivers(self) -> list[dict]:
        """
        One-shot scan of all currently loaded kernel drivers in System32\\drivers.
        Called on-demand from both the BYOVD page and the DriverGuard page.
        """
        findings = []
        if not os.path.exists(DRIVERS_DIR):
            return findings
        print(f"[*] BYOVD: Scanning drivers in {DRIVERS_DIR} ...")
        for fname in os.listdir(DRIVERS_DIR):
            if fname.lower().endswith(".sys"):
                result = self.check_driver(os.path.join(DRIVERS_DIR, fname))
                if result:
                    findings.append(result)
        return findings

    # ─────────────────────────────────────────────
    #  REAL-TIME WMI MONITOR
    # ─────────────────────────────────────────────

    def start_realtime_monitor(self):
        self._stop_monitor = threading.Event()
        t = threading.Thread(target=self._poll_drivers, daemon=True)
        t.start()
        print("[*] BYOVD: Real-time kernel driver monitor started.")

    def stop_realtime_monitor(self):
        if hasattr(self, "_stop_monitor"):
            self._stop_monitor.set()
            print("[*] BYOVD: Real-time kernel driver monitor stopped.")

    def _poll_drivers(self):
        seen: set[str] = set()
        try:
            import pythoncom, importlib, sys
            pythoncom.CoInitialize()
            try:
                if 'wmi' in sys.modules:
                    importlib.reload(sys.modules['wmi'])
                import wmi
                c = wmi.WMI()
                for drv in c.Win32_SystemDriver():
                    if drv.PathName:
                        seen.add(drv.PathName.lower())
            finally:
                pythoncom.CoUninitialize()
        except Exception:
            pass

        import time
        while not self._stop_monitor.is_set():
            time.sleep(10)
            try:
                import pythoncom, wmi
                pythoncom.CoInitialize()
                try:
                    c = wmi.WMI()
                    for drv in c.Win32_SystemDriver():
                        path = drv.PathName or ""
                        if path.lower() not in seen:
                            seen.add(path.lower())
                            resolved = path.replace(
                                "\\SystemRoot\\",
                                os.environ.get("SystemRoot", "C:\\Windows") + "\\"
                            )
                            self.check_driver(resolved)
                finally:
                    pythoncom.CoUninitialize()
            except Exception:
                pass
    # ─────────────────────────────────────────────
    #  UTILITIES
    # ─────────────────────────────────────────────

    def _hash_file(self, path: str) -> str | None:
        """SHA256 hash via chunked read (65536-byte chunks). Returns None on any I/O error."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest().lower()
        except Exception:
            return None


# Backwards-compatibility alias so any code still importing DriverGuard keeps working
DriverGuard = ByovdDetector

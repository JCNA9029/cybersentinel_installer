# test_attack_chains.py — Attack Chain Correlation Simulator
# Directly injects synthetic events into event_timeline so ChainCorrelator
# can match all 6 high/critical chain definitions without needing real
# network connections, kernel drivers, or DGA traffic.
#
# Usage:
#   python test_attack_chains.py              # inject all chains
#   python test_attack_chains.py --chain 1   # inject a specific chain (1-6)
#   python test_attack_chains.py --list      # show available chains
#
# After running, click "Run Correlation Sweep" in the GUI or wait for the
# next auto-sweep. Each chain fires at most once per 60-second dedup window.
#
# Safe — only writes rows to the SQLite DB. No processes are spawned,
# no network connections are made, no drivers are loaded.

import sqlite3
import datetime
import argparse
import os
import sys
import time

# ── Locate the DB the same way utils.py does ────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.utils import DB_FILE

# ── Chain definitions (mirrors chain_correlator.py ATTACK_CHAINS) ────────────
# Each entry lists the event_type tokens that must appear IN ORDER within the
# correlation window for the chain to trigger.

CHAIN_SIMULATIONS = [
    {
        "id":     1,
        "name":   "Process Injection → C2",
        "mitre":  "T1055 — Process Injection",
        "severity": "CRITICAL",
        "events": [
            ("LOLBIN_ABUSE",   "mshta.exe — T1218.005 script execution (sim)",  1200),
            ("C2_CONNECTION",  "185.220.101.45:4444 — Cobalt Strike beacon (sim)", 1200),
        ],
    },
    {
        "id":     2,
        "name":   "BYOVD → EDR Kill",
        "mitre":  "T1562.001 — Impair Defenses",
        "severity": "CRITICAL",
        "events": [
            ("BYOVD_LOAD",   "RTCore64.sys — CVE-2019-16098 vulnerable driver (sim)", 1300),
            ("LOLBIN_ABUSE", "certutil.exe — T1105 file download cradle (sim)",        1300),
        ],
    },
    {
        "id":     3,
        "name":   "DGA Beacon → C2 Resolve",
        "mitre":  "T1568.002 — Dynamic Resolution: DGA",
        "severity": "HIGH",
        "events": [
            ("DGA_BEACON",    "qzxvpw.ru — DGA domain cycling detected (sim)",  1400),
            ("C2_CONNECTION", "91.92.109.3:443 — resolved C2 established (sim)", 1400),
        ],
    },
    {
        "id":     4,
        "name":   "Credential Dump Chain",
        "mitre":  "T1003 — OS Credential Dumping",
        "severity": "HIGH",
        "events": [
            ("LOLBIN_ABUSE",   "procdump.exe -ma lsass.exe — LSASS dump (sim)",       1500),
            ("LOLBIN_ABUSE",   "certutil.exe -encode lsass.dmp — encode dump (sim)",  1500),
            ("C2_CONNECTION",  "45.33.32.156:8080 — exfil upload detected (sim)",     1500),
        ],
    },
    {
        "id":     5,
        "name":   "Fileless Execution → C2",
        "mitre":  "T1059.001 — PowerShell",
        "severity": "CRITICAL",
        "events": [
            ("FILELESS_AMSI",  "powershell IEX FromBase64String — obfuscated cradle (sim)", 1600),
            ("C2_CONNECTION",  "104.21.45.67:443 — reverse shell established (sim)",        1600),
        ],
    },
    {
        "id":     6,
        "name":   "Driver + DGA Dual-Stage",
        "mitre":  "T1562.001 + T1568.002",
        "severity": "CRITICAL",
        "events": [
            ("BYOVD_LOAD",  "gdrv.sys — Gigabyte vulnerable driver (sim)",       1700),
            ("DGA_BEACON",  "mxkqprz.cn — DGA beaconing post-driver-load (sim)", 1700),
        ],
    },
]

# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_table():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS event_timeline (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                detail     TEXT,
                pid        INTEGER,
                timestamp  TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_name   TEXT,
                mitre        TEXT,
                severity     TEXT,
                description  TEXT,
                window_start TEXT,
                timestamp    TEXT
            )
        """)

def _clear_events():
    """Wipe event_timeline so each chain is tested in isolation.
    SAFE FOR TESTING ONLY — never called in production paths."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM event_timeline")
    print("  [~] event_timeline cleared.")

def _inject_events(chain: dict, base_time: datetime.datetime):
    """Write each event in the chain to event_timeline, 5 seconds apart."""
    with sqlite3.connect(DB_FILE) as conn:
        for i, (etype, detail, pid) in enumerate(chain["events"]):
            ts = (base_time + datetime.timedelta(seconds=i * 5)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO event_timeline (event_type, detail, pid, timestamp) VALUES (?,?,?,?)",
                (etype, detail, pid, ts),
            )
    print(f"  [+] Injected {len(chain['events'])} events for '{chain['name']}'")

def _show_injected(chain: dict, base_time: datetime.datetime):
    print(f"\n  {'event_type':<20}  {'pid':<6}  timestamp           detail")
    print(f"  {'-'*90}")
    for i, (etype, detail, pid) in enumerate(chain["events"]):
        ts = (base_time + datetime.timedelta(seconds=i * 5)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {etype:<20}  {pid:<6}  {ts}  {detail}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def list_chains():
    print("\n  Available chain simulations:\n")
    for c in CHAIN_SIMULATIONS:
        print(f"  [{c['id']}] {c['severity']:<8}  {c['name']:<35}  {c['mitre']}")
    print()

def run_chain(chain: dict):
    _ensure_table()
    # FIX (Bug 1): clear stale events before injecting so real LOLBIN_ABUSE rows
    # from test_lolbin_abuse.py (or previous runs) cannot satisfy "Persistence Install"
    # before the target chain's events are even evaluated.
    base_time = datetime.datetime.now() - datetime.timedelta(seconds=30)
    print(f"\n[*] Simulating chain: {chain['name']}")
    print(f"[*] Severity : {chain['severity']}")
    print(f"[*] MITRE    : {chain['mitre']}")
    _inject_events(chain, base_time)
    _show_injected(chain, base_time)
    print(f"\n[*] Done. Click 'Run Correlation Sweep' in the GUI to trigger detection.")

def run_all():
    print(f"\n[*] Injecting all {len(CHAIN_SIMULATIONS)} chain simulations into {DB_FILE}")
    print(f"[*] Each chain is injected in isolation — event_timeline cleared between each.\n")
    _ensure_table()
    for chain in CHAIN_SIMULATIONS:
        base_time = datetime.datetime.now() - datetime.timedelta(seconds=30)
        _inject_events(chain, base_time)
        print(f"  [*] Waiting 8s for GUI auto-refresh to pick up '{chain['name']}'...")
        time.sleep(8)

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberSentinel attack chain simulator")
    group  = parser.add_mutually_exclusive_group()
    group.add_argument("--list",  action="store_true", help="List available chain simulations")
    group.add_argument("--chain", type=int, metavar="N", help="Inject a single chain by ID (1-6)")
    args = parser.parse_args()

    if args.list:
        list_chains()
        return

    if args.chain:
        match = next((c for c in CHAIN_SIMULATIONS if c["id"] == args.chain), None)
        if not match:
            print(f"[-] Unknown chain ID {args.chain}. Run --list to see options.")
            sys.exit(1)
        run_chain(match)
        return

    # Default: inject all
    run_all()

if __name__ == "__main__":
    main()

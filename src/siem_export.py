"""
siem_export.py — CyberSentinel SIEM Exporter
=============================================
Exports CyberSentinel detections and telemetry to Splunk (or any SIEM that
accepts Splunk-compatible HEC JSON) and/or a JSON Lines file.

Sourcetypes
-----------
  cybersentinel:detection   chain_alerts, c2_alerts, driver_alerts, fileless_alerts
  cybersentinel:telemetry   event_timeline (raw behavioral events)

Modes
-----
  --mode hec    Push to Splunk HTTP Event Collector
  --mode file   Write JSON Lines to disk  (default: cybersentinel_export.jsonl)
  --mode both   Do both simultaneously

Incremental
-----------
  State is stored in siem_export_state.json next to this script.
  Each run only exports records newer than the last successful export,
  so re-running is always safe — no duplicate events in Splunk.

Config
------
  Copy siem_config.json.example to siem_config.json and fill in your values,
  OR pass everything via CLI flags (CLI flags override the config file).

Usage
-----
  cd C:\\Users\\Acer\\Desktop\\CyberSentinel

  # One-shot file export (no config needed)
  python siem_export.py --mode file

  # Push to Splunk HEC
  python siem_export.py --mode hec --hec-url https://splunk:8088 --hec-token YOUR_TOKEN

  # Both, reading from config file
  python siem_export.py --mode both

  # Continuous mode — poll every N seconds and push deltas
  python siem_export.py --mode hec --watch 30

  # Force full re-export (ignores saved state)
  python siem_export.py --mode file --reset
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Iterator

# ── Path resolution — same pattern as all other CyberSentinel scripts ─────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.utils import DB_FILE  # noqa: E402

_THIS_DIR   = Path(os.path.dirname(os.path.abspath(__file__)))
_STATE_FILE = _THIS_DIR / "siem_export_state.json"
_CONFIG_FILE = _THIS_DIR / "siem_config.json"

_HOSTNAME = socket.gethostname()

# ── Config example written on first run if missing ────────────────────────────
_CONFIG_EXAMPLE = {
    "hec_url":       "https://your-splunk-host:8088",
    "hec_token":     "YOUR-HEC-TOKEN-HERE",
    "hec_index":     "cybersentinel",
    "output_file":   "cybersentinel_export.jsonl",
    "batch_size":    50,
    "_comment": (
        "hec_url: Splunk HEC endpoint (include port, no trailing slash). "
        "hec_token: token from Settings → Data Inputs → HTTP Event Collector. "
        "hec_index: target Splunk index (must exist and be assigned to the token). "
        "output_file: path for --mode file / --mode both JSON Lines output."
    ),
}

# ── Table definitions ─────────────────────────────────────────────────────────
# Each entry describes one DB table, how to query it, and how to map it to a
# Splunk event.  "ts_col" is the timestamp column used for incremental export.
# "id_col" is used as a tiebreaker when timestamps collide (None = use ts only).

_TABLES: list[dict] = [
    # ── Finished detections (sourcetype: cybersentinel:detection) ─────────────
    {
        "table":      "chain_alerts",
        "sourcetype": "cybersentinel:detection",
        "severity_col": "severity",
        "ts_col":     "timestamp",
        "id_col":     "id",
        "columns":    ["id", "chain_name", "mitre", "severity", "description", "window_start", "timestamp"],
        "label":      "Attack Chain",
    },
    {
        "table":      "c2_alerts",
        "sourcetype": "cybersentinel:detection",
        "severity_col": None,
        "ts_col":     "timestamp",
        "id_col":     "id",
        "columns":    ["id", "detection_type", "indicator", "malware_family", "details", "timestamp"],
        "label":      "C2 Fingerprint",
    },
    {
        "table":      "driver_alerts",
        "sourcetype": "cybersentinel:detection",
        "severity_col": None,
        "ts_col":     "timestamp",
        "id_col":     None,       # sha256 PK, no integer id
        "columns":    ["sha256", "driver_name", "path", "cve", "description", "timestamp"],
        "label":      "BYOVD Driver",
    },
    {
        "table":      "fileless_alerts",
        "sourcetype": "cybersentinel:detection",
        "severity_col": None,
        "ts_col":     "timestamp",
        "id_col":     "id",
        "columns":    ["id", "source", "findings", "pid", "timestamp"],
        "label":      "Fileless / AMSI",
    },
    # ── Raw behavioral telemetry (sourcetype: cybersentinel:telemetry) ─────────
    {
        "table":      "event_timeline",
        "sourcetype": "cybersentinel:telemetry",
        "severity_col": None,
        "ts_col":     "timestamp",
        "id_col":     "id",
        "columns":    ["id", "event_type", "detail", "pid", "timestamp"],
        "label":      "Behavioral Event",
    },
]


# ── State management ──────────────────────────────────────────────────────────

def _load_state() -> dict:
    """Load last-exported timestamps per table.  Returns {} on first run."""
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: dict):
    _STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _reset_state():
    if _STATE_FILE.exists():
        _STATE_FILE.unlink()
    print("  [*] State reset — next run will export all historical records.")


# ── DB helpers ────────────────────────────────────────────────────────────────

def _fetch_new_rows(table_def: dict, since_ts: str, batch_size: int) -> list[dict]:
    """
    Return rows newer than since_ts, ordered oldest-first so the state
    high-water mark can be updated incrementally.
    """
    cols   = ", ".join(table_def["columns"])
    ts_col = table_def["ts_col"]
    id_col = table_def["id_col"]
    table  = table_def["table"]

    order = f"{ts_col} ASC" + (f", {id_col} ASC" if id_col else "")

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT {cols} FROM {table} "
                f"WHERE {ts_col} > ? ORDER BY {order} LIMIT ?",
                (since_ts, batch_size),
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        # Table doesn't exist yet (e.g. no BYOVD events ever fired)
        return []


# ── Event formatting ──────────────────────────────────────────────────────────

def _parse_json_field(value: str | None) -> dict | str:
    """Try to parse a TEXT column that might contain JSON."""
    if not value:
        return ""
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except Exception:
            pass
    return value


def _to_epoch(ts_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' to Unix epoch for Splunk's 'time' field."""
    try:
        dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except Exception:
        return time.time()


def _build_splunk_event(table_def: dict, row: dict) -> dict:
    """
    Build a Splunk HEC event envelope.

    Splunk HEC format:
        {
            "time":       <epoch float>,
            "host":       "<hostname>",
            "source":     "CyberSentinel",
            "sourcetype": "cybersentinel:detection",
            "index":      "<configured index>",   # injected by caller
            "event":      { ...row fields... }
        }

    JSON-encoded TEXT columns (details, findings, etc.) are decoded in-place
    so Splunk field extraction works without needing a custom props.conf.
    """
    ts_str = row.get(table_def["ts_col"], "")

    # Build the event payload — decode any embedded JSON fields
    event: dict = {"_label": table_def["label"]}
    for key, value in row.items():
        if key in ("details", "findings", "detail", "components", "apis"):
            event[key] = _parse_json_field(value)
        else:
            event[key] = value

    # Add a normalised severity field so Splunk Notable Events work out of the box
    if table_def["severity_col"] and table_def["severity_col"] in row:
        event["_severity"] = row[table_def["severity_col"]]
    else:
        # Infer severity from event content for tables that don't have a column
        label = table_def["label"]
        if "chain" in label.lower() or "byovd" in label.lower() or "fileless" in label.lower():
            event["_severity"] = "HIGH"
        elif "c2" in label.lower():
            event["_severity"] = "CRITICAL"
        else:
            event["_severity"] = "MEDIUM"

    return {
        "time":       _to_epoch(ts_str),
        "host":       _HOSTNAME,
        "source":     "CyberSentinel",
        "sourcetype": table_def["sourcetype"],
        "event":      event,
    }


# ── HEC output ────────────────────────────────────────────────────────────────

def _push_hec(events: list[dict], hec_url: str, hec_token: str, hec_index: str) -> bool:
    """
    POST a batch of events to Splunk HEC.
    Splunk accepts multiple events in one request as newline-separated JSON objects.
    Returns True on success.
    """
    try:
        import requests as _requests
    except ImportError:
        print("  [!] 'requests' not installed — run: pip install requests")
        return False

    endpoint = hec_url.rstrip("/") + "/services/collector/event"
    headers  = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type":  "application/json",
    }

    # Inject index into each event, then serialise as newline-delimited JSON
    payload_lines = []
    for ev in events:
        ev_copy = dict(ev)
        if hec_index:
            ev_copy["index"] = hec_index
        payload_lines.append(json.dumps(ev_copy, default=str))

    payload = "\n".join(payload_lines)

    try:
        resp = _requests.post(endpoint, headers=headers, data=payload, timeout=10, verify=True)
        if resp.status_code == 200:
            return True
        print(f"  [!] HEC returned HTTP {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as e:
        print(f"  [!] HEC push failed — {e}")
        return False


# ── File output ───────────────────────────────────────────────────────────────

def _write_jsonl(events: list[dict], output_path: str):
    """Append events to a JSON Lines file (one JSON object per line)."""
    with open(output_path, "a", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, default=str) + "\n")


# ── Core export loop ──────────────────────────────────────────────────────────

def run_export(
    mode:        str,
    hec_url:     str  = "",
    hec_token:   str  = "",
    hec_index:   str  = "cybersentinel",
    output_file: str  = "cybersentinel_export.jsonl",
    batch_size:  int  = 50,
) -> int:
    """
    Run one export pass across all tables.
    Returns total number of events exported this pass.
    """
    state        = _load_state()
    total_pushed = 0

    for table_def in _TABLES:
        table    = table_def["table"]
        since_ts = state.get(table, "1970-01-01 00:00:00")

        rows = _fetch_new_rows(table_def, since_ts, batch_size)
        if not rows:
            continue

        events = [_build_splunk_event(table_def, row) for row in rows]

        success = True
        if mode in ("hec", "both"):
            ok = _push_hec(events, hec_url, hec_token, hec_index)
            if not ok:
                print(f"  [!] HEC push failed for {table} — state not advanced, will retry next run.")
                success = False

        if mode in ("file", "both") and success:
            _write_jsonl(events, output_file)

        if success:
            # Advance the high-water mark to the newest exported timestamp
            newest_ts = rows[-1][table_def["ts_col"]]
            state[table] = newest_ts
            total_pushed += len(events)
            print(f"  [+] {table:<20}  {len(events):>4} events  (up to {newest_ts})")

    _save_state(state)
    return total_pushed


# ── Config loading ────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if _CONFIG_FILE.exists():
        try:
            return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  [!] Could not read siem_config.json — {e}")
    return {}


def _write_config_example():
    example_path = _THIS_DIR / "siem_config.json.example"
    if not example_path.exists():
        example_path.write_text(json.dumps(_CONFIG_EXAMPLE, indent=2), encoding="utf-8")
        print(f"  [*] Config example written to {example_path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel SIEM exporter — push detections to Splunk or JSON Lines."
    )
    parser.add_argument(
        "--mode", choices=["hec", "file", "both"], default="file",
        help="Export mode: hec (Splunk HEC push), file (JSON Lines), or both. Default: file.",
    )
    parser.add_argument("--hec-url",   default="", help="Splunk HEC endpoint, e.g. https://splunk:8088")
    parser.add_argument("--hec-token", default="", help="Splunk HEC token")
    parser.add_argument("--hec-index", default="", help="Splunk index name (default: cybersentinel)")
    parser.add_argument("--output",    default="", help="JSON Lines output file path (--mode file / both)")
    parser.add_argument("--batch",     type=int, default=0, help="Max rows per table per pass (default: 50)")
    parser.add_argument(
        "--watch", type=int, default=0, metavar="SECONDS",
        help="Continuous mode — poll every N seconds. 0 = run once and exit.",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Clear saved state and re-export everything from the beginning.",
    )
    args = parser.parse_args()

    # Write example config on first run
    _write_config_example()

    # Merge: config file < CLI flags
    cfg = _load_config()
    hec_url     = args.hec_url     or cfg.get("hec_url",     "")
    hec_token   = args.hec_token   or cfg.get("hec_token",   "")
    hec_index   = args.hec_index   or cfg.get("hec_index",   "cybersentinel")
    output_file = args.output      or cfg.get("output_file", "cybersentinel_export.jsonl")
    batch_size  = args.batch       or cfg.get("batch_size",  50)

    if args.reset:
        _reset_state()

    # Validate HEC config if needed
    if args.mode in ("hec", "both"):
        if not hec_url or not hec_token:
            print(
                "  [!] --mode hec requires --hec-url and --hec-token\n"
                "      (or set hec_url / hec_token in siem_config.json)"
            )
            sys.exit(1)

    print(f"\n{'='*58}")
    print(f"  CyberSentinel SIEM Exporter")
    print(f"  Mode   : {args.mode.upper()}")
    print(f"  DB     : {DB_FILE}")
    if args.mode in ("file", "both"):
        print(f"  Output : {output_file}")
    if args.mode in ("hec", "both"):
        print(f"  HEC    : {hec_url}  (index: {hec_index})")
    print(f"{'='*58}\n")

    def _one_pass():
        n = run_export(
            mode        = args.mode,
            hec_url     = hec_url,
            hec_token   = hec_token,
            hec_index   = hec_index,
            output_file = output_file,
            batch_size  = batch_size,
        )
        if n == 0:
            print("  [=] No new events since last export.")
        else:
            print(f"\n  [✓] {n} events exported.")
        return n

    if args.watch > 0:
        print(f"  Watching — polling every {args.watch}s.  Ctrl+C to stop.\n")
        try:
            while True:
                _one_pass()
                print(f"  [*] Next poll in {args.watch}s...")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\n  [*] Stopped.")
    else:
        _one_pass()
        print()


if __name__ == "__main__":
    main()

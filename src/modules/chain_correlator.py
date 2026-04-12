# modules/chain_correlator.py — Behavioral Attack Chain Correlator
#
# Reads events from the shared event_timeline SQLite table (populated by all
# detectors) and matches their sequence against multi-step attack chain definitions.
# A single consolidated CRITICAL alert fires when a full chain completes within
# the correlation window — replacing N fragmented low-signal alerts.
#
# Webhook: fires a rich SOC L1 alert (Discord/Slack/Teams) when a chain triggers.
# Payload includes severity embed, MITRE ATT&CK link, per-event breakdown,
# and chain-specific L1 triage steps.
#
# MITRE reference: https://attack.mitre.org/
import json
import uuid
import sqlite3
import datetime
import urllib.parse
import requests
from . import utils
from . import colors

WINDOW_MINUTES    = 10  # correlation look-back (chain matching)
RETENTION_MINUTES = 60  # how long events stay in event_timeline for the GUI Live Feed

# Severity → Discord embed colour (decimal RGB)
_SEVERITY_COLOR = {
    "CRITICAL": 16711680,   # 0xFF0000 — red
    "HIGH":     16744192,   # 0xFF6800 — orange
    "MEDIUM":   16776960,   # 0xFFFF00 — yellow
    "LOW":      3389747,    # 0x33BB33 — green
}

# Severity → status icon
_SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

# Recommended L1 triage steps, keyed by chain name.
# Shown verbatim in the webhook embed so an L1 analyst can act without lookup.
_L1_ACTIONS: dict[str, list[str]] = {
    "Process Injection → C2": [
        "Isolate the host from the network immediately (break physical or NAC)",
        "Identify the injected process via PID in event details — dump its memory",
        "Block the C2 IP/domain at the perimeter firewall and EDR network policy",
        "Escalate to L2/IR — assume active shell; do NOT reboot the host",
    ],
    "BYOVD → EDR Kill": [
        "Verify EDR agent is still running on the affected host (check heartbeat)",
        "Collect the driver binary and submit SHA-256 to threat intel / VirusTotal",
        "Revoke driver signing cert if internal; open vendor ticket if third-party",
        "Escalate to L2 — assume defenses may be partially or fully blinded",
    ],
    "DGA Beacon → C2 Resolve": [
        "Pull full DNS query logs for the host for the past 30 minutes",
        "Sinkhole or null-route the resolved C2 domain at DNS and firewall",
        "Check for lateral movement — scan for the same domain in proxy logs",
        "Escalate to L2 — active C2 channel may already be established",
    ],
    "Credential Dump Chain": [
        "Reset credentials for ALL accounts that have logged into this host",
        "Check LSASS process handle list for unexpected parent processes",
        "Review AD / Azure AD / local SAM auth logs for post-dump misuse",
        "Escalate to L2 — treat credentials as compromised until proven otherwise",
    ],
    "Fileless Execution → C2": [
        "Pull PowerShell ScriptBlock logs (Event ID 4104) — decode full payload",
        "Block the identified C2 destination at proxy and perimeter firewall",
        "Enumerate WMI subscriptions and scheduled tasks for persistence artifacts",
        "Escalate to L2 — in-memory payload active; standard AV will not find it",
    ],
    "Driver + DGA Dual-Stage": [
        "Hard-isolate the host immediately — dual-stage indicates sophisticated actor",
        "Preserve volatile state: do NOT reboot; collect memory and DNS logs now",
        "Search SIEM for the same driver hash or DGA domain across all endpoints",
        "Escalate directly to L2/CSIRT — treat as active APT intrusion",
    ],
    "Persistence Install": [
        "Enumerate scheduled tasks, registry Run/RunOnce keys, and Startup folder",
        "Diff against baseline — identify new or modified autostart entries",
        "Remove the unauthorized persistence mechanism; re-image if a dropper found",
        "Escalate to L2 if a dropper binary or secondary payload is identified",
    ],
}

_DEFAULT_L1_ACTIONS = [
    "Monitor or isolate the affected host pending investigation",
    "Collect process, network, and Windows Event logs for the detection window",
    "Cross-reference PIDs and process names shown in the event details",
    "Escalate to L2 if activity cannot be attributed within 15 minutes",
]

ATTACK_CHAINS = [
    {
        "name":        "Process Injection → C2",
        "events":      ["LOLBIN_ABUSE", "C2_CONNECTION"],
        "mitre":       "T1055 — Process Injection",
        "mitre_url":   "https://attack.mitre.org/techniques/T1055/",
        "severity":    "CRITICAL",
        "description": "LoLBin abuse followed by outbound C2 — shellcode injected into trusted process to establish remote shell.",
    },
    {
        "name":        "BYOVD → EDR Kill",
        "events":      ["BYOVD_LOAD", "LOLBIN_ABUSE"],
        "mitre":       "T1562.001 — Impair Defenses",
        "mitre_url":   "https://attack.mitre.org/techniques/T1562/001/",
        "severity":    "CRITICAL",
        "description": "Vulnerable kernel driver loaded then LoLBin abused — classic EDR-kill pre-stage enabling payload deployment.",
    },
    {
        "name":        "DGA Beacon → C2 Resolve",
        "events":      ["DGA_BEACON", "C2_CONNECTION"],
        "mitre":       "T1568.002 — Dynamic Resolution: DGA",
        "mitre_url":   "https://attack.mitre.org/techniques/T1568/002/",
        "severity":    "HIGH",
        "description": "DGA cycling detected then outbound C2 connection established — malware successfully resolved active C2 IP.",
    },
    {
        "name":        "Credential Dump Chain",
        "events":      ["LOLBIN_ABUSE", "LOLBIN_ABUSE", "C2_CONNECTION"],
        "mitre":       "T1003 — OS Credential Dumping",
        "mitre_url":   "https://attack.mitre.org/techniques/T1003/",
        "severity":    "CRITICAL",
        "description": "Multiple LoLBin events then C2 connection — consistent with LSASS dump + encode + exfiltration chain.",
    },
    {
        "name":        "Fileless Execution → C2",
        "events":      ["FILELESS_AMSI", "C2_CONNECTION"],
        "mitre":       "T1059.001 — PowerShell",
        "mitre_url":   "https://attack.mitre.org/techniques/T1059/001/",
        "severity":    "CRITICAL",
        "description": "Obfuscated in-memory script intercepted then C2 established — fileless backdoor executed without touching disk.",
    },
    {
        "name":        "Driver + DGA Dual-Stage",
        "events":      ["BYOVD_LOAD", "DGA_BEACON"],
        "mitre":       "T1562.001 + T1568.002",
        "mitre_url":   "https://attack.mitre.org/techniques/T1562/001/",
        "severity":    "CRITICAL",
        "description": "Vulnerable driver loaded then DGA beaconing started — sophisticated actor disabling defenses while seeking new C2.",
    },
    {
        "name":        "Persistence Install",
        "events":      ["LOLBIN_ABUSE", "LOLBIN_ABUSE"],
        "mitre":       "T1547 — Boot/Logon Autostart",
        "mitre_url":   "https://attack.mitre.org/techniques/T1547/",
        "severity":    "HIGH",
        "description": "Two sequential LoLBin events — consistent with scheduled task creation + dropper download for persistence.",
    },
]


class ChainCorrelator:
    """Correlates event sequences into high-confidence attack chain alerts."""

    def __init__(self, webhook_url: str = "", webhooks: dict | None = None):
        self._webhook_url = webhook_url
        self._webhooks    = webhooks or {}

    def run_correlation(self) -> list[dict]:
        """Pull recent events and match against all chain definitions."""
        events = self._fetch_recent()
        if not events:
            return []

        seq       = [e["event_type"] for e in events]
        triggered = []

        window_start = events[0]["timestamp"] if events else ""
        for chain in ATTACK_CHAINS:
            if not self._sequence_present(seq, chain["events"]):
                continue

            matched_events = self._extract_matched_events(events, chain["events"])

            # Dedup key includes the timestamp of the first matched event so
            # two separate incidents triggering the same chain don't suppress
            # each other — only identical event sequences are deduplicated.
            first_ts = matched_events[0]["timestamp"] if matched_events else window_start
            if self._already_alerted(f"{chain['name']}_{first_ts}"):
                continue

            alert_id = str(uuid.uuid4())[:8].upper()

            finding = {
                "alert_id":       alert_id,
                "chain_name":     chain["name"],
                "mitre":          chain["mitre"],
                "mitre_url":      chain.get("mitre_url", ""),
                "severity":       chain["severity"],
                "description":    chain["description"],
                "window_start":   window_start,
                "matched_events": matched_events,
            }
            self._persist(finding)
            self._print_alert(finding)
            if self._webhook_url or self._webhooks.get("webhook_chains"):
                self._fire_webhook(finding)
            triggered.append(finding)

        self._prune_old_events()
        return triggered
    
    def _already_alerted(self, key: str) -> bool:
        """Dedup check keyed on chain_name + first matched event timestamp.
        Uses rsplit so chain names containing underscores are handled correctly."""
        chain_name, first_ts = key.rsplit("_", 1)
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                row = conn.execute(
                    """SELECT id FROM chain_alerts
                       WHERE chain_name=? AND window_start=? LIMIT 1""",
                    (chain_name, first_ts)
                ).fetchone()
            return row is not None
        except Exception:
            return False

    # ── helpers ──────────────────────────────────────────────────────────────

    def _fetch_recent(self) -> list[dict]:
        cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=WINDOW_MINUTES)
                  ).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT event_type, detail, pid, timestamp FROM event_timeline "
                    "WHERE timestamp >= ? ORDER BY timestamp ASC", (cutoff,)
                ).fetchall()
            return [{"event_type": r[0], "detail": r[1], "pid": r[2], "timestamp": r[3]} for r in rows]
        except Exception:
            return []
    
    def _prune_old_events(self):
        cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=RETENTION_MINUTES)
                  ).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                conn.execute("DELETE FROM event_timeline WHERE timestamp < ?", (cutoff,))
        except Exception:
            pass

    @staticmethod
    def _sequence_present(haystack: list[str], needle: list[str]) -> bool:
        idx = 0
        for item in haystack:
            if item == needle[idx]:
                idx += 1
                if idx == len(needle):
                    return True
        return False

    @staticmethod
    def _extract_matched_events(events: list[dict], needle: list[str]) -> list[dict]:
        """
        Walk the event list in order and return the specific events that satisfied
        the chain (same greedy algorithm as _sequence_present).  Detail JSON is
        parsed so the webhook embed can show process names, IPs, driver names, etc.
        """
        matched: list[dict] = []
        idx = 0
        for ev in events:
            if ev["event_type"] == needle[idx]:
                detail_parsed: dict | str = {}
                try:
                    raw = ev.get("detail") or ""
                    if isinstance(raw, str) and raw.startswith("{"):
                        detail_parsed = json.loads(raw)
                    else:
                        detail_parsed = raw
                except Exception:
                    detail_parsed = ev.get("detail", "")
                matched.append({
                    "event_type": ev["event_type"],
                    "timestamp":  ev["timestamp"],
                    "pid":        ev.get("pid", 0),
                    "detail":     detail_parsed,
                })
                idx += 1
                if idx == len(needle):
                    break
        return matched

    def _persist(self, f: dict):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
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
                conn.execute(
                    "INSERT INTO chain_alerts (chain_name,mitre,severity,description,window_start,timestamp) VALUES (?,?,?,?,?,?)",
                    (f["chain_name"], f["mitre"], f["severity"], f["description"], f["window_start"], now),
                )
        except Exception:
            pass  # Non-critical: operation continues regardless

    def _print_alert(self, f: dict):
        icon = _SEVERITY_ICON.get(f["severity"], "🔴")
        colors.critical(
            f"\n{'='*65}\n"
            f"  {icon}  ATTACK CHAIN: {f['chain_name']}  [Case CS-{f['alert_id']}]\n"
            f"  Severity : {f['severity']}\n"
            f"  MITRE    : {f['mitre']}\n"
            f"  Details  : {f['description']}\n"
            f"  Window   : {f['window_start']} → now\n"
            f"{'='*65}"
        )

    # ── webhook ──────────────────────────────────────────────────────────────

    def _fire_webhook(self, f: dict):
        """
        Builds and dispatches a rich SOC L1 alert to Discord / Slack / Teams.

        Discord receives a fully-structured embed with colour, inline fields,
        a clickable MITRE ATT&CK link, a per-event breakdown table, and a
        chain-specific L1 triage checklist.

        Slack legacy and Teams receive the plain-text fallback in the
        top-level "text" key — same data, no markdown formatting.

        Security: SSRF protection mirrors utils.send_webhook_alert (HTTPS-only,
        private/loopback ranges blocked).
        """
        # Extract fields first — severity must be available for routing logic below
        severity    = f["severity"]
        chain_name  = f["chain_name"]
        alert_id    = f["alert_id"]
        mitre       = f["mitre"]
        mitre_url   = f.get("mitre_url", "")
        description = f["description"]
        window      = f["window_start"]
        ev_list     = f.get("matched_events", [])
        now_str     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        # ── Routing — dual-fire: severity channel + chains archive ──────────
        if severity == "CRITICAL":
            severity_target = self._webhooks.get("webhook_critical") or self._webhook_url
        elif severity == "HIGH":
            severity_target = self._webhooks.get("webhook_high") or self._webhook_url
        else:
            severity_target = self._webhook_url

        chains_target = self._webhooks.get("webhook_chains", "")

        targets: list[str] = []
        for url in (severity_target, chains_target):
            if url and url.startswith("https://") and url not in targets:
                targets.append(url)

        if not targets:
            return

        # ── SSRF guard (applied per target) ─────────────────────────────────
        _BLOCKED = (
            "localhost", "127.", "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "169.254.", "0.0.0.0",
        )

        def _ssrf_safe(url: str) -> bool:
            try:
                host = urllib.parse.urlparse(url).hostname or ""
                if host in {"localhost", "::1", "[::1]"} or any(host.startswith(p) for p in _BLOCKED):
                    print(f"[-] Chain webhook rejected: private/loopback address ({host}).")
                    return False
                return True
            except Exception:
                print("[-] Chain webhook rejected: URL parsing failed.")
                return False

        targets = [u for u in targets if _ssrf_safe(u)]
        if not targets:
            return

        icon    = _SEVERITY_ICON.get(severity, "🔴")
        color   = _SEVERITY_COLOR.get(severity, 16711680)
        actions = _L1_ACTIONS.get(chain_name, _DEFAULT_L1_ACTIONS)

        # ── Event breakdown block ────────────────────────────────────────────
        event_lines: list[str] = []
        for i, ev in enumerate(ev_list, 1):
            pid    = ev.get("pid") or "N/A"
            ts     = ev.get("timestamp", "")
            detail = ev.get("detail", "")
            if isinstance(detail, dict):
                detail = "  ·  ".join(f"{k}: {v}" for k, v in detail.items())
            detail_str = str(detail)[:180].strip() if detail else "—"
            event_lines.append(
                f"`{i}.` **{ev['event_type']}**  —  PID `{pid}`  @  `{ts}`\n"
                f"    ↳ {detail_str}"
            )
        event_block = "\n".join(event_lines) if event_lines else "_(event detail unavailable)_"

        # ── L1 triage checklist ──────────────────────────────────────────────
        action_block = "\n".join(f"`{i}.` {a}" for i, a in enumerate(actions, 1))

        # ── MITRE field (clickable in Discord) ───────────────────────────────
        mitre_field = f"[{mitre}]({mitre_url})" if mitre_url else mitre

        # ── Discord embed ────────────────────────────────────────────────────
        embed = {
            "title":       f"{icon}  ATTACK CHAIN DETECTED — {severity}",
            "description": f"**{chain_name}**\n{description}",
            "color":       color,
            "fields": [
                {
                    "name":   "🆔  Case Reference",
                    "value":  f"`CS-{alert_id}`",
                    "inline": True,
                },
                {
                    "name":   "⚠️  Severity",
                    "value":  f"`{severity}`",
                    "inline": True,
                },
                {
                    "name":   "🗺️  MITRE ATT&CK",
                    "value":  mitre_field,
                    "inline": True,
                },
                {
                    "name":   "🕐  Detection Window",
                    "value":  f"`{window}` → `{now_str}`",
                    "inline": False,
                },
                {
                    "name":   f"📋  Event Chain  ({len(ev_list)} event{'s' if len(ev_list) != 1 else ''} matched)",
                    "value":  event_block[:1020],
                    "inline": False,
                },
                {
                    "name":   "🔍  L1 Triage — Immediate Actions",
                    "value":  action_block[:1020],
                    "inline": False,
                },
            ],
            "footer": {
                "text": (
                    f"CyberSentinel EDR  •  {now_str}"
                    f"  •  Correlation window: {WINDOW_MINUTES} min"
                )
            },
        }

        # ── Plain-text fallback (Slack legacy / Teams) ───────────────────────
        plain_actions = "\n".join(f"{i}. {a}" for i, a in enumerate(actions, 1))
        plain_events  = "\n".join(
            f"[{ev['event_type']}] PID={ev.get('pid','?')} @ {ev.get('timestamp','')}"
            for ev in ev_list
        )
        plain = (
            f"{icon} ATTACK CHAIN DETECTED — {severity}\n"
            f"Case: CS-{alert_id}  |  {chain_name}\n"
            f"MITRE: {mitre}\n"
            f"{description}\n\n"
            f"Detection Window: {window} → {now_str}\n\n"
            f"Events:\n{plain_events}\n\n"
            f"L1 Actions:\n{plain_actions}"
        )

        payload = {
            "content": f"{icon} **ATTACK CHAIN — {severity}**  |  Case `CS-{alert_id}`  |  {chain_name}",
            "embeds":  [embed],
            "text":    plain,
        }

        for _url in targets:
            try:
                resp = requests.post(_url, json=payload, timeout=5)
                if resp.status_code not in (200, 204):
                    print(f"[-] Chain webhook: unexpected HTTP {resp.status_code} ({_url})")
            except requests.exceptions.ConnectionError:
                print(f"[-] Chain webhook: connection refused ({_url})")
            except requests.exceptions.Timeout:
                print(f"[-] Chain webhook: timed out ({_url})")
            except Exception as exc:
                print(f"[-] Chain webhook error: {exc}")

    def display_chain_alerts(self, limit: int = 20):
        """CLI display of recent chain alerts."""
        try:
            with sqlite3.connect(utils.DB_FILE) as conn:
                rows = conn.execute(
                    "SELECT chain_name,mitre,severity,description,window_start,timestamp "
                    "FROM chain_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        except Exception:
            rows = []

        if not rows:
            print("[*] No attack chains detected yet.")
            return

        print(f"\n{'='*100}")
        print(f"  {'Timestamp':<20}  {'Severity':<10}  {'Chain':<35}  MITRE")
        print(f"{'─'*100}")
        for r in rows:
            chain_name, mitre, severity, _, _, ts = r
            sev = f"\033[91m{severity}\033[0m" if severity == "CRITICAL" else f"\033[93m{severity}\033[0m"
            print(f"  {ts:<20}  {sev:<10}  {chain_name:<35}  {mitre}")
        print(f"{'='*100}")

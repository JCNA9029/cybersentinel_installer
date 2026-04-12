# CyberSentinel — Test Suite README

This folder contains manual simulation and unit-style tests for validating
CyberSentinel's detection modules. Each test targets a specific threat detection
layer and can be run independently from the project root.

---

## Prerequisites

- CyberSentinel is installed and its Python environment is active.
- For tests that require the **daemon** (marked below), run `CyberSentinel.py` or
  start monitoring from the GUI before executing the test.
- For `test_rwx_injection.py`, run the script as **Administrator**.

---

## Test Files

### `test_attack_chains.py` — Attack Chain Correlation Simulator

Simulates multi-stage attack sequences by directly writing synthetic events into
the `event_timeline` SQLite database. The `ChainCorrelator` then matches these
events against 6 built-in chain definitions (CRITICAL/HIGH severity) without
needing real network connections, kernel drivers, or live malware.

**What it tests:** That the chain correlation engine correctly links related events
(e.g. a BYOVD driver load followed by a C2 connection) and raises the right
MITRE-tagged alert.

**Safe:** Only writes rows to the SQLite DB. No processes are spawned, no network
connections are made.

```
python test_attack_chains.py              # inject all 6 chains
python test_attack_chains.py --chain 3   # inject a specific chain by ID
python test_attack_chains.py --list      # show all available chains
```

After running, click **Run Correlation Sweep** in the GUI or wait for the next
auto-sweep. Each chain fires at most once per 60-second deduplication window.

---

### `test_feodo_c2.py` — Feodo Tracker C2 IP Blocklist Detection

Validates that `FeodoMonitor.check_ip()` correctly matches known botnet C2 IPs
from the locally cached `intel/feodo_blocklist.json` (sourced from abuse.ch).

**What it tests:**
- **Sub-test A** — Real C2 IPs from the feed must trigger a match (PASS = detected).
- **Sub-test B** — Benign IPs (Google DNS, Cloudflare, localhost) must not trigger
  a false positive.

**Safe:** Pure in-memory set lookup. No network connections are made.

```
python test_feodo_c2.py
```

If Sub-test A fails, the local feed may be stale — run **Intel Update** from the
GUI to refresh `intel/feodo_blocklist.json` and re-run.

---

### `test_ja3_fingerprint.py` — JA3 TLS Fingerprint Blocklist Detection

Validates that `Ja3Monitor.check_fingerprint()` correctly identifies known-malicious
TLS client fingerprints from `intel/ja3_blocklist.csv` (abuse.ch SSLBL feed).

**What it tests:**
- **Sub-test A** — Known-malicious JA3 hashes (Dridex, TrickBot, Adware) must match.
- **Sub-test B** — Legitimate browser fingerprints (Firefox, synthetic hashes) must
  not match.

**Safe:** Pure in-memory lookup. No packet capture or network traffic is generated.

```
python test_ja3_fingerprint.py
```

> Note: Live packet sniffing via `Ja3Monitor` requires scapy + Npcap. This test
> only exercises the in-memory check path, so Npcap is not required.

---

### `test-ja3.py` — Quick JA3 Blocklist Spot Check

A minimal, standalone script that checks three hardcoded JA3 hashes (TrickBot,
Dridex, and a benign hash) against `Ja3Monitor`. Used for fast sanity-checking
after changes to the blocklist or `c2_fingerprint.py`.

```
python test-ja3.py
```

---

### `test_lolbas_feed.py` — LOLBAS Feed & Pattern Database Coverage

Tests both detection layers for Living-off-the-Land Binary abuse:

- **Part A — `LolbasDetector`** (`intel/lolbas.json`): Verifies Layer 4 fuzzy token
  matching against binaries that are in the live LOLBAS feed but not in the built-in
  pattern list (e.g. `AddinUtil.exe`, `CertReq.exe`, `Bash.exe`).
- **Part B — `LolbinDetector`** (`data/lolbas_patterns.json`): Verifies that the
  static pattern file correctly flags known-abused built-ins (`certutil`, `mshta`,
  `regsvr32`, `bitsadmin`, `wmic`) and does NOT flag a benign process (`svchost.exe`).

**Safe:** All checks are pure in-memory lookups. No processes are spawned.

```
python test_lolbas_feed.py
```

---

### `test_lolbin_abuse.py` — Live LOLBin Process Spawning

Actually spawns real Windows binaries to verify the daemon's WMI/ETW process
monitor detects them. Each binary is kept alive long enough for WMI to read
its `CommandLine` from the process PEB before it exits.

| Binary | Technique | How it stays alive |
|---|---|---|
| `certutil.exe` | T1105 — File download cradle | Network attempt takes ~200–500ms |
| `mshta.exe` | T1218.005 — HTA execution | Writes a `.hta` file with `WScript.Sleep 3000` |
| `cmd.exe` | T1059.003 — Chained commands | `ping -n 3` loop keeps it alive ~2s |

**Requires:** CyberSentinel daemon running. Check the daemon terminal or the
**Fileless / AMSI Alerts** page in the GUI for `[LOLBIN ALERT]` / `[LOLBAS ALERT]`.

```
python test_lolbin_abuse.py
```

---

### `test_rwx_injection.py` — Cross-Process RWX Memory Injection

Opens a handle to a running `notepad.exe` process and allocates an anonymous
RWX (Read-Write-Execute) memory region inside it using `VirtualAllocEx`. This
replicates the exact technique used by Cobalt Strike and Meterpreter to stage
shellcode — an anonymous RWX region in a non-JIT process is a high-confidence
indicator of injection.

**What it tests:** That CyberSentinel's `VirtualQueryEx`-based memory scanner
detects the RWX region within its 30-second scan interval and raises a
`[HIGH CONFIDENCE]` alert in the daemon.

**Requires:**
1. `notepad.exe` must be running before you launch the test.
2. The script must be run **as Administrator**.
3. CyberSentinel daemon must be running.

The script holds the RWX region open for 90 seconds then frees it cleanly.

```
# Start notepad.exe first, then:
python test_rwx_injection.py
```

---

### `test_webhook_gui.py` — Webhook Severity Routing

Verifies that CyberSentinel's `route_webhook_alert()` function sends alerts to
the correct webhook channel based on severity and whether the alert comes from
an attack chain.

**What it tests (8 sub-tests):**

| Test | Input | Expected Channel |
|---|---|---|
| 1 | Routing logic (dry run) | Validates CRITICAL/HIGH/MEDIUM/LOW/chain routing |
| 2 | Live CRITICAL alert | `webhook_critical` |
| 3 | Live HIGH alert | `webhook_high` |
| 4 | Live MEDIUM alert | `webhook_url` (fallback) |
| 5 | Attack chain (CRITICAL) | `webhook_chains` |
| 6 | Feodo C2 match (CRITICAL) | `webhook_critical` |
| 7 | DGA burst (HIGH) | `webhook_high` |
| 8 | Fallback (only `webhook_url` set) | All land in fallback |

**Setup:** Fill in your real webhook URLs at the top of the file before running:

```python
WEBHOOKS = {
    "webhook_url":      "YOUR-WEBHOOK-URL",
    "webhook_critical": "YOUR-CRITICAL-WEBHOOK-URL",
    "webhook_high":     "YOUR-HIGH-WEBHOOK-URL",
    "webhook_chains":   "YOUR-CHAINS-WEBHOOK-URL",
}
```

```
python test_webhook_gui.py
```

Live delivery tests (2–8) will show `❌ Failed (expected if URL is mock)` if
placeholder URLs are left in place — the routing logic tests (Test 1) still pass.

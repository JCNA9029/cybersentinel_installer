<div align="center">

# 🛡️ CyberSentinel v1 — Source Reference

**Multi-Tiered Endpoint Detection & Response (EDR) Framework**

*Python-native · Offline-capable · AI-assisted · Research-grade*

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-informational?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Entry Points](#entry-points)
- [Detection Architecture](#detection-architecture)
- [Novel Contributions](#novel-contributions)
- [Module Reference](#module-reference)
- [Data & Intel Feeds](#data--intel-feeds)
- [Configuration](#configuration)
- [Database Schema](#database-schema)
- [Exclusions](#exclusions)
- [SIEM Export](#siem-export)
- [Evaluation Harness](#evaluation-harness)
- [Requirements](#requirements)
- [File Tree](#file-tree)

---

## Overview

The `src/` directory contains the entire CyberSentinel application — a modular, multi-tiered EDR framework built for under-resourced SOC teams. It chains cloud reputation scanning, offline machine learning, a locally-served LLM, and four original research contributions into a single deployable pipeline.

The stack comprises five distinct interfaces sharing one detection backend:

| Interface | Entry point | Description |
|-----------|-------------|-------------|
| CLI console | `CyberSentinel.py` | Full interactive 16-item menu |
| PyQt6 desktop GUI | `gui.py` | 15-page responsive GUI with threaded workers |
| SOC web dashboard | `dashboard.py` | Flask dashboard at `http://127.0.0.1:5000` |
| Headless daemon | `CyberSentinel.py --daemon PATH` | WMI + watchdog folder monitor |
| Evaluation harness | `eval_harness.py` | Quantitative benchmarking pipeline |

All interfaces import from `modules/` — there is no duplicated logic.

---

## Entry Points

### CLI — `CyberSentinel.py`

The primary interface. Run from a terminal with administrator privileges:

```
python CyberSentinel.py
```

The 16-item menu is organized into four bands:

**Core Scanning**
- `1` — Scan local file or directory (batch-scans `.exe`, `.dll`, `.sys`, etc.)
- `2` — Scan hash / IP / URL / IoC batch `.txt` file
- `3` — Analyze active memory via Live EDR (process path resolver)

**Detectors**
- `4` — LoLBin abuse checker (process name + command-line)
- `5` — BYOVD vulnerable driver scan (System32\drivers)
- `6` — Attack chain correlation alerts
- `7` — Baseline environment manager (learn/stop/stats)
- `8` — Fileless / AMSI alert history

**Advanced Detectors**
- `9` — BYOVD real-time kernel driver monitor
- `10` — AMSI hook: script file scan or PID memory scan

**Management**
- `11` — Network containment control (isolate / restore)
- `12` — Update all threat intelligence feeds
- `13` — Configure API keys, webhook URL, LLM model
- `14` — View threat cache (SQLite-backed results)
- `15` — View analyst feedback history
- `16` — Generate session report and exit

**CLI flags:**

| Flag | Purpose |
|------|---------|
| `--daemon PATH` | Headless daemon monitoring a folder |
| `--dashboard` | Launch Flask SOC dashboard |
| `--evaluate` | Launch evaluation harness |
| `--update-intel` | Pull all four threat intel feeds and exit |
| `--sync URL` | Pull enterprise threat hashes via HTTPS |

### GUI — `gui.py`

```
python gui.py
```

A full PyQt6 desktop application (~5,600 lines). Architecture:

- Left sidebar navigation across 15 pages
- All scan operations run in `QThread` workers — the UI never blocks
- `ConsoleWidget` strips ANSI escape codes and applies color-coded formatting
- GUI callback system replaces CLI `input()` prompts with Qt dialogs (quarantine authorization, network isolation confirmation, AI report display, engine selection)
- `_run_on_main_signal` provides a thread-safe bridge for dialogs spawned from worker threads

**Pages:** Dashboard, Scan File, Scan Hash/IoC, Live EDR, LoLBin Abuse, BYOVD Drivers, Attack Chains, Baseline, Fileless/AMSI, Network, Intel Feeds, Settings, Evaluation, Analyst Feedback, Adaptive Learning.

### SOC Dashboard — `dashboard.py`

```
python dashboard.py
# or
python CyberSentinel.py --dashboard
```

A single-file Flask app that serves a self-contained HTML dashboard at `http://127.0.0.1:5000`. Reads exclusively from `threat_cache.db` — always resolves the DB path relative to `dashboard.py` so it uses the same database as the CLI/GUI regardless of working directory. Provides 7 tabs with live statistics and auto-refresh.

### Daemon — `--daemon PATH`

```
python CyberSentinel.py --daemon "C:\Watch\Folder"
```

Seven concurrent threads:

| Thread | Role |
|--------|------|
| 1 (watchdog observer) | Intercepts new file drops matching watched extensions |
| 2 (WMI hook) | Fires on every new process/driver event — runs LoLBin + BYOVD + baseline checks |
| 3 (ETW/Event 4688) | Process-creation monitor via Windows Security Event Log |
| 4 (Feodo monitor) | Polls active connections vs C2 IP blocklist |
| 5 (JA3 sniffer) | Passive TLS fingerprint capture (requires Npcap + Scapy) |
| 6 (AMSI ScriptBlock) | Event ID 4104 PowerShell ScriptBlock log monitor |
| 7 (chain correlator) | Sweeps event timeline for completed attack chains every 60 s |

Watched extensions: `.exe .dll .sys .apk .elf .pdf .bat .ps1 .vbs .hta`

---

## Detection Architecture

Every file or process event is routed through the following tier stack, implemented in `modules/analysis_manager.py`:

```
Input: File path / Hash / IP / URL / Process
          │
┌─────────▼────────────────────────────────────────────────┐
│  Tier 0      Allowlist / exclusion check                  │
│              (exclusions.txt + JIT exclusions)            │
├──────────────────────────────────────────────────────────-┤
│  Tier 0.5    SQLite cache                                 │
│              Instant repeat-detection — no re-scan        │
├───────────────────────────────────────────────────────────┤
│  Tier 1      Cloud Consensus — concurrent ThreadPoolExec  │
│              VirusTotal v3 · AlienVault OTX ·             │
│              MetaDefender · MalwareBazaar                 │
│              Verdict: ≥3 engines → MALICIOUS              │
├───────────────────────────────────────────────────────────┤
│  Tier 2      Offline LightGBM ML classifier               │
│              EMBER2024 thrember — 2381–2568 PE features   │
│              Threshold θ = 0.60  (0.00% FPR on LoLBins)  │
│              100 MB hard size limit (99.2% coverage)      │
│              + IAT high-risk API call parser              │
├───────────────────────────────────────────────────────────┤
│  Tier 3      Local Ollama LLM (default: deepseek-r1:8b)   │
│              Structured triage report:                    │
│               • MITRE ATT&CK v14+ technique mapping       │
│               • Windows API behavioral chaining           │
│               • Forensic impact assessment                │
│               • Auto-generated YARA rule                  │
├───────────────────────────────────────────────────────────┤
│  Tier 4      Containment                                  │
│              • Fernet AES-128 encrypted quarantine        │
│              • Windows Firewall host isolation            │
└───────────────────────────────────────────────────────────┘
          │
 ── Novel Intelligence Layer ────────────────────────────────
 NC-1  Adaptive Learning Engine    (label-poison-safe)
 NC-2  SHAP Explainability         (real-time per-scan)
 NC-3  Dynamic Risk Scoring        (6-signal composite)
 NC-4  Page-Hinkley Drift Detector (closed retraining loop)
```

### MITRE ATT&CK Technique Weights

`analysis_manager.py` maintains a weighted technique table used by the Live Dynamic Severity Score (`calculate_live_dss()`). The score is normalized to a 0–10 scale with a threshold of 25 representing a "full kill chain."

High-weight techniques (weight 9–10): T1486 (Ransomware), T1485 (Data Destruction), T1003 (Credential Dumping), T1055.012 (Process Hollowing), T1055 (Process Injection), T1078 (Valid Accounts).

A masquerading penalty (+7.5 raw points) applies when a binary uses a known system process name (e.g. `svchost.exe`) but does not reside in `System32`.

### Cloud API Rate Limiting

Each cloud API wrapper uses a token-bucket rate limiter to respect free-tier quotas without exhausting daily limits during batch scans:

| Service | Rate |
|---------|------|
| VirusTotal | 4 req/min |
| AlienVault OTX | 10 req/min |
| MetaDefender | 10 req/min |
| MalwareBazaar | 20 req/min |

All requests are hard-capped at a 5-second timeout. IP and URL lookups are routed to VirusTotal and OTX only — MetaDefender and MalwareBazaar do not support those indicator types.

---

## Novel Contributions

### NC-1 — Adaptive Learning with Label Poisoning Protection (`adaptive_learner.py`)

Incremental LightGBM retraining driven by analyst feedback, protected by a five-stage validation pipeline that prevents poisoned corrections from corrupting the model.

**Correction lifecycle:**

```
Analyst flags FP/FN
      │
   PENDING_REVIEW  ← automated validation runs here
      │
   (passes all checks)
      │
   PENDING  ← eligible for retraining
      │
   TRAINED  ← included in a retraining session
```

**Automated validation checks (run on every submission):**

1. **Self-contradiction check** — rejects logically impossible labels (e.g., FP on a SAFE verdict)
2. **Cross-source conflict** — flags when analyst label contradicts the cached cloud/ML verdict
3. **Duplicate conflict** — detects the same SHA-256 being corrected with contradictory labels across sessions

**Additional safeguards:**

- **Revocation** — any `PENDING` or `PENDING_REVIEW` correction can be revoked before a retraining session; `TRAINED` corrections trigger a model rollback to a pre-session backup snapshot
- **Conflict queue** — `CONFLICTED` corrections are held for manual analyst approval in the GUI's Adaptive Learning page
- **Anchor samples** — confirmed true-positive scans are registered as anchor samples with a cross-validation guard to prevent imbalance-driven false approval
- **Auto-retrain threshold** — retraining fires automatically when 5 validated corrections accumulate (configurable via `AUTO_RETRAIN_THRESHOLD`)

**Hyperparameters:** `learning_rate=0.05`, `n_trees=15`, `max_depth=4`.

### NC-2 — Real-Time SHAP Explainability (`explainability.py`)

SHAP `TreeExplainer` runs after every Tier 2 verdict, producing a ranked list of the top-N PE feature attributions using Shapley values (cooperative game theory).

Feature labels are built dynamically from EMBER2024 group definitions and scale with whatever `thrember` version is installed (2381 or 2568 dimensions). Groups covered: Byte Histogram (256 features), Byte Entropy Histogram (256 features), String Features (~104), General File Info, Header Info, Section Info, Import/Export Tables, and DataDirectories (extended builds only).

Results are persisted to SQLite and surfaced inline in the GUI's scan output and on the dedicated Adaptive Learning page.

### NC-3 — Dynamic Risk Scoring (`risk_scorer.py`)

Computes a composite Dynamic Risk Score (DRS) from 0.0–1.0 that replaces the raw ML probability for display and prioritization. The DRS answers: *"How urgent is this alert right now, on this machine, at this moment?"* It does not change the binary SAFE/MALICIOUS verdict.

**Six signals and their weights:**

| Signal | Weight | Rationale |
|--------|--------|-----------|
| ML/cloud verdict probability | 0.45 | Dominant signal — base maliciousness estimate |
| Temporal anomaly | 0.10 | Off-hours and weekend scans score higher |
| Active threat count | 0.15 | Concurrent detections amplify individual scores |
| Attack chain presence | 0.15 | Chain-in-progress makes every new event more urgent |
| Network activity | 0.10 | Active outbound connections from new process |
| Baseline deviation | 0.05 | Unknown process not in host behavioral profile |

**Temporal risk profile:** Business hours (Mon–Fri, 08:00–18:00) return a temporal score of 0.1. Nights and weekends return up to 0.8.

**DRS thresholds:** `< 0.35` → LOW · `< 0.55` → MEDIUM · `< 0.75` → HIGH · `≥ 0.75` → CRITICAL.

### NC-4 — Page-Hinkley Concept Drift Detector (`drift_detector.py`)

Statistically monitors the ML confidence score distribution over time using the Page-Hinkley online change detection algorithm (Page, 1954). Detects when the model's average confidence on `MALICIOUS` verdicts drops significantly compared to a reference window — the hallmark of concept drift caused by evolving malware that the current model no longer confidently recognizes.

**Parameters:**

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `MIN_REFERENCE_WINDOW` | 30 scans | Minimum history before detection activates |
| `DETECTION_WINDOW` | 20 scans | Rolling window compared to reference |
| `DRIFT_THRESHOLD` | 0.15 | 15% drop in mean confidence triggers alert |
| `PH_DELTA` | 0.005 | Page-Hinkley sensitivity |
| `PH_LAMBDA` | 50.0 | Page-Hinkley detection threshold |

Drift alerts are stored in `drift_alerts` (SQLite) and surfaced on the Adaptive Learning GUI page with a recommendation to retrain. The drift detector integrates with the Adaptive Learning Engine to form a **closed detection-to-retraining loop** — the first such loop in a deployable open-source EDR.

---

## Module Reference

### `modules/analysis_manager.py` — Pipeline Orchestrator (1,592 lines)

Central `ScannerLogic` class. Owns the full scan pipeline from input validation through containment. Key responsibilities:

- Routes inputs through all four tiers concurrently where applicable
- Manages GUI callback registration for thread-safe dialog prompting from `QThread` workers
- Fires SOC webhook alerts on every confirmed malicious verdict
- Coordinates the analyst feedback and adaptive learning pipeline post-scan
- Computes the Live DSS (`calculate_live_dss()`) from the IAT API call list

### `modules/scanner_api.py` — Cloud API Wrappers (373 lines)

Four independently rate-limited API client classes:

- `VirusTotalAPI` — v3 Files endpoint; consensus threshold ≥ 3 engines; also handles IP/URL
- `AlienVaultAPI` — OTX Indicators endpoint; also handles IP/URL
- `MetaDefenderAPI` — hash lookup only
- `MalwareBazaarAPI` — hash lookup only

All expose a standardized `get_report(hash)` returning `{"verdict": "MALICIOUS"|"SAFE", "engines_detected": int}` or `None`. Requests run concurrently via `ThreadPoolExecutor` in `analysis_manager.py`.

### `modules/ml_engine.py` — Offline ML Classifier (320 lines)

`LocalScanner` class. Extracts 2,381–2,568 dimensional PE feature vectors via `thrember` (EMBER2024) and classifies via `LightGBM` (`CyberSentinel_v2.model`).

- Hard skips files > 100 MB and non-PE files (no MZ magic bytes)
- Verifies model file SHA-256 integrity before loading to detect tampering
- Reads the adaptive learner reload flag before each scan to pick up newly retrained models without restarting
- Also parses the PE Import Address Table for high-risk Windows API calls to feed `calculate_live_dss()`

### `modules/adaptive_learner.py` — Self-Correcting ML Engine (1,508 lines)

`AdaptiveLearner` singleton (`get_learner()`). Implements NC-1 (described above). Manages the correction queue SQLite table, the five-stage validation pipeline, incremental LightGBM retraining, model backup/rollback, and the audit JSONL log (`models/learning_audit.jsonl`).

### `modules/explainability.py` — SHAP Explainability (480 lines)

`SHAPExplainer` singleton (`get_explainer()`). Implements NC-2 (described above). Degrades gracefully when `shap` is not installed — skips explanation without breaking the scan pipeline.

### `modules/risk_scorer.py` — Dynamic Risk Scoring (475 lines)

`DynamicRiskScorer` singleton (`get_risk_scorer()`). Implements NC-3 (described above). Reads active threat count and chain state directly from SQLite to compute a contextually-aware score at the time of each alert.

### `modules/drift_detector.py` — Concept Drift Detector (424 lines)

`DriftDetector` singleton (`get_drift_detector()`). Implements NC-4 (described above). Called by `analysis_manager.py` after every ML verdict. Stores drift alerts to `drift_alerts` table.

### `modules/lolbas_detector.py` — LoLBin Abuse Detector (589 lines)

Five-layer detection engine for Living-off-the-Land Binary abuse. Used by both the CLI/GUI (manual check) and the daemon (real-time WMI hook).

**Layers:**

1. Command-line normalization — strips caret obfuscation (`^`), environment variable substitution, and whitespace tricks before matching
2. Path normalization — extracts binary name from full path so copies to non-standard directories are caught
3. Pattern matching — 22 built-in high-confidence regex patterns + live LOLBAS feed (loaded via `intel_updater`)
4. Shannon entropy scoring — flags Base64 and high-entropy argument strings above threshold 4.2
5. Parent process context — process lineage included in findings for kill-chain context

Data source: LOLBAS Project (`https://lolbas-project.github.io/`).

**Built-in patterns cover:** certutil, mshta, regsvr32, rundll32, msbuild, installutil, ieexec, cmstp, odbcconf, mavinject (execution/download), schtasks, reg, at (persistence), wmic, bitsadmin (lateral movement), forfiles, pcalua (defense evasion), procdump, ntdsutil (credential access), and PowerShell stealth flags.

### `modules/lolbin_detector.py` — LOLBin Real-Time Monitor (192 lines)

Lightweight daemon-facing companion to `lolbas_detector.py`. Receives process events from the WMI hook and routes them through the LOLBAS detection engine in real time.

### `modules/byovd_detector.py` — BYOVD Vulnerable Driver Detector (375 lines)

Unified `ByovdDetector` class combining live feed lookup, static fallback, and real-time WMI monitoring.

**Detection strategy:**

1. Live LOLDrivers feed lookup via SHA-256 (O(1) hash set)
2. Filename fallback for unsigned/modified drivers
3. Static local `data/loldrivers.json` if live feed is unavailable
4. Real-time WMI background monitor (polls `Win32_SystemDriver` every 10 s)
5. Webhook alert on detection; SQLite persistence for dashboard/audit

Data source: LOLDrivers Project (`https://www.loldrivers.io/`).

### `modules/c2_fingerprint.py` — C2 Traffic Fingerprinting (425 lines)

Three passive detection mechanisms — no traffic decryption required:

- **`FeodoMonitor`** — polls active `psutil` connections and cross-references remote IPs against the Feodo Tracker abuse.ch botnet C2 blocklist
- **`DgaMonitor`** — Shannon entropy analysis (`_shannon_entropy()`) on DNS queries; flags domains with entropy > 3.5 AND label length > 12 OR consonant/vowel ratio > 4. Extensive CDN/cloud whitelist (Google, Microsoft, AWS, Akamai, Cloudflare, etc.) reduces false positives
- **`Ja3Monitor`** — passive TLS ClientHello capture via Scapy + Npcap; matches JA3 fingerprint hashes against abuse.ch SSLBL; requires Npcap installed

All three monitors run as background threads started in `CyberSentinelUI.__init__()`.

### `modules/chain_correlator.py` — Attack Chain Correlator (516 lines)

Reads events from the shared `event_timeline` SQLite table (populated by all detectors) and matches their sequence against 7 predefined multi-step attack chain definitions within a 10-minute correlation window.

**Predefined chains:**

| Chain | Stages |
|-------|--------|
| Process Injection → C2 | Memory injection + outbound C2 connection |
| BYOVD → EDR Kill | Vulnerable driver load + EDR process termination |
| DGA Beacon → C2 Resolve | DGA domain query + C2 IP connection |
| Credential Dump Chain | LSASS access + credential API calls |
| Fileless Execution → C2 | PowerShell obfuscation + C2 connection |
| Driver + DGA Dual-Stage | Vulnerable driver + DGA (sophisticated APT indicator) |
| Persistence Install | Registry run key + startup folder write |

When a chain fires, a rich webhook embed (Discord/Slack/Teams compatible) is sent with severity color coding, MITRE ATT&CK links, a per-event breakdown, and chain-specific L1 triage steps.

Event retention: 60 minutes in `event_timeline` for the GUI Live Feed.

### `modules/amsi_monitor.py` — PowerShell ScriptBlock Monitor (232 lines)

`AmsiMonitor` class. Reads Windows Event Log Event ID 4104 (PowerShell ScriptBlock logging) and scores each script against 16 obfuscation indicator patterns.

**Patterns include:** Base64-encoded commands (`-enc` flag), inline `FromBase64String`, IEX/Invoke-Expression, PowerSploit modules (Mimikatz, ReflectivePEInjection), Marshal P/Invoke, WebClient download cradles, BITS transfers, `-NoProfile`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, Win32 memory allocation APIs, AMSI bypass strings, temp directory executable drops, character-code construction, and string-replace obfuscation.

Alert threshold: ≥ 2 matched patterns. Falls back gracefully when `pywin32` is unavailable.

### `modules/amsi_hook.py` — Fileless / In-Memory Attack Detector (629 lines)

Two detection classes:

- **`AmsiScanner`** — scans script file content against 20+ regex patterns covering AMSI bypass, credential theft, PowerShell cradles, mshta/WScript/CScript script hosts, and process injection APIs. Each pattern maps to a MITRE ATT&CK technique.
- **`FilelessMonitor`** — scans running process memory via `VirtualQueryEx` (ctypes/Windows API) for anonymous RWX memory regions — a hallmark of in-memory shellcode staging. JIT processes (V8, .NET CLR, JVM) are excluded via `jit_exclusions.txt`.

### `modules/baseline_engine.py` — Behavioral Baseline (255 lines)

`BaselineEngine` class. Per-machine behavioral profiling — not fleet-wide — making it accurate for specialized and air-gapped systems.

**Two modes:**

- **LEARN** — silently records every running process and its network destinations for a configurable window (default 24 h, `CS_BASELINE_HOURS` env var). Writes a behavioral profile to SQLite. Persists across restarts via a flag file.
- **DETECT** — compares new processes against the profile. Unknown binaries receive a `trust_penalty` score fed back to NC-3 (the 5% baseline deviation weight in the DRS).

### `modules/daemon_monitor.py` — Headless Daemon (384 lines)

`start_daemon(path)` spins up all seven monitoring threads (listed above) and a `watchdog` folder observer. On a new file drop, a 2-second sleep absorbs write completion before scanning.

### `modules/quarantine.py` — Encrypted Quarantine (107 lines)

`quarantine_file(file_path)` — read → Fernet AES-128 encrypt → write encrypted blob to `Quarantine/` → delete original only after encrypted copy is verified. The Fernet key is derived from the machine's hardware MAC address via PBKDF2-HMAC-SHA256 (100,000 iterations) — the encrypted file cannot be decrypted on a different machine. `Quarantine/` is marked system+hidden via `attrib`.

### `modules/network_isolation.py` — Windows Firewall Isolation (75 lines)

`isolate_network()` — sets Windows Firewall to `blockinbound,blockoutbound` on all profiles. `restore_network()` — restores to default (`blockinbound,allowoutbound`). Both use `netsh advfirewall` via subprocess with `CREATE_NO_WINDOW` to suppress the terminal flash. Requires Administrator.

### `modules/intel_updater.py` — Threat Intel Feed Manager (236 lines)

Downloads and caches four open-source threat intelligence feeds under `intel/`:

| Feed | Source | File |
|------|--------|------|
| LOLBAS | `lolbas-project.github.io/api/lolbas.json` | `intel/lolbas.json` |
| LOLDrivers | `loldrivers.io/api/drivers.json` | `intel/loldrivers.json` |
| Abuse.ch JA3 | `sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` | `intel/ja3_blocklist.csv` |
| Feodo Tracker | `feodotracker.abuse.ch/downloads/ipblocklist.json` | `intel/feodo_blocklist.json` |

All feeds are validated for minimum size and parseable content before overwriting the cached copy — an empty or error response is rejected. Last-update timestamps are stored in `intel/update_meta.json`. The app runs fully offline after first update.

### `modules/feedback.py` — Analyst Feedback Loop (357 lines)

`prompt_analyst_feedback()` — post-scan review prompt (CLI) or GUI dialog. Options: Confirm (TP) / False Positive / False Negative / Skip.

On False Positive: adds the file to `exclusions.txt` and queues an ML correction in the Adaptive Learning Engine.
On False Negative: queues an ML correction.
On Confirm: registers the file as an anchor sample to anchor-validate future conflicting corrections.

`display_feedback_history()` renders the full correction queue with status and timestamps.

### `modules/utils.py` — Shared Utilities (786 lines)

Five sections:

1. **Hardware-bound Fernet encryption** — AES-128 + HMAC-SHA256 key derived from MAC address via PBKDF2 (100,000 iterations). Used for `config.json` API key storage and quarantine.
2. **Configuration persistence** — `load_config()` / `save_config()` — encrypted read/write of API keys, webhook URL, and LLM model name.
3. **SOC webhook dispatcher** — `fire_webhook()` — Discord/Slack/Teams-compatible JSON payloads. SSRF-protected (only HTTPS URLs accepted).
4. **Network and file utilities** — connectivity check, SHA-256 file hashing.
5. **SQLite database management** — schema initialization, cache read/write, `get_all_cached_results()`.

### `modules/_paths.py` — Central Path Resolver (47 lines)

Resolves the install root in priority order:

1. `HKLM\SOFTWARE\CyberSentinel\InstallDir` (Windows registry — set by installer)
2. `__file__`-relative fallback (source/dev runs)

Exports `INSTALL_DIR`, `MODELS_DIR`, `CONFIG_FILE`, `DB_FILE`. All modules import paths from here instead of computing them independently.

### `modules/colors.py` — Terminal Color Output (76 lines)

Thin wrapper over `colorama`. Functions: `header()`, `success()`, `info()`, `warning()`, `error()`, `critical()`, `verdict_color()`. Used throughout the CLI for consistent coloring.

### `modules/loading.py` — Spinner (41 lines)

`Spinner` class — a simple animated terminal spinner for long-running blocking operations (model loading, API calls).

### `modules/live_edr.py` — Live Process Resolver (57 lines)

`get_target_process_path()` — presents a list of running processes and resolves the selected PID to an executable path for routing through the scan pipeline.

---

## Data & Intel Feeds

```
intel/
  lolbas.json          — LOLBAS Project abuse pattern definitions
  loldrivers.json      — LOLDrivers vulnerable driver database
  ja3_blocklist.csv    — Abuse.ch JA3 TLS fingerprint blocklist
  feodo_blocklist.json — Feodo Tracker C2 IP blocklist
  update_meta.json     — Per-feed last-update timestamps

data/
  lolbas_patterns.json — Compiled local LOLBAS pattern cache
  loldrivers.json      — Static LOLDrivers fallback
  ja3_blocklist.json   — Static JA3 fallback
```

The `intel/` directory holds the live-updated feeds. `data/` holds static bundled fallbacks used if live feeds are unavailable. `intel_updater.py` always prefers the live feed and falls back to `data/` automatically.

---

## Configuration

**File:** `config.json` (at the install root, encrypted)

```json
{
  "api_keys": {
    "virustotal":   "<encrypted>",
    "alienvault":   "<encrypted>",
    "metadefender": "<encrypted>",
    "malwarebazaar": "<encrypted>"
  },
  "webhook_url": "<encrypted>",
  "llm_model": "deepseek-r1:8b"
}
```

All sensitive values are encrypted with the hardware-bound Fernet key — the file cannot be decrypted on a different machine. Edit via `Settings` (menu item 13) or `python CyberSentinel.py` → Configure Settings.

**LLM model:**

The model is hardcoded to `cybersentinel-analyst` — a fine-tuned `Qwen2.5-7B-Instruct` model (~4.5 GB VRAM) registered with Ollama by the installer. It is not user-selectable.

**`config.json` is preserved across reinstalls** — the installer backs it up before overwriting.

---

## Database Schema

All state is stored in `threat_cache.db` (SQLite), resolved via `_paths.py`.

| Table | Contents |
|-------|---------|
| `scan_cache` | SHA-256, filename, verdict, timestamp — Tier 0.5 repeat-detection cache |
| `event_timeline` | All detector events (type, severity, process, timestamp) — shared across all modules for chain correlation and the GUI Live Feed; 60-minute rolling retention |
| `chain_alerts` | Completed attack chain records with chain name, severity, event list, and webhook status |
| `c2_alerts` | Feodo / DGA / JA3 hits |
| `driver_alerts` | BYOVD detections |
| `fileless_alerts` | AMSI / fileless / RWX memory hits |
| `baseline_profiles` | Per-process behavioral profiles (SHA-256, network destinations, seen count) |
| `feedback_queue` | Analyst corrections with status lifecycle (PENDING_REVIEW → PENDING → TRAINED / REVOKED / CONFLICTED) |
| `shap_explanations` | Per-scan top-N feature attribution results |
| `drift_alerts` | Page-Hinkley and mean-drop drift detection records |
| `ml_score_history` | Raw ML confidence scores — input to the drift detector |

The `v2_predictions.db` file is the **evaluation harness** database, separate from `threat_cache.db`, storing benchmark scan results across runs for persistence and re-analysis.

---

## Exclusions

Two exclusion files at the install root:

**`exclusions.txt`** — Process names, paths, or directories to skip entirely. One entry per line. Entries added automatically when an analyst marks a False Positive. Example:

```
# CyberSentinel Enterprise Exclusion List
C:\Program Files\MySafeCompany\
StoreDesktopExtension.exe
```

**`jit_exclusions.txt`** — Process names excluded from **RWX memory scanning only** (FilelessMonitor). Used for JIT runtimes that legitimately allocate anonymous RWX memory (V8, .NET CLR, JVM). Has no effect on file or hash scanning. Example:

```
node.exe
java.exe
dotnet.exe
```

---

## SIEM Export

**File:** `siem_export.py`

Exports detections and telemetry to Splunk (HEC) and/or a JSON Lines file. Runs incrementally — only records newer than the last export are included, making re-runs safe.

**Source types exported:**

| Sourcetype | Tables |
|------------|--------|
| `cybersentinel:detection` | chain_alerts, c2_alerts, driver_alerts, fileless_alerts |
| `cybersentinel:telemetry` | event_timeline (raw behavioral events) |

**Usage:**

```bash
# One-shot file export
python siem_export.py --mode file

# Push to Splunk HEC
python siem_export.py --mode hec --hec-url https://splunk:8088 --hec-token YOUR_TOKEN

# Both simultaneously, reading from siem_config.json
python siem_export.py --mode both

# Continuous mode — push deltas every 30 seconds
python siem_export.py --mode hec --watch 30

# Force full re-export (ignore saved state)
python siem_export.py --mode file --reset
```

State is persisted in `siem_export_state.json`. Configuration can be supplied via `siem_config.json` or CLI flags (CLI flags take precedence).

---

## Evaluation Harness

**File:** `eval_harness.py` (740 lines)

Implements the full quantitative benchmark pipeline.

**Expected sample directory layout:**

```
samples/
  pre2020/
    malware/   ← Pre-2020 malicious PE files
    clean/     ← Pre-2020 benign files
  post2020/
    malware/   ← Post-2020 malicious PE files
    clean/     ← Post-2020 benign files
  stealth/
    malware/   ← UPX-packed malicious PE files (adversarial)
    clean/     ← UPX-packed benign files (optional)
```

**Pipeline steps:**

1. Persistent SQLite score retention (`v2_predictions.db`) — results survive restarts
2. Fault-tolerant execution loop with per-file error logging
3. Temporal stratification (Pre-2020 / Post-2020 subsets)
4. Stealth/UPX adversarial dataset (separate subdirectory)
5. Threshold sweep (θ = 0.40 → 0.80, step 0.05)
6. Confusion matrix per threshold (TP/FP/TN/FN)
7. Metrics: Precision, Recall, F1, FPR, FNR, Accuracy
8. Per-sample raw score log for post-hoc analysis
9. Tier 1 cloud consensus evaluation (optional `--tier1` flag)
10. JSON + TXT forensic report export

```bash
python eval_harness.py
# or
python CyberSentinel.py --evaluate
```

---

## Requirements

**Install:**

```bash
pip install -r requirements.txt
```

**Core dependencies:**

| Package | Purpose |
|---------|---------|
| `requests` | Cloud API calls |
| `psutil` | Live process enumeration and network monitoring |
| `watchdog` | Daemon filesystem observer |
| `cryptography` | Fernet AES-128 encryption |
| `colorama` | Terminal color output |
| `pefile` | Windows PE feature extraction |
| `lightgbm` | Tier 2 ML classifier |
| `numpy` | Feature array processing |
| `scipy` | Required by SHAP TreeExplainer |
| `shap` | NC-2: real-time per-scan feature attribution |
| `ollama` | Tier 3 local LLM interface |
| `flask` | SOC dashboard |
| `PyQt6` | Desktop GUI |
| `tqdm` | Progress display |
| `pandas` | Evaluation harness tabulation |

**Windows-only (install separately):**

```bash
pip install pywin32   # AMSI monitor + WMI daemon hook
pip install wmi       # Tier 0 kernel-bridge process hook
```

**Optional — JA3 TLS fingerprinting:**

Requires [Npcap](https://npcap.com/) installed first, then:

```bash
pip install scapy
```

**EMBER2024 ML feature extraction — not on PyPI:**

```bash
pip install signify==0.7.1
git clone https://github.com/FutureComputing4AI/EMBER2024
cd EMBER2024 && pip install .
```

Required for Tier 2 ML and SHAP. Cloud (Tier 1) and AI (Tier 3) tiers function without it.

---

## File Tree

```
src/
├── CyberSentinel.py            ← CLI entry point (16-item menu)
├── gui.py                      ← PyQt6 desktop GUI (15 pages, 5,602 lines)
├── dashboard.py                ← Flask SOC dashboard
├── eval_harness.py             ← Quantitative benchmark pipeline
├── siem_export.py              ← Splunk HEC / JSONL exporter
├── config.json                 ← Encrypted runtime configuration
├── exclusions.txt              ← Global scan exclusion list
├── jit_exclusions.txt          ← RWX scan JIT runtime exclusions
├── requirements.txt            ← Python dependency manifest
├── LICENSE
│
├── modules/                    ← All detection and utility code
│   ├── __init__.py             ← Package exports
│   ├── _paths.py               ← Central install-directory resolver
│   ├── analysis_manager.py     ← Pipeline orchestrator (all tiers)
│   ├── scanner_api.py          ← Cloud API wrappers (Tier 1)
│   ├── ml_engine.py            ← LightGBM ML classifier (Tier 2)
│   ├── adaptive_learner.py     ← NC-1: self-correcting ML engine
│   ├── explainability.py       ← NC-2: SHAP feature attribution
│   ├── risk_scorer.py          ← NC-3: dynamic risk scoring
│   ├── drift_detector.py       ← NC-4: Page-Hinkley drift detection
│   ├── lolbas_detector.py      ← LoLBin abuse detector (5-layer)
│   ├── lolbin_detector.py      ← Real-time LOLBin process monitor
│   ├── byovd_detector.py       ← BYOVD vulnerable driver detector
│   ├── c2_fingerprint.py       ← Feodo + DGA + JA3 C2 fingerprinting
│   ├── chain_correlator.py     ← Attack chain correlation (7 chains)
│   ├── amsi_monitor.py         ← PowerShell Event ID 4104 monitor
│   ├── amsi_hook.py            ← Script scanner + RWX memory scanner
│   ├── baseline_engine.py      ← Per-machine behavioral profiler
│   ├── daemon_monitor.py       ← Headless daemon (7 threads)
│   ├── quarantine.py           ← Fernet AES-128 encrypted quarantine
│   ├── network_isolation.py    ← Windows Firewall host isolation
│   ├── intel_updater.py        ← Threat intel feed manager (4 feeds)
│   ├── feedback.py             ← Analyst feedback + learning loop
│   ├── live_edr.py             ← Live process path resolver
│   ├── utils.py                ← Shared utilities (encryption, DB, webhooks)
│   ├── colors.py               ← Terminal color output (colorama)
│   └── loading.py              ← Animated spinner
│
├── intel/                      ← Live-updated threat intelligence feeds
│   ├── lolbas.json
│   ├── loldrivers.json
│   ├── ja3_blocklist.csv
│   ├── feodo_blocklist.json
│   └── update_meta.json
│
├── data/                       ← Static bundled feed fallbacks
│   ├── lolbas_patterns.json
│   ├── loldrivers.json
│   └── ja3_blocklist.json
│
├── assets/
│   └── icon.ico
│
└── Analysis Files/             ← Analyst session output directory
```

---

*CyberSentinel v1 — Built as a thesis project. All detection models trained exclusively on publicly available malware behavioral datasets for research and defensive security purposes.*

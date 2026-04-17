# modules/analysis_manager.py

import os
import sys
import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as _requests
import re
from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
from .scanner_api import VirusTotalAPI, AlienVaultAPI, MetaDefenderAPI, MalwareBazaarAPI
from .feedback import prompt_analyst_feedback
from .chain_correlator import ChainCorrelator
from .baseline_engine import BaselineEngine
from . import network_isolation
from . import utils
from . import colors

# ==========================================
# 🧠 CYBERSENTINEL THREAT SCORING ENGINE
# ==========================================

# 1. Master Risk Weights (Copied from your training script)
TECHNIQUE_WEIGHTS = {
    "T1486": 10, "T1485": 10, "T1003": 10, "T1055.012": 10, "T1548.002": 9,
    "T1055": 9,  "T1078": 9,  "T1489": 9,  "T1021": 8,      "T1041": 8,
    "T1020": 8,  "T1574.001": 8, "T1547.001": 8, "T1071": 8, "T1573": 8,
    "T1059": 7,  "T1105": 7,  "T1543": 7,  "T1497": 5,      "T1027": 5,
    "T1112": 4,  "T1140": 4,  "T1119": 4,  "T1082": 2,      "T1083": 2,
    "T1033": 2,  "T1012": 2,  "T1007": 1
}

# 2. Threat Intelligence Mapping
api_context = {
    'NtResumeThread': {'mitre_mapping': 'T1055.012'},
    'CreateProcessInternalW': {'mitre_mapping': 'T1543'},
    'NtTerminateProcess': {'mitre_mapping': 'T1489'},
    'CreateRemoteThread': {'mitre_mapping': 'T1055.002'},
    'NtCreateThreadEx': {'mitre_mapping': 'T1055'},
    'NtAllocateVirtualMemory': {'mitre_mapping': 'T1055'},
    'LdrLoadDll': {'mitre_mapping': 'T1574.001'},
    'NtProtectVirtualMemory': {'mitre_mapping': 'T1055'},
    'WriteProcessMemory': {'mitre_mapping': 'T1055'},
    'RegSetValueExA': {'mitre_mapping': 'T1547.001'},
    'RegCreateKeyExW': {'mitre_mapping': 'T1112'},
    'NtQueryValueKey': {'mitre_mapping': 'T1012'},
    'WSAStartup': {'mitre_mapping': 'T1071'},
    'socket': {'mitre_mapping': 'T1041'},
    'InternetOpenUrlA': {'mitre_mapping': 'T1105'},
    'IsDebuggerPresent': {'mitre_mapping': 'T1497.001'},
    'NtDelayExecution': {'mitre_mapping': 'T1497.003'},
    'NtCreateFile': {'mitre_mapping': 'T1486'},
    'FindFirstFileExW': {'mitre_mapping': 'T1083'},
    'GetSystemWindowsDirectoryW': {'mitre_mapping': 'T1082'},
    'CryptAcquireContextW': {'mitre_mapping': 'T1486'},
    'CryptCreateHash': {'mitre_mapping': 'T1573'},
    # Add your thesis-specific APIs here
    'VirtualAllocEx': {'mitre_mapping': 'T1055'},
    'GetKeyboardState': {'mitre_mapping': 'T1056.001'},
    'SetWindowsHookExA': {'mitre_mapping': 'T1056.001'}
}

def calculate_live_dss(api_list, file_path):
    if not api_list:
        return 0.5

    unique_techs = set()
    for api in api_list:
        if api in api_context:
            mitre_full = api_context[api].get('mitre_mapping', 'Uncategorized')
            if mitre_full != 'Uncategorized':
                # Extract base technique ID (e.g., "T1055")
                base_tech = mitre_full.split(' ')[0]
                unique_techs.add(base_tech)

    # Check if we found anything after the full loop
    if not unique_techs:
        return 1.0 # Suspicious activity, but no mapped techniques

    # Sum weights for all unique techniques found
    raw_score = sum(TECHNIQUE_WEIGHTS.get(tid, 3) for tid in unique_techs)

    # Masquerading Penalty (+1.5 to final score)
    filename = os.path.basename(file_path).lower()
    system_names = ["svchost.exe", "explorer.exe", "dllhost.exe", "services.exe", "lsass.exe", "autoclickers.exe"]
    if filename in system_names and "system32" not in file_path.lower():
        raw_score += 7.5 # (7.5 / 50 * 10 = 1.5 penalty)

    # NORMALIZATION: 25 is the new 'Full Chain' threshold
    normalized_score = (raw_score / 25) * 10
    return min(10.0, round(normalized_score, 1))

class ScannerLogic:
    """Orchestrates the Multi-Tier Pipeline: Cache → Cloud → ML → LLM → Containment."""

    def __init__(self):
        config = utils.load_config()
        self.api_keys      = config.get("api_keys", {})
        self.webhook_url      = config.get("webhook_url", "")
        self.webhook_critical = config.get("webhook_critical", "")
        self.webhook_high     = config.get("webhook_high", "")
        self.webhook_chains   = config.get("webhook_chains", "")
        # Model is hardcoded — CyberSentinel uses its own fine-tuned domain analyst.
        # Do NOT make this configurable; the model is purpose-built for this pipeline.
        self.llm_model = config.get("llm_model", "cybersentinel-analyst")
        self.ml_scanner    = LocalScanner()
        self.session_log: list[str] = []
        self.headless_mode = False
        # Daemon overwrites these references with its shared instances.
        # In CLI mode they still function independently.
        self.correlator    = ChainCorrelator(webhook_url=self.webhook_url, webhooks=self._webhooks())
        self.baseline      = BaselineEngine()
        utils.init_db()
        # unbounded database growth in long-running daemon deployments.
        try:
            utils.prune_old_records(days=90)
        except Exception:
            pass   # Non-critical — startup continues regardless

        # Scenario 3 Fix: Pre-extracted feature cache.
        # Stores compressed feature vectors keyed by sha256, extracted BEFORE
        # quarantine runs so feedback/adaptive-learning has them even after the
        # original file has been moved or encrypted.
        # Entries are removed immediately after the feedback dialog consumes them.
        self._prefetch_features_cache: dict = {}

    # ── LOGGING

    def log_event(self, message: str, print_to_screen: bool = True):
        """Appends a message to the session log and optionally prints it."""
        if print_to_screen:
            try:
                if sys.stdout is not None:
                    print(message)
            except Exception:
                pass
        self.session_log.append(message)

    # ── TIER 1: CONCURRENT CLOUD CONSENSUS

    def _run_tier1_concurrent(self, file_hash: str) -> dict:
        """
        Queries all configured cloud engines CONCURRENTLY using a thread pool.
        Previously sequential (up to 20 s); now completes in the time of the
        slowest single API call (~5 s max).

        Returns a dict with 'verdict', 'context', and 'sources'.
        """
        # Build a dict of {engine_name: callable}
        engine_map = {}
        if self.api_keys.get("malwarebazaar"):
            engine_map["MalwareBazaar"] = lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash)
        if self.api_keys.get("virustotal"):
            engine_map["VirusTotal"] = lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash)
        if self.api_keys.get("alienvault"):
            engine_map["AlienVault"] = lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash)
        if self.api_keys.get("metadefender"):
            engine_map["MetaDefender"] = lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash)

        if not engine_map:
            self.log_event("[!] No API keys configured — Tier 1 skipped.")
            return {"verdict": None, "context": "No APIs configured", "sources": []}

        malicious_sources: list[str] = []
        unknown_sources:  list[str] = []
        # Quorum tracking — populated when VirusTotal returns engines_total
        _vt_detected: int = 0
        _vt_total:    int = 0

        with ThreadPoolExecutor(max_workers=len(engine_map)) as pool:
            futures = {pool.submit(fn): name for name, fn in engine_map.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if result is None:
                        self.log_event(f"    -> {name}: UNKNOWN (No record / API error)")
                        unknown_sources.append(name)
                    elif result.get("verdict") == "MALICIOUS":
                        hits  = result.get("engines_detected", 0)
                        total = result.get("engines_total", 0)
                        label = f"Hits: {hits}" + (f" / {total}" if total else "")
                        colors.critical(f"    -> {name}: MALICIOUS ({label})")
                        self.session_log.append(f"    -> {name}: MALICIOUS ({label})")
                        malicious_sources.append(name)
                        if name == "VirusTotal" and total:
                            _vt_detected, _vt_total = hits, total
                    else:
                        hits  = result.get("engines_detected", 0)
                        total = result.get("engines_total", 0)
                        label = f"Hits: {hits}" + (f" / {total}" if total else "")
                        colors.success(f"    -> {name}: SAFE ({label})")
                        self.session_log.append(f"    -> {name}: SAFE ({label})")
                        if name == "VirusTotal" and total:
                            _vt_detected, _vt_total = hits, total
                except Exception as e:
                    self.log_event(f"    -> {name}: ERROR ({e})")

        # Quorum summary line — only when VirusTotal responded with engine totals
        if _vt_total > 0:
            pct = (_vt_detected / _vt_total) * 100
            consensus = "MALICIOUS" if _vt_detected >= 3 else "SAFE"
            quorum_line = (
                f"[*] QUORUM: {_vt_detected} / {_vt_total} VT engines flagged "
                f"({pct:.1f}%) — {consensus} consensus"
            )
            if _vt_detected >= 3:
                colors.critical(quorum_line)
            else:
                colors.success(quorum_line)
            self.session_log.append(quorum_line)

        if malicious_sources:
            verdict = "MALICIOUS"
            context = f"Consensus ({', '.join(malicious_sources)})"
        else:
            verdict = "SAFE"
            context = "Consensus (All Clean)" if not unknown_sources else f"Consensus (Clean — {len(unknown_sources)} unknown)"

        return {"verdict": verdict, "context": context, "sources": malicious_sources}

    def _run_tier1_single(self, file_hash: str, engine_name: str) -> dict | None:
        """Queries a single cloud engine and returns its result dict."""
        key_map = {
            "virustotal":    lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash),
            "alienvault":    lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash),
            "metadefender":  lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash),
            "malwarebazaar": lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash),
        }
        if engine_name not in key_map:
            return None
        # Warn and fall back to consensus if the selected engine has no API key configured.
        if not self.api_keys.get(engine_name):
            self.log_event(f"[-] '{engine_name}' API key is not configured. Falling back to consensus.")
            return self._run_tier1_concurrent(file_hash)
        return key_map[engine_name]()

    # ── TIER 3: LLM ANALYST

    def generate_llm_report(self, family_name, detected_apis, file_path, confidence_score, sha256, file_size_mb):
        # ── Pre-compute all deterministic values ──────────────────────────────
        # These are ground-truth values owned by Python. The LLM never writes
        # any of these — it only generates behavioral narrative sections.
        max_apis = 50
        if detected_apis:
            extracted_api_text = "\n".join(
                f"- {api}" for api in detected_apis[:max_apis]
            )
            if len(detected_apis) > max_apis:
                extracted_api_text += f"\n- ... and {len(detected_apis) - max_apis} more."
        else:
            extracted_api_text = "None extracted. Likely API hashing or packing."

        live_dss        = calculate_live_dss(detected_apis, file_path)
        live_confidence = int((live_dss / 10.0) * 100)

        if live_dss >= 8.0:
            triage_priority = "CRITICAL"
        elif live_dss >= 6.0:
            triage_priority = "HIGH"
        elif live_dss >= 4.0:
            triage_priority = "MEDIUM"
        else:
            triage_priority = "LOW"

        # Sanitize path — strip analyst username before any external use
        sanitized_path = re.sub(r'(?i)(Users\\\\)[^\\\\]+', r'\\1<analyst>', file_path)

        # ── Deterministic report header ───────────────────────────────────────
        report_header = (
            f"\n--------------------------------------------------\n"
            f"🔍 CYBERSENTINEL ANALYST REPORT\n"
            f"--------------------------------------------------\n"
            f"Target File      : {os.path.basename(file_path)}\n"
            f"Target SHA256    : {sha256}\n"
            f"File Size        : {file_size_mb:.2f} MB\n"
            f"Classification   : {family_name}\n"
            f"DSS Score        : {live_dss}/10\n"
            f"Triage Priority  : {triage_priority}\n"
            f"Detected APIs    :\n"
            f"{extracted_api_text}\n"
            f"--------------------------------------------------\n"
        )

        # ── Deterministic KQL generator ───────────────────────────────────────
        # Maps known APIs to Microsoft Defender for Endpoint ActionType values.
        # This is the source of truth — the LLM is never trusted to write KQL.
        _API_TO_ACTION: dict[str, str] = {
            "VirtualAllocEx":           "VirtualAllocApiCall",
            "NtAllocateVirtualMemory":  "VirtualAllocApiCall",
            "WriteProcessMemory":       "WriteProcessMemoryApiCall",
            "NtProtectVirtualMemory":   "ModifyMemoryProtection",
            "OpenProcess":              "OpenProcessApiCall",
            "CreateRemoteThread":       "CreateRemoteThreadApiCall",
            "NtCreateThreadEx":         "CreateRemoteThreadApiCall",
            "NtResumeThread":           "ResumeThread",
            "SetWindowsHookExA":        "SetWindowsHookApiCall",
            "GetKeyboardState":         "GetAsyncKeyStateApiCall",
            "LdrLoadDll":               "ImageLoaded",
            "RegSetValueExA":           "RegistryValueSet",
            "RegCreateKeyExW":          "RegistryKeyCreated",
            "NtCreateFile":             "FileCreated",
            "InternetOpenUrlA":         "NetworkConnectionEvents",
            "WSAStartup":               "NetworkConnectionEvents",
            "socket":                   "NetworkConnectionEvents",
            "CryptAcquireContextW":     "CryptoApiCall",
            "CryptCreateHash":          "CryptoApiCall",
        }

        def generate_deterministic_kql(file_name: str, api_list: list) -> str:
            """Generates a correct DeviceEvents KQL query from the detected API list."""
            if not api_list:
                return ""
            action_types = sorted({
                f'"{_API_TO_ACTION[api]}"'
                for api in api_list
                if api in _API_TO_ACTION
            })
            if not action_types:
                return ""
            safe_name   = file_name.replace('"', "")
            actions_str = ", ".join(action_types)
            return (
                f"\n### 📊 SIEM/EDR Detection (Deterministic)\n"
                f"**KQL — Microsoft Defender for Endpoint:**\n"
                f"DeviceEvents\n"
                f"| where InitiatingProcessFileName =~ \"{safe_name}\"\n"
                f"| where ActionType in ({actions_str})\n"
                f"| project TimeGenerated, DeviceName, ActionType,\n"
                f"          InitiatingProcessFileName, InitiatingProcessFolderPath,\n"
                f"          AccountName\n"
                f"| order by TimeGenerated desc\n"
            )

        def generate_deterministic_yara(file_name: str, api_list: list) -> str:
            """Generates a behaviorally-sound YARA rule from the detected API list."""
            if not api_list:
                return ""
            rule_name     = re.sub(r'[^a-zA-Z0-9]', '_', file_name.rsplit('.', 1)[0])
            strings_lines = [
                f'        $api{i} = "{api}" ascii wide'
                for i, api in enumerate(api_list)
            ]
            strings_block = "\n".join(strings_lines)
            yara_rule = (
                f"\n### 🎯 Resilient YARA Rule (Auto-Generated)\n"
                f"rule Detect_{rule_name} {{\n"
                f"    meta:\n"
                f'        description = "Behavioral detection for {file_name}"\n'
                f'        severity    = "{triage_priority}"\n'
                f'        dss_score   = "{live_dss}/10"\n'
                f"    strings:\n"
                f"{strings_block}\n"
                f"    condition:\n"
                f"        uint16(0) == 0x5A4D and any of ($api*)\n"
                f"}}"
            )
            
            # [THESIS FIX] YARA Rule Validation Layer
            # Ensures generated rules are syntactically valid to prevent hallucinated signatures from breaking downstream tools.
            try:
                import yara
                compiled_rule = yara.compile(source=yara_rule)
            except ImportError:
                yara_rule += "\n// [!] yara-python not installed; rule syntax not verified."
            except Exception as e:
                yara_rule = f"// [!] YARA generation failed validation: {e}"
                
            return yara_rule

        # ── LLM prompt ────────────────────────────────────────────────────────
        # The model was trained on a fixed output format that includes KQL and
        # YARA. We cannot override that via prompting alone — the training
        # weights dominate. Strategy: ask only for narrative sections, add stop
        # tokens to halt generation before structured blocks, then strip and
        # replace any structured output that slips through with deterministic
        # Python-generated versions. The LLM handles what it is good at —
        # behavioral narrative and attack maneuver grouping.
        system_msg = (
            "You are CyberSentinel Pro, a Tier-3 Malware Research Assistant. "
            "Provide high-fidelity behavioral analysis for SOC environments.\n\n"
            "OUTPUT EXACTLY THESE SECTIONS IN ORDER — NOTHING ELSE:\n"
            "1. ### 🛡️ CyberSentinel High-Fidelity Verdict\n"
            "   One paragraph executive summary. State verdict label only — no scores or percentages.\n"
            "2. ### ⚔️ Attack Maneuvers (Behavioral Analysis)\n"
            "   Group APIs into named maneuvers. Use full MITRE sub-technique IDs (e.g. T1055.001).\n"
            "3. ### 💥 Blast Radius\n"
            "   One paragraph on maximum potential impact if the threat executes fully.\n"
            "4. ### 🕵️ Forensic Artifacts (Hunt List)\n"
            "   Specific file paths, registry keys, memory indicators.\n\n"
            "STOP after Forensic Artifacts. Do NOT write KQL, SIEM queries, or YARA rules."
        )

        real_user = (
            f"--- [START OF TELEMETRY] ---\n"
            f"EXECUTION CONTEXT:\n"
            f"- Filename: {os.path.basename(file_path)}\n"
            f"- Full Path: {sanitized_path}\n"
            f"- File Size: {file_size_mb:.2f} MB\n"
            f"THREAT METADATA:\n"
            f"- Classification: {family_name}\n"
            f"- DSS Score: {live_dss}/10\n"
            f"- Triage Priority: {triage_priority}\n"
            f"API TELEMETRY TRACE:\n"
            f"{chr(44).join(detected_apis) if detected_apis else 'NONE'}\n"
            f"--- [END OF TELEMETRY] ---"
        )

        _OLLAMA_URL      = "http://127.0.0.1:11434/api/chat"
        _CONNECT_TIMEOUT = 15
        _READ_TIMEOUT    = None

        payload = {
            "model":    self.llm_model,
            "messages": [{"role": "user", "content": real_user}],
            "system":   system_msg,
            "options": {
                "temperature": 0.1,
                "num_ctx":     4096,
                "num_predict": 600,
                # Stop tokens — halt generation before the model writes structured blocks
                "stop": [
                    "<|im_end|>",
                    "### 📊",
                    "### 🎯",
                    "DeviceImageLoadEvents",
                    "DeviceEvents\n|",
                    "rule Detect_",
                    "```kql",
                    "```yara",
                    "```KQL",
                ]
            },
            "stream": True,
        }

        try:
            import json as _json
            tokens: list[str] = []

            with _requests.post(
                _OLLAMA_URL,
                json=payload,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                stream=True,
            ) as resp:
                resp.raise_for_status()
                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    try:
                        chunk = _json.loads(raw_line)
                    except ValueError:
                        continue
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        tokens.append(token)
                    if chunk.get("done"):
                        break

            # ── Post-process LLM output ───────────────────────────────────────
            # Safety net: strip any structured blocks the model generated despite
            # stop tokens (quantized models can be unpredictable). Everything
            # from SIEM/YARA sections onward is removed and replaced with the
            # deterministic Python-generated versions below.
            ai_text = "".join(tokens)

            for pattern in (
                r"### 📊.*",
                r"### 🎯.*",
                r"```kql.*?```",
                r"```yara.*?```",
                r"```kql.*",
                r"```KQL.*",
                r"DeviceImageLoadEvents.*",
                r"rule Detect_.*",
            ):
                ai_text = re.sub(pattern, "", ai_text, flags=re.DOTALL | re.IGNORECASE)

            ai_text = ai_text.rstrip()

            # ── Assemble final report ─────────────────────────────────────────
            # Deterministic Header → LLM Narrative → Deterministic KQL → Deterministic YARA
            kql_block  = generate_deterministic_kql(os.path.basename(file_path), detected_apis)
            yara_block = generate_deterministic_yara(os.path.basename(file_path), detected_apis)

            return report_header + "\n" + ai_text + "\n" + kql_block + "\n" + yara_block

        except _requests.exceptions.ConnectionError:
            return (
                "[-] CyberSentinel Analyst Offline: Ollama is not running.\n"
                "    Start Ollama, then retry the AI analyst report."
            )
        except _requests.exceptions.Timeout:
            return (
                "[-] Ollama did not respond within 15s.\n"
                "    Ensure Ollama is running: open a terminal and run 'ollama serve'."
            )
        except _requests.exceptions.HTTPError as e:
            status = getattr(resp, "status_code", "?")
            if status == 404:
                return (
f"[-] Model '{self.llm_model}' not found in Ollama.\n"
f"    Run: ollama create {self.llm_model} -f Modelfile"
                )
            return f"[-] Ollama API error ({status}): {e}"
        except (KeyError, ValueError) as e:
            return f"[-] Unexpected response format from Ollama: {e}"
        except Exception as e:
            return f"[-] CyberSentinel Analyst error: {e}"

    # ── TIER 4: CONTAINMENT & QUARANTINE

    def _prompt_quarantine(self, file_path, sha256, threat_source, verdict,
                           filename="", ai_already_done=False,
                           detected_apis=None):
        """
        Tier 4 containment — called for every malicious verdict.
        Modes:
          headless_mode=True  : auto-quarantine + isolate (daemon)
          gui_callbacks set   : Qt dialogs instead of input() (GUI)
          neither             : standard CLI input() prompts
        gui_callbacks keys: "ask" (str)->bool, "ai_report" (str)->None,
                            "feedback" (sha256,fname,file_path,verdict)->None

        Scenario 3 Fix:
          Step 0.5 pre-extracts PE features BEFORE Step 4 quarantine runs,
          so adaptive learning has valid feature vectors even when the analyst
          approves quarantine and the original file is moved/encrypted.
          For ML-detected threats the already-computed features are reused
          from _prefetch_features_cache (populated by _handle_critical_ml_threat)
          so no double extraction occurs.
        """
        fname = filename or (os.path.basename(file_path) if file_path else sha256)
        gui   = getattr(self, "gui_callbacks", None)

        # ── Step 0.5: Pre-extract features BEFORE quarantine ─────────────────
        # This is the Scenario 3 fix. If features are not already cached
        # (Path B: ML engine pre-cached them in _handle_critical_ml_threat),
        # extract them now while the file is guaranteed to still be on disk.
        # This runs silently — it never blocks or changes the user-visible flow.
        if sha256 not in self._prefetch_features_cache:
            if file_path and os.path.isfile(file_path):
                try:
                    from .adaptive_learner import get_learner
                    fj = get_learner()._extract_and_serialize(file_path)
                    if fj:
                        self._prefetch_features_cache[sha256] = fj
                        self.log_event("[*] Features cached for adaptive learning.")
                except Exception:
                    pass  # Non-critical — learning degrades gracefully without features

         # Step 1: Webhook — always fires first
        if self.webhook_url or self.webhook_critical:
            import socket as _sock
            import datetime as _dt
            # Derive SOC severity from verdict string for correct channel routing
            _v = (verdict or "").upper()
            if "CRITICAL" in _v:
                _severity = "CRITICAL"
            elif "MALICIOUS" in _v or "HIGH" in _v:
                _severity = "CRITICAL"   # malicious file = on-call level
            elif "SUSPICIOUS" in _v or "MEDIUM" in _v:
                _severity = "HIGH"
            else:
                _severity = "MEDIUM"
            ok = utils.route_webhook_alert(
                self._webhooks(),
                _severity,
                "🚨 Threat Detected on Endpoint",
                {
                    "File":     fname,
                    "SHA256":   sha256,
                    "Source":   threat_source,
                    "Verdict":  verdict,
                    "Severity": _severity,
                    "Host":     _sock.gethostname(),
                    "Time":     _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
            status = "OK" if ok else "FAILED"
            colors.success(f"[+] Webhook {status}.") if ok else colors.warning(f"[!] Webhook {status}.")
            self.session_log.append(f"[WEBHOOK] {status}")
        else:
            colors.warning("[!] No webhook configured.")

        # Step 2: Threat banner
        sep = "=" * 60
        self.log_event(sep)
        self.log_event("  THREAT CONFIRMED")
        self.log_event(f"  Verdict : {verdict}")
        self.log_event(f"  Source  : {threat_source}")
        self.log_event(f"  File    : {fname}")
        self.log_event(f"  SHA-256 : {sha256[:32]}...")
        self.log_event(sep)

        # Step 3: Headless daemon — auto-act, no prompts
        if self.headless_mode:
            self.log_event("[!] HEADLESS: Auto-quarantining.")
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
            self.log_event("[!] HEADLESS: Isolating network.")
            network_isolation.isolate_network()
            return

        # Step 4: Quarantine
        if gui:
            msg = ("THREAT CONFIRMED: " + verdict + "\n\n"
                   "File: " + fname + "\nSource: " + threat_source
                   + "\n\nQuarantine this file?")
            q = gui["ask"](msg)
        else:
            q = input("\n[?] Quarantine this file? (Y/N): ").strip().upper() == "Y"
        if q:
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
                colors.success("[+] File quarantined.")
            else:
                colors.warning("[!] No file path — hash-only scan.")
        else:
            colors.warning("[*] Quarantine skipped.")
            self.session_log.append("[*] Quarantine skipped.")

        # Step 5: Network isolation
        if gui:
            n = gui["ask"]("Isolate this host from the network?\n\nBlocks ALL traffic until restored.")
        else:
            n = input("[?] Isolate host network? (Y/N): ").strip().upper() == "Y"
        if n:
            # if the Windows Firewall service is disabled or lacks privileges.
            isolated = network_isolation.isolate_network()
            if isolated:
                colors.critical("[!] Network isolated — restore via Network page when safe.")
                self.session_log.append("[!] NETWORK ISOLATED")
            else:
                colors.warning(
                    "[!] Network isolation FAILED — machine may still be connected. "
                    "Check Administrator privileges and Firewall service status."
                )
                self.session_log.append("[!] ISOLATION FAILED")
        else:
            colors.warning("[*] Network isolation skipped.")

        # Step 6: AI Analyst Report — skip if ML handler already ran it
        if ai_already_done:
            self.log_event("[*] AI report already generated above.")
        else:
            if gui:
                run_ai = gui["ask"](
                    "Generate AI analyst report for:\n" + fname
                    + "\n\nUses your local Ollama model.\nMay take 30-60 seconds."
                )
            else:
                run_ai = input("\n[?] Generate AI analyst report? (Y/N): ").strip().lower() == "y"

            if run_ai:
                self.log_event("[*] Generating AI report...")
                spinner = Spinner("[*] Generating AI threat report...")
                spinner.start()
                report = self.generate_llm_report(
                    family_name="Unknown - Cloud/Signature Detection",
                    detected_apis=detected_apis or [],
                    file_path=file_path or "",
                    confidence_score=100.0,
                    sha256=sha256,
                    file_size_mb=0.0,
                )
                spinner.stop()
                # Save report to session log for the .txt export
                self.session_log.append("--- AI Analyst Report ---")
                self.session_log.append(report)
                if gui and "ai_report" in gui:
                    # GUI mode: _show_ai_report handles both the dialog
                    # and the console echo — do not double-print via log_event
                    gui["ai_report"](report)
                else:
                    # CLI mode: print directly since there is no GUI callback
                    self.log_event("--- AI Analyst Report ---")
                    self.log_event(report)
            else:
                self.log_event("[*] AI report skipped.")

        # Step 7: Analyst Feedback
        # Retrieve pre-extracted features from cache — these were captured in
        # Step 0.5 before quarantine ran, so they are available even if the
        # file no longer exists on disk.
        prefetched_fj = self._prefetch_features_cache.pop(sha256, None)

        if gui:
            if "feedback" in gui:
                gui["feedback"](sha256, fname, file_path or "", verdict,
                                prefetched_fj)
            else:
                self.log_event(
                    f"[*] Verdict logged: {verdict}. "
                    f"Review in Analyst Feedback tab."
                )
        else:
            prompt_analyst_feedback(sha256, fname, verdict,
                                    file_path=file_path or "",
                                    prefetched_features_json=prefetched_fj)

    def _webhooks(self) -> dict:
     """Returns the webhook routing dict for route_webhook_alert."""
     return {
        "webhook_url":      self.webhook_url,
        "webhook_critical": self.webhook_critical,
        "webhook_high":     self.webhook_high,
        "webhook_chains":   self.webhook_chains,
    }

    # ── ML THREAT HANDLER

    def _handle_critical_ml_threat(
        self,
        file_path: str,
        sha256: str,
        file_size_mb: float,
        ml_result: dict,
    ):
        """Orchestrates LLM reporting for ML-detected threats.
        Supports three modes: headless (auto), GUI (callbacks), CLI (input()).
        """
        fam_name = "Unknown"
        features = ml_result.get("features")

        # Scenario 3 Fix (Path B):
        # The ML engine already extracted the feature vector during scan_stage1().
        # Serialize and cache it NOW before deleting it from memory, so
        # _prompt_quarantine Step 0.5 finds it pre-populated and skips
        # re-extraction entirely. This avoids double I/O on the file.
        if features is not None and sha256 not in self._prefetch_features_cache:
            try:
                import json as _json, zlib as _zlib, base64 as _b64
                raw  = _json.dumps(features.tolist()).encode("utf-8")
                comp = _zlib.compress(raw, level=6)
                self._prefetch_features_cache[sha256] = (
                    "z:" + _b64.b64encode(comp).decode("ascii")
                )
            except Exception:
                pass  # Non-critical — Step 0.5 will attempt fresh extraction

        # Release the feature array immediately to prevent memory growth in long-running daemon mode.
        if features is not None:
            del ml_result["features"]

        # Resolve GUI callbacks — mirrors the pattern in scan_file() and _prompt_quarantine()
        gui = getattr(self, "gui_callbacks", None)

        # AI Analyst report
        if self.headless_mode:
            run_ai = True
        elif gui:
            run_ai = gui["ask"](
                f"Malware family: {fam_name}\n\n"
                "Generate AI analyst report via Ollama?\n"
                "Includes API behavioral analysis, MITRE mapping, and YARA rule.\n"
                "May take 30-60 seconds."
            )
        else:
            run_ai = input("\n[?] Generate local AI analyst report via Ollama? (Y/N): ").strip().lower() == "y"

        if run_ai:
            self.log_event("[*] Generating AI report...")
            spinner = Spinner("[*] Generating AI threat report (this may take a moment)...")
            spinner.start()
            report = self.generate_llm_report(
                fam_name,
                ml_result.get("detected_apis", []),
                file_path,
                ml_result["score"] * 100,
                sha256,
                file_size_mb,
            )
            spinner.stop()
            # Save to session log for .txt export
            self.session_log.append("\n--- AI Analyst Report ---")
            self.session_log.append(report)
            if gui and "ai_report" in gui:
                # GUI mode: _show_ai_report handles dialog + console echo
                gui["ai_report"](report)
            else:
                # CLI mode: print directly
                self.log_event("\n--- AI Analyst Report ---")
                self.log_event(report)
        else:
            self.log_event("[*] AI report skipped.")

        self._prompt_quarantine(
            file_path, sha256, "Local ML Engine", "CRITICAL RISK",
            ai_already_done=True,
            detected_apis=ml_result.get("detected_apis", []),
        )

    # ── PUBLIC: SCAN FILE

    def scan_file(self, file_path: str):
        """Main routing pipeline for physical file scans (Tiers 0.5 → 1 → 2 → 3 → 4)."""

        # ── Tier 0: Exclusion list ──────────────────────────────────────────
        if utils.is_excluded(file_path):
            self.log_event(f"[*] ALLOWLISTED: {os.path.basename(file_path)} — bypassed per policy.")
            return

        # ── Priority flag ────────────────────────────────────────────────────
        # High-priority paths (configured in Settings) are flagged so the daemon
        # can fast-track their results — no change to scan logic, purely advisory.
        try:
            hp_paths = utils.load_config().get("high_priority_paths", [])
            if any(file_path.lower().startswith(p.lower()) for p in hp_paths if p):
                self.log_event(
                    f"[!] HIGH PRIORITY: {os.path.basename(file_path)} "
                    f"— matches a critical monitored path."
                )
        except Exception:
            pass  # Non-critical

        sha256 = utils.get_sha256(file_path)
        if not sha256:
            colors.error("[-] Cannot read file — OS may have locked it.")
            return

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            colors.error("[-] File was moved/deleted before scanning could begin.")
            return

        filename = os.path.basename(file_path)
        self.log_event("─" * 60)
        colors.info(f"[*] Target   : {filename}")
        self.session_log.append(f"[*] Target   : {filename}")
        self.log_event(f"[*] SHA-256  : {sha256}")
        self.log_event(f"[*] Size     : {file_size_mb:.2f} MB")

        # ── Tier 0.5: Local cache ───────────────────────────────────────────
        cached = utils.get_cached_result(sha256)
        if cached:
            verdict = cached['verdict'].upper()
            if any(v in verdict for v in ("MALICIOUS", "CRITICAL")):
                colors.critical(f"[*] CACHE HIT — {cached['verdict']}")
            elif "SAFE" in verdict:
                colors.success(f"[*] CACHE HIT — {cached['verdict']}")
            else:
                colors.warning(f"[*] CACHE HIT — {cached['verdict']}")
            self.session_log.append(f"[*] CACHE HIT — {cached['verdict']}")
            self.log_event(f"    Verdict    : {cached['verdict']}")
            self.log_event(f"    Cached On  : {cached['timestamp']}")
            self.log_event(f"    Source     : {cached['source']}")
            cached_apis = cached.get("detected_apis", [])
            if cached_apis:
                self.log_event(f"    Cached APIs: {', '.join(cached_apis)}")
            # Malicious cache hits must still trigger webhook and quarantine — not silently return.
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                self._prompt_quarantine(
                    file_path, sha256,
                    f"Cache Hit ({cached['source']})",
                    cached['verdict'],
                    filename,
                    detected_apis=cached_apis,
                )
            return

       # ── Tier 1: Cloud Intelligence ──────────────────────────────────────
        self.log_event("\n[*] Initializing Cloud Intelligence...")

        import sys as _sys
        gui = getattr(self, "gui_callbacks", None)
        selected_engine = "consensus"

        if gui and "engine" in gui:
            # GUI mode — engine already selected via combo box, never prompt
            selected_engine = gui["engine"]()
        elif (
            not self.headless_mode
            and not gui
            and hasattr(_sys.stdin, "isatty")
            and _sys.stdin.isatty()
        ):
            # CLI interactive mode — prompt once
            print("[?] Select cloud engine:")
            print("  1. VirusTotal        2. AlienVault OTX")
            print("  3. MetaDefender      4. MalwareBazaar")
            print("  5. Smart Consensus (all active APIs) [recommended]")
            mapping = {"1": "virustotal", "2": "alienvault", "3": "metadefender",
                       "4": "malwarebazaar", "5": "consensus"}
            selected_engine = mapping.get(input("  Choice (1-5): ").strip(), "consensus")
        # else: daemon / headless / non-tty — stays "consensus" silently

        cloud_verdict = None
        cloud_context = "N/A"

        if selected_engine == "consensus":
            self.log_event("[*] Running Smart Consensus (concurrent)...")
            result = self._run_tier1_concurrent(sha256)
            cloud_verdict = result["verdict"]
            cloud_context = result["context"]
        else:
            result = self._run_tier1_single(sha256, selected_engine)
            if result:
                cloud_verdict = result.get("verdict")
                cloud_context = selected_engine.capitalize()
                self.log_event(f"[*] {cloud_context}: {cloud_verdict} (Hits: {result.get('engines_detected', 0)})")

        if cloud_verdict:
            intel_context = f"{filename} | Tier 1: {cloud_context}"

            if cloud_verdict == "MALICIOUS":
                colors.critical(f"\n[!] TIER 1 VERDICT: MALICIOUS — detected by {cloud_context}")
                self.session_log.append(f"[!] TIER 1 VERDICT: MALICIOUS — {cloud_context}")

                # Extract API calls from the file's Import Address Table so the
                # AI analyst report has behavioral context even though Tier 2 ML
                # was not needed to confirm the verdict.
                # This is a read-only IAT parse — no LightGBM inference runs.
                cloud_apis = []
                if file_path and os.path.isfile(file_path) and file_size_mb <= 100.0:
                    try:
                        cloud_apis = self.ml_scanner.get_suspicious_apis(file_path)
                        if cloud_apis:
                            self.log_event(
                                f"[*] IAT analysis: {len(cloud_apis)} suspicious API(s) found — "
                                + ", ".join(cloud_apis[:5])
                                + (" ..." if len(cloud_apis) > 5 else "")
                            )
                        else:
                            self.log_event(
                                "[*] IAT analysis: No APIs readable — file may be packed or obfuscated. "
                                "Proceeding to Tier 2 ML for structural analysis."
                            )
                    except Exception:
                        pass

                # ── Tier 2 ML runs even on cloud-MALICIOUS files ────────────
                # This gives analysts SHAP explainability and a second independent
                # verdict even when cloud already confirmed the threat.
                # Packed files that hide their IAT can still be scored structurally.
                ml_cloud_apis = cloud_apis
                if file_size_mb <= 100.0 and file_path and os.path.isfile(file_path):
                    self.log_event("\n[*] Running Tier 2 ML for independent structural analysis...")
                    ml_result_cloud = self.ml_scanner.scan_stage1(file_path)
                    if ml_result_cloud is not None:
                        ml_v  = ml_result_cloud["verdict"]
                        ml_sc = ml_result_cloud["score"]
                        if ml_v == "CRITICAL RISK":
                            colors.critical(f"[*] TIER 2 VERDICT: {ml_v} (Score: {ml_sc:.2%})")
                        elif ml_v == "SUSPICIOUS":
                            colors.warning(f"[*] TIER 2 VERDICT: {ml_v} (Score: {ml_sc:.2%})")
                        else:
                            colors.success(f"[+] TIER 2 VERDICT: {ml_v} (Score: {ml_sc:.2%})")
                        self.session_log.append(f"[*] TIER 2 (supplemental): {ml_v} ({ml_sc:.2%})")
                        # Prefer ML-extracted APIs over IAT-only if available
                        if ml_result_cloud.get("detected_apis"):
                            ml_cloud_apis = ml_result_cloud["detected_apis"]
                            self.log_event(
                                f"[*] Tier 2 APIs: {len(ml_cloud_apis)} API(s) — "
                                + ", ".join(ml_cloud_apis[:5])
                                + (" ..." if len(ml_cloud_apis) > 5 else "")
                            )
                        # Run SHAP explainability on the cloud-confirmed malicious file
                        try:
                            shap_expl = ml_result_cloud.get("shap_explanation")
                            if shap_expl:
                                for line in shap_expl["narrative"].splitlines():
                                    self.log_event(line)
                        except Exception:
                            pass
                    else:
                        self.log_event(
                            "[-] Tier 2: Could not process file (invalid PE or packed beyond "
                            "static extraction). Structural analysis unavailable."
                        )

                # Save APIs to cache so future cache-hit reports also have them
                utils.save_cached_result(
                    sha256, cloud_verdict, intel_context,
                    detected_apis=ml_cloud_apis,
                )

                if file_size_mb > 100.0:
                    self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML limit — skipping Tier 2.")
                # Quarantine fires for all cloud MALICIOUS verdicts regardless of file size.
                self._prompt_quarantine(
                    file_path, sha256, cloud_context, "MALICIOUS", filename,
                    detected_apis=ml_cloud_apis,
                )
                return
            else:
                colors.success(f"\n[+] TIER 1 VERDICT: SAFE — {cloud_context}")
                self.session_log.append(f"[+] TIER 1 VERDICT: SAFE")
                utils.save_cached_result(sha256, cloud_verdict, intel_context)

        # ── Tier 2: Local ML ────────────────────────────────────────────────
        if file_size_mb > 100.0:
            self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML extraction limit. Tier 2 skipped.")
            return

        self.log_event("\n[*] Proceeding to Tier 2: Offline ML...")
        ml_result = self.ml_scanner.scan_stage1(file_path)

        if ml_result is None:
            self.log_event("[-] ML engine could not process file (invalid PE or extraction error).")
            return

        ml_verdict = ml_result["verdict"]
        score_pct = ml_result["score"]

        # [THESIS FIX] Log custom YARA matches if any
        yara_matches = ml_result.get("yara_matches")
        if yara_matches:
            self.log_event(f"[*] CUSTOM YARA MATCHES: {', '.join(yara_matches)}")
            self.session_log.append(f"[*] YARA MATCHES: {', '.join(yara_matches)}")

        self.session_log.append(f"[*] TIER 2: {ml_verdict} ({score_pct:.2%})")
        ml_context = f"{filename} | Tier 2: Local ML ({score_pct:.2%})"
        # Save detected APIs alongside the verdict so cache-hit re-scans
        # can pass them to the AI analyst report without re-running the ML engine.
        utils.save_cached_result(
            sha256, ml_verdict, ml_context,
            detected_apis=ml_result.get("detected_apis", []),
        )

        # Compute context-aware composite risk score combining ML verdict,
        # time-of-day, active threats, chain presence, and baseline deviation.
        try:
            from .risk_scorer import get_risk_scorer
            drs = get_risk_scorer().compute(
                sha256     = sha256,
                filename   = filename,
                verdict    = ml_verdict,
                base_score = score_pct,
                file_path  = file_path,
            )
            self.log_event(
                f"[*] DYNAMIC RISK SCORE: {drs['dynamic_score']:.2f} / 1.00 "
                f"— {drs['risk_level']}"
            )
            self.session_log.append(f"[*] DRS: {drs['dynamic_score']:.2f} ({drs['risk_level']})")
        except Exception as e:
            self.log_event(f"[-] Risk Scorer: Non-critical error: {e}")

        shap_expl = ml_result.get("shap_explanation")
        if shap_expl:
            for line in shap_expl["narrative"].splitlines():
                self.log_event(line)

        drift = ml_result.get("drift_alert")
        if drift:
            colors.warning(
                f"[!] CONCEPT DRIFT: Model confidence dropped {drift['drift_magnitude']:.1%}. "
                f"Retraining recommended — see Adaptive Learning page."
            )
            self.session_log.append(f"[!] DRIFT ALERT: {drift['drift_magnitude']:.1%} degradation")

        # ── Feed findings into chain correlator ─────────────────────────────
        import sqlite3 as _sq, datetime as _dt
        _now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with _sq.connect(utils.DB_FILE) as _c:
                for api in ml_result.get("detected_apis", []):
                    _c.execute(
                        "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
                        ("SUSPICIOUS_API", f"{api} — {filename}", 0, _now),
                    )
        except Exception:
            pass

        if ml_verdict == "CRITICAL RISK":
            self._handle_critical_ml_threat(file_path, sha256, file_size_mb, ml_result)
        elif ml_verdict == "SUSPICIOUS":
            colors.warning("[!] Anomalies detected but below isolation threshold. Sandbox testing advised.")
            if self.webhook_url or self.webhook_high:
                import socket as _sock, datetime as _dt
                utils.route_webhook_alert(
                    self._webhooks(),
                    "HIGH",
                    "⚠️ Suspicious File Detected",
                    {
                        "File":     os.path.basename(file_path) if file_path else "Unknown",
                        "SHA256":   sha256,
                        "Verdict":  "SUSPICIOUS",
                        "Score":    f"{ml_result['score']:.2%}",
                        "Severity": "HIGH",
                        "Host":     _sock.gethostname(),
                        "Time":     _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Action":   "Sandbox testing advised",
                    },
                )
        else:
            colors.success("[+] File structure aligns with safe parameters.")

    # ── PUBLIC: SCAN HASH

    def scan_indicator(self, indicator: str):
        """
        Routes an indicator to the correct scan method based on its type.

        Accepts:
          - IP address  (e.g. 185.220.101.45)
          - URL         (e.g. http://evil.com/payload.exe)
          - Hash        (MD5 / SHA-1 / SHA-256 — routed to scan_hash)

        IP and URL lookups are supported by VirusTotal and AlienVault OTX only.
        MetaDefender and MalwareBazaar do not offer IP/URL reputation APIs
        so they are skipped for these indicator types.
        """
        import re as _re
        indicator = indicator.strip()

        # Detect IP address (IPv4 only)
        if _re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", indicator):
            self._scan_ip(indicator)
            return

        # Detect URL
        if indicator.startswith("http://") or indicator.startswith("https://"):
            self._scan_url(indicator)
            return

        # Fall through to hash scan for everything else
        self.scan_hash(indicator)

    def _scan_ip(self, ip: str):
        """Queries VirusTotal and AlienVault OTX for an IP address verdict."""
        from modules.scanner_api import VirusTotalAPI, AlienVaultAPI
        self.log_event("─" * 60)
        colors.info(f"[*] IP Reputation Scan: {ip}")
        colors.info("[*] Querying VirusTotal and AlienVault OTX...")
        colors.warning("[!] Note: MetaDefender and MalwareBazaar do not support IP lookups — skipped.")
        self.session_log.append(f"[*] IP Scan: {ip}")

        results = {}
        if self.api_keys.get("virustotal"):
            vt = VirusTotalAPI(self.api_keys["virustotal"])
            results["VirusTotal"] = vt.get_ip_report(ip)
        if self.api_keys.get("alienvault"):
            otx = AlienVaultAPI(self.api_keys["alienvault"])
            results["AlienVault OTX"] = otx.get_ip_report(ip)

        if not results:
            colors.error("[-] No API keys configured for IP lookup. Add VirusTotal or AlienVault OTX in Settings.")
            return

        self._display_indicator_results(ip, "IP", results)

    def _scan_url(self, url_indicator: str):
        """Queries VirusTotal and AlienVault OTX for a URL reputation verdict."""
        from modules.scanner_api import VirusTotalAPI, AlienVaultAPI
        self.log_event("─" * 60)
        colors.info(f"[*] URL Reputation Scan: {url_indicator}")
        colors.info("[*] Querying VirusTotal and AlienVault OTX...")
        colors.warning("[!] Note: MetaDefender and MalwareBazaar do not support URL lookups — skipped.")
        self.session_log.append(f"[*] URL Scan: {url_indicator}")

        results = {}
        if self.api_keys.get("virustotal"):
            vt = VirusTotalAPI(self.api_keys["virustotal"])
            results["VirusTotal"] = vt.get_url_report(url_indicator)
        if self.api_keys.get("alienvault"):
            otx = AlienVaultAPI(self.api_keys["alienvault"])
            results["AlienVault OTX"] = otx.get_url_report(url_indicator)

        if not results:
            colors.error("[-] No API keys configured for URL lookup. Add VirusTotal or AlienVault OTX in Settings.")
            return

        self._display_indicator_results(url_indicator, "URL", results)

    def _display_indicator_results(self, indicator: str, itype: str, results: dict):
        """Displays and logs IP/URL reputation results from all queried engines."""
        any_malicious = False
        all_failed    = True

        for engine, result in results.items():
            if result is None:
                colors.warning(f"  [-] {engine}: No record found or API error.")
                continue
            all_failed = False
            verdict    = result.get("verdict", "UNKNOWN")
            detected   = result.get("engines_detected", 0)
            if verdict == "MALICIOUS":
                any_malicious = True
                colors.critical(f"  [!] {engine}: MALICIOUS ({detected} detection(s))")
            else:
                colors.success(f"  [+] {engine}: SAFE ({detected} detection(s))")

        # All engines failed — likely offline or API keys not configured
        if all_failed:
            colors.error(
                f"\n[!] INCONCLUSIVE — All engines failed to respond.\n"
                f"    This usually means you are offline or your API keys are not configured.\n"
                f"    Do NOT treat this as a SAFE result. Verify manually when online."
            )
            self.session_log.append(
                f"[!] {itype} SCAN INCONCLUSIVE (offline/no keys): {indicator}"
            )
            return

        if any_malicious:
            colors.critical(f"\n[!] FINAL VERDICT: MALICIOUS — {itype} flagged by one or more engines")
            self.session_log.append(f"[!] {itype} VERDICT: MALICIOUS — {indicator}")
            if self.webhook_url or self.webhook_critical:
                import socket as _sock, datetime as _dt
                utils.route_webhook_alert(
                    self._webhooks(),
                    "CRITICAL",
                    f"🚨 Malicious {itype} Detected",
                    {
                        itype:      indicator,
                        "Verdict":  "MALICIOUS",
                        "Severity": "CRITICAL",
                        "Host":     _sock.gethostname(),
                        "Time":     _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    },
                )
        else:
            colors.success(f"\n[+] FINAL VERDICT: SAFE — No engines flagged this {itype.lower()}")
            self.session_log.append(f"[+] {itype} VERDICT: SAFE — {indicator}")

    def scan_hash(self, file_hash: str):
        """Hash-only pipeline: Cache → concurrent Tier 1 cloud consensus."""
        # Accepts only hex strings of exactly 32 (MD5), 40 (SHA-1), or 64 (SHA-256) chars.
        # Rejects anything that could be used for URL injection into the API endpoint paths.
        import re as _re
        if not _re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", file_hash.strip()):
            short = file_hash[:32]
            colors.error(
                f"[-] Invalid hash rejected: '{short}...'. "
                "Must be a hex string of 32 (MD5), 40 (SHA-1), or 64 (SHA-256) chars."
            )
            return
        file_hash = file_hash.strip().lower()

        self.log_event("─" * 60)
        colors.info(f"[*] Manual Hash Scan: {file_hash}")
        self.session_log.append(f"[*] Manual Hash Scan: {file_hash}")

        cached = utils.get_cached_result(file_hash)
        if cached:
            colors.warning("[*] CACHE HIT — Local Threat DB")
            self.session_log.append("[*] CACHE HIT")
            self.log_event(f"    Verdict  : {cached['verdict']}")
            self.log_event(f"    Cached On: {cached['timestamp']}")
            self.log_event(f"    Source   : {cached['source']}")
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                colors.critical(
                    "[!] This hash is flagged as MALICIOUS in the local cache.\n"
                    "    If you have the actual file on disk, scan it directly\n"
                    "    via Scan File to trigger quarantine and containment."
                )
                self.session_log.append(
                    f"[!] HASH FLAGGED: {file_hash} — "
                    "Scan the file directly to quarantine it."
                )
                if self.webhook_url or self.webhook_critical:
                    import socket as _sock, datetime as _dt
                    utils.route_webhook_alert(
                        self._webhooks(),
                        "CRITICAL",
                        "🚨 Malicious Hash — Cache Hit",
                        {
                            "Hash":     file_hash,
                            "Verdict":  cached["verdict"],
                            "Source":   cached["source"],
                            "Severity": "CRITICAL",
                            "Host":     _sock.gethostname(),
                            "Time":     _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "Action":   "Scan the file directly to quarantine it",
                        },
                    )
            return

        self.log_event("[*] Running Smart Consensus (concurrent)...")
        result = self._run_tier1_concurrent(file_hash)
        cloud_verdict = result["verdict"]
        cloud_context = result["context"]

        if cloud_verdict == "MALICIOUS":
            colors.critical(f"\n[!] FINAL VERDICT: MALICIOUS — {cloud_context}")
            colors.critical(
                "[!] This hash is confirmed MALICIOUS by cloud engines.\n"
                "    If you have the actual file on disk, scan it directly\n"
                "    via Scan File to trigger quarantine and containment."
            )
            self.session_log.append(f"[!] HASH VERDICT: MALICIOUS — {cloud_context}")
            if self.webhook_url or self.webhook_critical:
                import socket as _sock, datetime as _dt
                utils.route_webhook_alert(
                    self._webhooks(),
                    "CRITICAL",
                    "🚨 Malicious Hash Confirmed by Cloud",
                    {
                        "Hash":     file_hash,
                        "Verdict":  "MALICIOUS",
                        "Source":   cloud_context,
                        "Severity": "CRITICAL",
                        "Host":     _sock.gethostname(),
                        "Time":     _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Action":   "Scan the file directly to quarantine it",
                    },
                )
        else:
            colors.success(f"\n[+] FINAL VERDICT: SAFE — {cloud_context}")
            self.session_log.append(f"[+] HASH VERDICT: SAFE")

        if cloud_verdict:
            utils.save_cached_result(
                file_hash, cloud_verdict,
                f"Cloud Consensus ({cloud_context})"
            )

    # ── SESSION LOG

    def save_session_log(self):
        """
        Writes the session log to a timestamped .txt file.
        GUI mode: shows a save-session dialog with custom filename option.
        CLI mode: interactive filename prompt.
        """
        if not self.session_log:
            return

        gui = getattr(self, "gui_callbacks", None)
        analysis_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "Analysis Files"
        )
        os.makedirs(analysis_dir, exist_ok=True)

        if gui:
            # GUI mode — show a non-blocking save dialog via signal
            import threading
            done = threading.Event()

            def _show_save_dialog():
                try:
                    from PyQt6.QtWidgets import (
                        QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                        QLineEdit, QPushButton, QCheckBox
                    )
                    import datetime as _dt

                    default_name = (
                        "scan_report_"
                        + _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    )

                    # Color constants — hardcoded here because analysis_manager.py
                    # must not import from gui.py. These match the CyberSentinel THEME.
                    _BG      = "#161b22"
                    _SURFACE = "#0d1117"
                    _BLUE    = "#58a6ff"
                    _TEXT    = "#e6edf3"
                    _MUTED   = "#8b949e"
                    _BORDER  = "#30363d"

                    dlg = QDialog()
                    dlg.setWindowTitle("Save Scan Session")
                    dlg.setFixedWidth(480)
                    dlg.setStyleSheet(f"""
                        QDialog {{
                            background: {_BG};
                        }}
                        QLabel {{
                            color: {_TEXT};
                            border: none;
                        }}
                        QLineEdit {{
                            background: {_SURFACE};
                            color: {_TEXT};
                            border: 1px solid {_BORDER};
                            border-radius: 4px;
                            padding: 6px 10px;
                            font-size: 12px;
                            selection-background-color: {_BLUE};
                        }}
                        QLineEdit:focus {{
                            border: 1px solid {_BLUE};
                        }}
                        QPushButton {{
                            background: {_BG};
                            color: {_TEXT};
                            border: 1px solid {_BORDER};
                            border-radius: 4px;
                            padding: 6px 16px;
                            font-size: 11px;
                        }}
                        QPushButton:hover {{
                            background: #21262d;
                            border-color: {_TEXT};
                        }}
                        QPushButton#primary {{
                            background: {_BLUE};
                            color: #ffffff;
                            border: none;
                            font-weight: bold;
                        }}
                        QPushButton#primary:hover {{
                            background: #388bfd;
                        }}
                    """)
                    layout = QVBoxLayout(dlg)
                    layout.setContentsMargins(24, 24, 24, 20)
                    layout.setSpacing(14)

                    # Header
                    header = QLabel("💾  Save Scan Session Report")
                    header.setStyleSheet(
                        f"color: {_BLUE}; font-size: 14px; "
                        f"font-weight: bold; border: none;"
                    )
                    layout.addWidget(header)

                    # Summary of what will be saved
                    n_lines = len(self.session_log)
                    summary = QLabel(
                        f"The current session contains <b>{n_lines}</b> log entries.<br>"
                        f"The report will be saved to: <code>Analysis Files\\</code>"
                    )
                    summary.setStyleSheet(
                        f"color: {_MUTED}; font-size: 11px; "
                        f"background: #0d1117; border: 1px solid {_BORDER}; "
                        f"border-radius: 4px; padding: 10px;"
                    )
                    summary.setWordWrap(True)
                    layout.addWidget(summary)

                    # Filename input
                    fname_row = QHBoxLayout()
                    fname_lbl = QLabel("Filename:")
                    fname_lbl.setFixedWidth(72)
                    fname_lbl.setStyleSheet(f"color: {_TEXT}; font-size: 11px; border: none;")
                    fname_input = QLineEdit(default_name)
                    fname_input.setPlaceholderText("e.g. my_scan_report")
                    fname_row.addWidget(fname_lbl)
                    fname_row.addWidget(fname_input)
                    ext_lbl = QLabel(".html")
                    ext_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 11px; border: none;")
                    fname_row.addWidget(ext_lbl)
                    layout.addLayout(fname_row)

                    # Divider
                    from PyQt6.QtWidgets import QFrame
                    divider = QFrame()
                    divider.setFrameShape(QFrame.Shape.HLine)
                    divider.setStyleSheet(f"color: {_BORDER};")
                    layout.addWidget(divider)

                    # Buttons
                    btn_row = QHBoxLayout()
                    save_btn = QPushButton("💾  Save Report")
                    save_btn.setObjectName("primary")
                    save_btn.setFixedWidth(140)
                    save_btn.setFixedHeight(32)
                    skip_btn = QPushButton("Skip")
                    skip_btn.setFixedWidth(80)
                    skip_btn.setFixedHeight(32)
                    btn_row.addStretch()
                    btn_row.addWidget(save_btn)
                    btn_row.addWidget(skip_btn)
                    layout.addLayout(btn_row)

                    def _do_save():
                        raw = fname_input.text().strip() or default_name
                        # Sanitize — remove path separators and dangerous chars
                        import re
                        safe = re.sub(r'[\\/:*?"<>|]', '_', raw)
                        if not safe.endswith(".html"):
                            safe += ".html"
                        filepath = os.path.join(analysis_dir, safe)
                        # Avoid overwrite silently — append timestamp if exists
                        if os.path.exists(filepath):
                            import datetime as _dt2
                            ts = _dt2.datetime.now().strftime("_%H%M%S")
                            safe = safe.replace(".html", f"{ts}.html")
                            filepath = os.path.join(analysis_dir, safe)
                        try:
                            # [THESIS FIX] HTML Export for Analyst Reports
                            with open(filepath, "w", encoding="utf-8") as f:
                                html = f"""<!DOCTYPE html>
<html>
<head>
<title>CyberSentinel Scan Report</title>
<style>
body {{ background: #0d1117; color: #c9d1d9; font-family: Consolas, monospace; padding: 20px; }}
h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
.log {{ background: #161b22; padding: 15px; border: 1px solid #30363d; border-radius: 5px; white-space: pre-wrap; }}
</style>
</head>
<body>
<h2>🛡️ CyberSentinel Scan Report</h2>
<p><b>Generated:</b> {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="log">
{chr(10).join(self.session_log)}
</div>
</body>
</html>"""
                                f.write(html)
                            self.log_event(
                                f"[+] Session report saved: Analysis Files\\{safe}"
                            )
                        except Exception as e:
                            self.log_event(f"[-] Report save failed: {e}")
                        dlg.accept()

                    save_btn.clicked.connect(_do_save)
                    skip_btn.clicked.connect(dlg.reject)
                    dlg.exec()

                except Exception as e:
                    print(f"[-] Save dialog error: {e}")
                finally:
                    done.set()

            # Run on main Qt thread
            try:
                from PyQt6.QtCore import QMetaObject, Qt
                # Use the existing main-thread signal if available
                if hasattr(self, '_run_on_main_signal'):
                    self._run_on_main_signal.emit(_show_save_dialog)
                else:
                    _show_save_dialog()
            except Exception:
                _show_save_dialog()
            return

        # CLI interactive path
        print("\n" + "=" * 50)
        ans = input("[?] Save session results to a forensic .txt log? (Y/N): ").strip().lower()
        if ans != "y":
            return

        while True:
            filename = input("[>] Filename (e.g., my_report): ").strip() or "scan_results"
            if not filename.endswith(".txt"):
                filename += ".txt"

            filepath = os.path.join(analysis_dir, filename)

            if os.path.exists(filepath):
                overwrite = input(f"[!] '{filename}' already exists. Overwrite? (Y/N): ").strip().lower()
                if overwrite != "y":
                    print("[*] Enter a different filename.")
                    continue

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "=" * 60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "=" * 60 + "\n END OF REPORT\n" + "=" * 60 + "\n")
                colors.success(f"\n[+] Report saved: {os.path.abspath(filepath)}")
                break
            except Exception as e:
                colors.error(f"[-] Save error: {e}")
                break

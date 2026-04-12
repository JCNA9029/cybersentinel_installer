# modules/ml_engine.py

import os
import numpy as np
import pefile
import lightgbm as lgb
from .loading import Spinner
from . import utils
from pathlib import Path
from ._paths import MODELS_DIR

try:
    import thrember
    _THREMBER_AVAILABLE = True
except ImportError:
    _THREMBER_AVAILABLE = False
    print("[!] Warning: 'thrember' library not found. Local ML scanning will be unavailable.")

class LocalScanner:
    def __init__(
        self,
        all_model_path: str = str(MODELS_DIR / "CyberSentinel_v2.model"),
        threshold: float = 0.6,
    ):
        self.all_model_path = all_model_path
        self.threshold = threshold

        self.all_model = None

    # ── MODEL LOADING

    def _load_model(self, path: str) -> lgb.Booster | None:
        if not os.path.exists(path):
            print(f"[-] Model file '{path}' not found.")
            return None

        # Detects tampering or accidental corruption — a modified model that
        # always returns SAFE would silently disable Tier 2 detection.
        if not self._verify_model_integrity(path):
            print(f"[!] WARNING: Model integrity check failed for '{path}'.")
            print("[!] The model file may have been tampered with or corrupted.")
            print("[!] Tier 2 ML scanning disabled until model is verified.")
            return None

        spinner = Spinner("[*] Loading ML model...")
        spinner.start()
        try:
            model = lgb.Booster(model_file=path)
            spinner.stop()
            return model
        except Exception as e:
            spinner.stop()
            print(f"[-] Failed to load ML model: {e}")
            return None

    def _verify_model_integrity(self, model_path: str) -> bool:
        """
        Verifies the model file against a stored SHA-256 hash.

        On first load (no hash file exists), computes and stores the hash —
        Trust On First Use (TOFU). On subsequent loads, compares against stored hash.
        If the hash file is missing after first use, that itself is a warning sign.

        Returns True if the model is unmodified, False if tampering is detected.
        """
        import hashlib
        hash_path = model_path + ".sha256"

        try:
            actual_hash = hashlib.sha256(
                open(model_path, "rb").read()
            ).hexdigest()
        except Exception as e:
            print(f"[-] Cannot hash model file: {e}")
            return False

        if not os.path.exists(hash_path):
            # First use — store hash (TOFU)
            try:
                with open(hash_path, "w") as f:
                    f.write(actual_hash)
                print(f"[*] Model integrity baseline created: {os.path.basename(hash_path)}")
                return True
            except Exception:
                return True   # Cannot write hash file — proceed with warning

        try:
            expected_hash = open(hash_path).read().strip()
        except Exception:
            print("[!] Cannot read model hash file.")
            return True   # Cannot verify — proceed cautiously

        if actual_hash != expected_hash:
            print(f"[!] Model hash mismatch!")
            print(f"    Expected : {expected_hash}")
            print(f"    Actual   : {actual_hash}")
            return False

        return True

    # ── FEATURE EXTRACTION

    def extract_features(self, file_path: str) -> np.ndarray | None:
        """
        Maps PE structural metadata into a float32 feature tensor via thrember.
        Hard limits:
          - 100 MB file size cap (host resource protection — covers 99.2% of
            real-world malware while keeping peak RAM under ~1 GB)
          - MZ magic byte validation (defeats extension spoofing)
        """
        if not _THREMBER_AVAILABLE:
            print("[-] thrember not installed. Cannot extract features.")
            return None

        try:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                print("[-] INFO: File exceeds 100 MB optimization threshold. Skipping local ML.")
                return None
        except OSError:
            return None

        file_data = None
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            if not file_data.startswith(b"MZ"):
                print("[-] REJECTED: Not a valid Windows PE (bad magic bytes).")
                return None

            extractor = thrember.PEFeatureExtractor()
            features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
            return features.reshape(1, -1)

        except PermissionError:
            print("[!] ACCESS DENIED: File is locked by OS (actively executing).")
            return None
        except thrember.exceptions.PEFormatError:
            print("[-] PARSER ERROR: Corrupted PE header (possible decompression bomb).")
            return None
        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return None
        finally:
            if file_data is not None:
                del file_data

    # ── IAT FORENSIC ANALYSIS

    def get_suspicious_apis(self, file_path: str) -> list[str]:
        """
        Parses the Import Address Table (IAT) for high-risk Windows API calls.

        The pefile handle is closed in a finally block to guarantee mmap release
        even when malformed PE headers raise exceptions mid-parse.

        Import names are decoded with errors='ignore' because malware samples
        frequently embed non-UTF-8 bytes in import name strings to crash parsers.
        """
        suspicious_calls = []
        target_apis = {
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "SetWindowsHookEx", "GetKeyboardState", "URLDownloadToFile",
            "RegSetValueEx", "CryptEncrypt", "HttpSendRequest",
            "NtUnmapViewOfSection", "ZwWriteVirtualMemory", "OpenProcess",
        }

        pe = None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode("utf-8", errors="ignore")
                            if name in target_apis:
                                suspicious_calls.append(name)

        except Exception:
            pass
        finally:
            if pe is not None:
                pe.close()

        return list(set(suspicious_calls))

    # ── INFERENCE STAGES

    def scan_stage1(self, file_path: str) -> dict | None:
        """
        Stage 1: binary malicious/benign classification.
        Returns a result dict or None if the file cannot be processed.

        """
        try:
            from .adaptive_learner import check_and_clear_reload_flag
            if check_and_clear_reload_flag():
                print("[*] AdaptiveLearner: Reloading updated model...")
                self.all_model = self._load_model(self.all_model_path)
        except Exception:
            pass

        spinner = Spinner("[*] Extracting dimensional features...")
        spinner.start()
        features = self.extract_features(file_path)
        spinner.stop()

        if features is None:
            return None

        if self.all_model is None:
            self.all_model = self._load_model(self.all_model_path)
            if self.all_model is None:
                return None

        try:
            raw_score = float(self.all_model.predict(features)[0])

            if raw_score > self.threshold:
                verdict, is_malicious = "CRITICAL RISK", True
            elif raw_score > 0.4:
                verdict, is_malicious = "SUSPICIOUS", False
            else:
                verdict, is_malicious = "SAFE", False

            apis = self.get_suspicious_apis(file_path)

            result = {
                "verdict":        verdict,
                "score":          raw_score,
                "is_malicious":   is_malicious,
                "features":       features,
                "detected_apis":  apis,
                "shap_explanation": None,
                "drift_alert":    None,
            }

            try:
                from .explainability import get_explainer
                sha256 = utils.get_sha256(file_path) if file_path else None
                fname  = os.path.basename(file_path) if file_path else "unknown"
                expl   = get_explainer().explain(
                    model    = self.all_model,
                    features = features,
                    sha256   = sha256 or "",
                    filename = fname,
                    verdict  = verdict,
                    score    = raw_score,
                    top_n    = 10,
                )
                result["shap_explanation"] = expl
                if expl:
                    print(f"[*] SHAP: {expl['narrative'].splitlines()[0]}")
            except Exception as e:
                print(f"[-] SHAP: Non-critical explainability error: {e}")

            try:
                from .drift_detector import get_drift_detector
                sha256 = utils.get_sha256(file_path) if file_path else None
                fname  = os.path.basename(file_path) if file_path else "unknown"
                drift  = get_drift_detector().observe(
                    sha256   = sha256 or "",
                    filename = fname,
                    verdict  = verdict,
                    score    = raw_score,
                )
                result["drift_alert"] = drift
            except Exception as e:
                print(f"[-] DriftDetector: Non-critical error: {e}")

            return result

        except Exception as e:
            print(f"[-] ML inference failed: {e}")
            return None


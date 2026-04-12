# modules/scanner_api.py

import requests
from requests.exceptions import Timeout, RequestException
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
#
#  VirusTotal free tier: 4 requests/minute, 500/day.
#  Without throttling, scanning a folder of 100 files would fire 400 concurrent
#  API requests, exhausting the daily quota in seconds.
#
#  The token bucket algorithm allows burst usage while enforcing the average
#  rate. Tokens accumulate at the configured rate up to the bucket capacity.
# ─────────────────────────────────────────────────────────────────────────────

class _TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, calls_per_minute: float):
        self._rate    = calls_per_minute / 60.0   # tokens per second
        self._tokens  = calls_per_minute           # start full
        self._lock    = threading.Lock()
        self._last    = time.monotonic()

    def acquire(self):
        """Blocks until a token is available."""
        with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(
                self._tokens + elapsed * self._rate,
                self._rate * 60          # cap at one minute of tokens
            )
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                time.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

_vt_limiter    = _TokenBucket(calls_per_minute=4)    # VirusTotal free: 4/min
_otx_limiter   = _TokenBucket(calls_per_minute=10)   # AlienVault OTX: generous
_md_limiter    = _TokenBucket(calls_per_minute=10)   # MetaDefender free: ~10/min
_mb_limiter    = _TokenBucket(calls_per_minute=20)   # MalwareBazaar: generous

class VirusTotalAPI:
    """
    VirusTotal v3 Files API — consensus threshold: ≥3 engines for MALICIOUS.
    Also supports IP and URL reputation lookups.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"accept": "application/json", "x-apikey": api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """Queries the API and returns a standardised verdict dict or None."""
        if not self.api_key:
            return None
        _vt_limiter.acquire()
        try:
            response = requests.get(
                self.BASE_URL + file_hash,
                headers=self.headers,
                timeout=5,
            )
            if response.status_code == 200:
                stats = (
                    response.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious_count = stats.get("malicious", 0)
                engines_total = sum(stats.values())
                return {
                    "verdict":          "MALICIOUS" if malicious_count >= 3 else "SAFE",
                    "engines_detected": malicious_count,
                    "engines_total":    engines_total,
                }
            return None
        except RequestException:
            return None

    def get_ip_report(self, ip: str) -> dict | None:
        """Queries the API for an IP address reputation verdict."""
        if not self.api_key:
            return None
        _vt_limiter.acquire()
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=self.headers,
                timeout=5,
            )
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious_count = stats.get("malicious", 0)
                return {
                    "verdict":          "MALICIOUS" if malicious_count >= 3 else "SAFE",
                    "engines_detected": malicious_count,
                }
            return None
        except RequestException:
            return None

    def get_url_report(self, url_indicator: str) -> dict | None:
        """Queries the API for a URL reputation verdict."""
        import base64 as _b64
        if not self.api_key:
            return None
        _vt_limiter.acquire()
        try:
            url_id = _b64.urlsafe_b64encode(
                url_indicator.encode()
            ).decode().rstrip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=self.headers,
                timeout=5,
            )
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious_count = stats.get("malicious", 0)
                return {
                    "verdict":          "MALICIOUS" if malicious_count >= 3 else "SAFE",
                    "engines_detected": malicious_count,
                }
            return None
        except RequestException:
            return None

class AlienVaultAPI:
    """
    AlienVault OTX Indicators API — MALICIOUS if hash appears in ≥1 pulse.
    Also supports IP and URL reputation lookups.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """Queries the API and returns a standardised verdict dict or None."""
        if not self.api_key:
            return None
        try:
            _otx_limiter.acquire()
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                pulse_count = (
                    resp.json().get("pulse_info", {}).get("count", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if pulse_count > 0 else "SAFE",
                    "engines_detected": pulse_count,
                }
            return None
        except Timeout:
            print("[-] AlienVault: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] AlienVault: Network error — {e}")
            return None
        except ValueError:
            print("[-] AlienVault: Invalid JSON in response.")
            return None

    def get_ip_report(self, ip: str) -> dict | None:
        """Queries the API for an IP address reputation verdict."""
        if not self.api_key:
            return None
        try:
            _otx_limiter.acquire()
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                pulse_count = (
                    resp.json().get("pulse_info", {}).get("count", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if pulse_count > 0 else "SAFE",
                    "engines_detected": pulse_count,
                }
            return None
        except (Timeout, RequestException, ValueError):
            return None

    def get_url_report(self, url_indicator: str) -> dict | None:
        """Queries the API for a URL reputation verdict."""
        if not self.api_key:
            return None
        try:
            _otx_limiter.acquire()
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(url_indicator).netloc or url_indicator
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                pulse_count = (
                    resp.json().get("pulse_info", {}).get("count", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if pulse_count > 0 else "SAFE",
                    "engines_detected": pulse_count,
                }
            return None
        except (Timeout, RequestException, ValueError):
            return None

class MetaDefenderAPI:
    """
    OPSWAT MetaDefender v4 Hash Lookup API.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"apikey": self.api_key}

    def get_report(self, file_hash: str) -> dict | None:
        """Queries the API and returns a standardised verdict dict or None."""
        if not self.api_key:
            return None
        try:
            _md_limiter.acquire()
            url = f"https://api.metadefender.com/v4/hash/{file_hash}"
            resp = requests.get(url, headers=self.headers, timeout=5)
            if resp.status_code == 200:
                threats = (
                    resp.json().get("scan_results", {}).get("threats", 0)
                )
                return {
                    "verdict":          "MALICIOUS" if threats > 0 else "SAFE",
                    "engines_detected": threats,
                }
            return None
        except Timeout:
            print("[-] MetaDefender: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MetaDefender: Network error — {e}")
            return None
        except ValueError:
            print("[-] MetaDefender: Invalid JSON in response.")
            return None

class MalwareBazaarAPI:
    """
    abuse.ch MalwareBazaar hash lookup — hash present = definitively MALICIOUS.
    """

    _API_URL = "https://mb-api.abuse.ch/api/v1/"
    _HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; CyberSentinel-EDR/1.0; "
            "+https://github.com/JCNA9029/CyberSentinel_v.1)"
        )
    }

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_report(self, file_hash: str) -> dict | None:
        """Queries the API and returns a standardised verdict dict or None."""
        if not self.api_key:
            return None
        try:
            _mb_limiter.acquire()
            headers = {**self._HEADERS, "Auth-Key": self.api_key}
            resp = requests.post(
                self._API_URL,
                data={"query": "get_info", "hash": file_hash},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                result = resp.json()
                if result.get("query_status") == "ok":
                    return {"verdict": "MALICIOUS", "engines_detected": 1}
                return {"verdict": "SAFE", "engines_detected": 0}
            print(f"[-] MalwareBazaar: HTTP {resp.status_code}")
            return None
        except Timeout:
            print("[-] MalwareBazaar: Request timed out. Engine skipped.")
            return None
        except RequestException as e:
            print(f"[-] MalwareBazaar: Network error — {e}")
            return None
        except ValueError:
            print("[-] MalwareBazaar: Invalid JSON in response.")
            return None

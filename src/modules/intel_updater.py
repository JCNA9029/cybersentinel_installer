# modules/intel_updater.py — Threat Intelligence Feed Manager

import os
import json
import datetime
import requests

INTEL_DIR = "intel"
LOLBAS_PATH    = os.path.join(INTEL_DIR, "lolbas.json")
LOLDRIVERS_PATH = os.path.join(INTEL_DIR, "loldrivers.json")
JA3_PATH       = os.path.join(INTEL_DIR, "ja3_blocklist.csv")
FEODO_PATH     = os.path.join(INTEL_DIR, "feodo_blocklist.json")
META_PATH      = os.path.join(INTEL_DIR, "update_meta.json")

FEEDS = {
    "lolbas":    "https://lolbas-project.github.io/api/lolbas.json",
    "loldrivers":"https://www.loldrivers.io/api/drivers.json",
    "ja3":       "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "feodo":     "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}

TIMEOUT = 15   # seconds per feed download

# Minimum acceptable response sizes (bytes) — responses smaller than this
# indicate a compromised, empty, or error response and are rejected.
MIN_FEED_SIZES = {
    "lolbas":     10_000,
    "loldrivers": 50_000,
    "ja3":         1_000,
    "feodo":       5_000,
}

# before overwriting the cached copy.
_JSON_FEEDS = {"lolbas", "loldrivers", "feodo"}
_CSV_FEEDS  = {"ja3"}

def _ensure_intel_dir():
    os.makedirs(INTEL_DIR, exist_ok=True)

def _load_meta() -> dict:
    if os.path.exists(META_PATH):
        try:
            with open(META_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_meta(meta: dict):
    try:
        with open(META_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass

def _needs_update(meta: dict, feed_name: str, max_age_hours: int = 24) -> bool:
    last = meta.get(feed_name)
    if not last:
        return True
    try:
        delta = datetime.datetime.now() - datetime.datetime.fromisoformat(last)
        return delta.total_seconds() > max_age_hours * 3600
    except Exception:
        return True

def update_feed(feed_name: str, force: bool = False) -> bool:
    """Downloads a single feed. Returns True on success."""
    _ensure_intel_dir()
    meta = _load_meta()

    if not force and not _needs_update(meta, feed_name):
        return True   # Already fresh

    url = FEEDS.get(feed_name)
    if not url:
        print(f"[-] Unknown feed: {feed_name}")
        return False

    path_map = {
        "lolbas":     LOLBAS_PATH,
        "loldrivers": LOLDRIVERS_PATH,
        "ja3":        JA3_PATH,
        "feodo":      FEODO_PATH,
    }
    dest = path_map[feed_name]

    try:
        print(f"[*] Updating {feed_name} feed from {url} ...")
        resp = requests.get(url, timeout=TIMEOUT, verify=True)
        resp.raise_for_status()

        # A response smaller than the minimum indicates an error page,
        # a compromised feed, or a DNS hijack returning a stub response.
        min_size = MIN_FEED_SIZES.get(feed_name, 1000)
        if len(resp.content) < min_size:
            print(
                f"[-] {feed_name}: Response too small "
                f"({len(resp.content)} bytes, minimum {min_size}) — rejecting update."
            )
            return False

        # Validate the response is actually the expected format before
        # overwriting the cached copy. A corrupted or spoofed response
        # that cannot be parsed is rejected and the old cache is kept.
        if feed_name in _JSON_FEEDS:
            try:
                json.loads(resp.content)
            except json.JSONDecodeError as e:
                print(f"[-] {feed_name}: Invalid JSON in response ({e}) — rejecting update.")
                return False
        elif feed_name in _CSV_FEEDS:
            lines = resp.text.splitlines()
            data_lines = [l for l in lines if l.strip() and not l.startswith("#")]
            if not data_lines:
                print(f"[-] {feed_name}: No data lines in CSV response — rejecting update.")
                return False

        # Preserve user-added custom entries before overwriting the file.
        custom_feodo: list[dict] = []
        custom_ja3:   list[str]  = []
        if feed_name == "feodo" and os.path.exists(dest):
            try:
                existing = json.loads(open(dest, encoding="utf-8").read())
                custom_feodo = [e for e in existing if e.get("_custom")]
            except Exception:
                pass
        elif feed_name == "ja3" and os.path.exists(dest):
            try:
                for line in open(dest, encoding="utf-8").read().splitlines():
                    if line.startswith("#_custom:") or (",_custom," in line):
                        custom_ja3.append(line)
            except Exception:
                pass

        with open(dest, "wb") as f:
            f.write(resp.content)

        # Re-inject custom entries, skipping any that now exist in the feed.
        if feed_name == "feodo" and custom_feodo:
            try:
                fresh = json.loads(open(dest, encoding="utf-8").read())
                existing_ips = {e.get("ip_address") for e in fresh}
                merged = fresh + [e for e in custom_feodo
                                  if e.get("ip_address") not in existing_ips]
                with open(dest, "w", encoding="utf-8") as f:
                    json.dump(merged, f)
                print(f"[*] Preserved {len(custom_feodo)} custom Feodo entries.")
            except Exception:
                pass
        elif feed_name == "ja3" and custom_ja3:
            try:
                existing_hashes = set()
                for line in open(dest, encoding="utf-8").read().splitlines():
                    if not line.startswith("#") and line.strip():
                        existing_hashes.add(line.split(",")[0].strip())
                new_lines = [l for l in custom_ja3
                             if l.split(",")[0].strip() not in existing_hashes]
                if new_lines:
                    with open(dest, "a", encoding="utf-8") as f:
                        f.write("\n" + "\n".join(new_lines))
                print(f"[*] Preserved {len(custom_ja3)} custom JA3 entries.")
            except Exception:
                pass

        meta[feed_name] = datetime.datetime.now().isoformat()
        _save_meta(meta)
        size_kb = os.path.getsize(dest) / 1024
        print(f"[+] {feed_name} updated — {size_kb:.1f} KB saved to {dest}")
        return True
    except Exception as e:
        print(f"[-] Failed to update {feed_name}: {e}")
        return False

def update_all(force: bool = False):
    """Updates all four intelligence feeds."""
    print("\n[*] Updating CyberSentinel Threat Intelligence Feeds...")
    results = {}
    for name in FEEDS:
        results[name] = update_feed(name, force=force)
    ok = sum(results.values())
    print(f"[+] Intel update complete: {ok}/{len(FEEDS)} feeds refreshed.\n")
    return results

def feed_status() -> dict:
    """Returns the last-updated timestamp for each feed."""
    meta = _load_meta()
    status = {}
    for name, path in {
        "lolbas": LOLBAS_PATH, "loldrivers": LOLDRIVERS_PATH,
        "ja3": JA3_PATH, "feodo": FEODO_PATH,
    }.items():
        status[name] = {
            "last_update": meta.get(name, "Never"),
            "cached":      os.path.exists(path),
            "size_kb":     round(os.path.getsize(path) / 1024, 1) if os.path.exists(path) else 0,
        }
    return status

# ─── Convenience loaders used by detector modules ─────────────────────────────

def load_lolbas() -> list:
    """Returns LOLBAS entries as a list of dicts. Auto-updates if missing."""
    if not os.path.exists(LOLBAS_PATH):
        update_feed("lolbas")
    if not os.path.exists(LOLBAS_PATH):
        return []
    try:
        with open(LOLBAS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_loldrivers() -> list:
    """Returns LOLDrivers entries as a list of dicts. Auto-updates if missing."""
    if not os.path.exists(LOLDRIVERS_PATH):
        update_feed("loldrivers")
    if not os.path.exists(LOLDRIVERS_PATH):
        return []
    try:
        with open(LOLDRIVERS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_ja3_blocklist() -> set:
    """Returns a set of malicious JA3 fingerprint hex strings."""
    if not os.path.exists(JA3_PATH):
        update_feed("ja3")
    if not os.path.exists(JA3_PATH):
        return set()
    hashes = set()
    try:
        with open(JA3_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split(",")
                if parts:
                    hashes.add(parts[0].strip())
    except Exception:
        pass
    return hashes

def load_feodo_blocklist() -> set:
    """Returns a set of active C2 IP address strings."""
    if not os.path.exists(FEODO_PATH):
        update_feed("feodo")
    if not os.path.exists(FEODO_PATH):
        return set()
    try:
        with open(FEODO_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return {entry.get("ip_address", "") for entry in data if entry.get("ip_address")}
    except Exception:
        return set()


import re as _re

def add_feodo_entry(ip: str, malware: str = "Custom", status: str = "online") -> tuple[bool, str]:
    """
    Adds a custom IP entry to the Feodo blocklist.
    Returns (success, message).
    """
    _ensure_intel_dir()
    ip = ip.strip()
    # Basic IPv4 validation
    if not _re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
        return False, f"Invalid IP address format: {ip}"

    existing: list[dict] = []
    if os.path.exists(FEODO_PATH):
        try:
            existing = json.loads(open(FEODO_PATH, encoding="utf-8").read())
        except Exception:
            existing = []

    if any(e.get("ip_address") == ip for e in existing):
        return False, f"IP already exists in Feodo blocklist: {ip}"

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing.append({
        "ip_address":  ip,
        "port":        0,
        "status":      status,
        "malware":     malware,
        "country":     "Custom",
        "as_number":   "",
        "as_name":     "Manually Added",
        "first_seen":  now,
        "last_online": now,
        "_custom":     True,
    })
    try:
        with open(FEODO_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f)
        return True, f"Added {ip} to Feodo blocklist."
    except Exception as e:
        return False, f"Write error: {e}"


def add_ja3_entry(ja3_hash: str, family: str = "Custom") -> tuple[bool, str]:
    """
    Adds a custom JA3 fingerprint to the JA3 blocklist.
    Returns (success, message).
    """
    _ensure_intel_dir()
    ja3_hash = ja3_hash.strip().lower()
    if not _re.fullmatch(r"[0-9a-f]{32}", ja3_hash):
        return False, f"Invalid JA3 hash (must be 32-char MD5 hex): {ja3_hash}"

    if os.path.exists(JA3_PATH):
        try:
            for line in open(JA3_PATH, encoding="utf-8").read().splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                if line.split(",")[0].strip().lower() == ja3_hash:
                    return False, f"JA3 hash already exists in blocklist: {ja3_hash}"
        except Exception:
            pass

    now = datetime.datetime.now().strftime("%Y-%m-%d")
    line = f"{ja3_hash},{family},{now},{now},_custom"
    try:
        with open(JA3_PATH, "a", encoding="utf-8") as f:
            f.write("\n" + line)
        return True, f"Added {ja3_hash} to JA3 blocklist."
    except Exception as e:
        return False, f"Write error: {e}"

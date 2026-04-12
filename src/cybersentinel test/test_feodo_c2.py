# TEST 5: Feodo Tracker C2 IP Blocklist Detection
# Detected by: FeodoMonitor (c2_fingerprint.py) via intel/feodo_blocklist.json
# MITRE: T1071 — Application Layer Protocol
#        T1095 — Non-Application Layer Protocol
# ---------------------------------------------------------------
# Validates that FeodoMonitor.check_ip() correctly matches known
# botnet C2 IPs loaded from the abuse.ch Feodo Tracker feed.
#
# Two sub-tests:
#   A) Real C2 IPs from intel/feodo_blocklist.json  — must MATCH
#   B) Benign public IPs (DNS resolvers, CDNs)      — must NOT match
#
# Safe — check_ip() is a pure in-memory set lookup; no connections
# are made and no traffic is generated.

import os
import sys
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from modules.c2_fingerprint import FeodoMonitor

print("[*] TEST 5: Feodo Tracker C2 IP Blocklist")
print(f"[*] PID: {os.getpid()}")
print("[*] Loading FeodoMonitor (reads intel/feodo_blocklist.json) ...")
print()

monitor = FeodoMonitor(poll_interval=9999)   # Long interval — no background polling

# ── A: Pull real C2 IPs directly from the cached feed ───────────────────────
FEODO_PATH = os.path.join(ROOT, "intel", "feodo_blocklist.json")
KNOWN_C2: list[tuple[str, str]] = []

try:
    with open(FEODO_PATH, "r") as f:
        entries = json.load(f)
    # Pick up to 6 entries spanning different malware families
    seen_families: set[str] = set()
    for e in entries:
        family = e.get("malware", "Unknown")
        ip     = e.get("ip_address", "")
        if ip and family not in seen_families:
            KNOWN_C2.append((ip, family))
            seen_families.add(family)
        if len(KNOWN_C2) >= 6:
            break
    if not KNOWN_C2:
        # Fallback to first 6 IPs if family-dedup yielded nothing
        KNOWN_C2 = [(e["ip_address"], e.get("malware", "Unknown")) for e in entries[:6] if e.get("ip_address")]
except Exception as ex:
    print(f"[!] Could not read {FEODO_PATH}: {ex}")
    print("[!] Run Intel Update in the GUI first, then re-run this test.")
    sys.exit(1)

# ── B: Benign IPs that must not appear in the blocklist ─────────────────────
BENIGN_IPS = [
    ("8.8.8.8",        "Google Public DNS"),
    ("1.1.1.1",        "Cloudflare DNS"),
    ("208.67.222.222", "OpenDNS"),
    ("151.101.1.69",   "Fastly CDN"),
    ("127.0.0.1",      "Localhost"),
]

print("── Sub-test A: Blocklisted C2 IPs (must MATCH) ───────────────────────")
passed_a = 0
for ip, family in KNOWN_C2:
    result = monitor.check_ip(ip)
    status = "[+] MATCH  " if result else "[-] MISS   "
    outcome = "PASS" if result else "FAIL"
    print(f"  {status} {ip:<20} ({family})  → {outcome}")
    if result:
        passed_a += 1

print()
print("── Sub-test B: Benign IPs (must NOT match) ───────────────────────────")
passed_b = 0
for ip, label in BENIGN_IPS:
    result = monitor.check_ip(ip)
    status = "[-] CLEAN  " if not result else "[!] FALSE+ "
    outcome = "PASS" if not result else "FAIL"
    print(f"  {status} {ip:<20} ({label})  → {outcome}")
    if not result:
        passed_b += 1

print()
total_a = len(KNOWN_C2)
total_b = len(BENIGN_IPS)
print(f"[*] Sub-test A (C2 blocklist hits):  {passed_a}/{total_a} passed")
print(f"[*] Sub-test B (false positives):    {passed_b}/{total_b} passed")

if passed_a == total_a and passed_b == total_b:
    print("[✓] Feodo IP blocklist test PASSED — intel/feodo_blocklist.json is active.")
else:
    print("[✗] Feodo IP blocklist test had failures.")
    if passed_a < total_a:
        print("    → If Sub-test A fails, the feed may be stale. Re-run Intel Update.")

print()
print("[*] Live connection detection: start the daemon and open a socket to a C2 IP.")
print("[*] FeodoMonitor will alert within poll_interval seconds of ESTABLISHED state.")

# TEST 4: JA3 TLS Fingerprint Blocklist Detection
# Detected by: Ja3Monitor (c2_fingerprint.py) via intel/ja3_blocklist.csv
# MITRE: T1071.001 — Application Layer Protocol: Web Protocols
# ---------------------------------------------------------------
# Validates that Ja3Monitor.check_fingerprint() correctly matches
# known-malicious JA3 hashes loaded from the abuse.ch SSLBL feed.
#
# Two sub-tests:
#   A) Real blocklisted hashes from intel/ja3_blocklist.csv  — must MATCH
#   B) Benign browser fingerprints (Firefox/Chrome)          — must NOT match
#
# Safe — no network traffic is generated; all checks are in-memory
# lookups against the locally cached blocklist.

import os
import sys

# Run from the CyberSentinel project root
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from modules.c2_fingerprint import Ja3Monitor

print("[*] TEST 4: JA3 TLS Fingerprint Blocklist")
print(f"[*] PID: {os.getpid()}")
print("[*] Loading Ja3Monitor (reads intel/ja3_blocklist.csv) ...")
print()

monitor = Ja3Monitor()

# ── A: Known-malicious JA3 hashes from intel/ja3_blocklist.csv ──────────────
# These are the first entries in the cached abuse.ch SSLBL feed.
# Family labels are from the CSV comment column.
KNOWN_MALICIOUS = [
    ("b386946a5a44d1ddcc843bc75336dfce", "Dridex"),
    ("8991a387e4cc841740f25d6f5139f92d", "Adware"),
    ("cb98a24ee4b9134448ffb5714fd870ac", "Dridex"),
    ("1aa7bf8b97e540ca5edd75f7b8384bfa", "TrickBot"),
    ("3d89c0dfb1fa44911b8fa7523ef8dedb", "Adware"),
    ("8f52d1ce303fb4a6515836aec3cc16b1", "TrickBot"),
]

# ── B: Legitimate TLS fingerprints — should NOT trigger an alert ─────────────
# These represent typical browser TLS ClientHellos that are NOT in the blocklist.
BENIGN = [
    ("aaa152b2caba4bab5b3680a3d55b027b", "Firefox 102 baseline"),
    ("deadbeefdeadbeefdeadbeefdeadbeef", "synthetic non-existent hash"),
    ("00000000000000000000000000000000", "null hash sanity check"),
]

print("── Sub-test A: Blocklisted fingerprints (must MATCH) ─────────────────")
passed_a = 0
for ja3, label in KNOWN_MALICIOUS:
    result = monitor.check_fingerprint(ja3)
    status = "[+] MATCH  " if result else "[-] MISS   "
    outcome = "PASS" if result else "FAIL"
    print(f"  {status} {ja3}  ({label})  → {outcome}")
    if result:
        passed_a += 1

print()
print("── Sub-test B: Benign fingerprints (must NOT match) ──────────────────")
passed_b = 0
for ja3, label in BENIGN:
    result = monitor.check_fingerprint(ja3)
    status = "[-] CLEAN  " if not result else "[!] FALSE+ "
    outcome = "PASS" if not result else "FAIL"
    print(f"  {status} {ja3}  ({label})  → {outcome}")
    if not result:
        passed_b += 1

print()
total_a = len(KNOWN_MALICIOUS)
total_b = len(BENIGN)
print(f"[*] Sub-test A (blocklist hits):   {passed_a}/{total_a} passed")
print(f"[*] Sub-test B (false positives):  {passed_b}/{total_b} passed")

if passed_a == total_a and passed_b == total_b:
    print("[✓] JA3 blocklist test PASSED — intel/ja3_blocklist.csv is active.")
else:
    print("[✗] JA3 blocklist test had failures.")
    if passed_a < total_a:
        print("    → If Sub-test A fails, run Intel Update in the GUI to refresh the feed.")
    if passed_b < total_b:
        print("    → If Sub-test B fails, a benign hash was incorrectly added to the blocklist.")

print()
print("[*] Note: Ja3Monitor live packet capture requires scapy + Npcap.")
print("[*] check_fingerprint() is the in-memory path tested here — no sniffing needed.")

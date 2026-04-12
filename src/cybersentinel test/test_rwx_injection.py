# test_rwx_injection_correct.py
# Tests CyberSentinel's VirtualQueryEx-based memory scanner.
# Injects an anonymous RWX region into notepad.exe — a high-value
# non-JIT process — which is how real attackers (Cobalt Strike,
# Meterpreter) actually stage shellcode.
#
# Run: start notepad.exe first, then run this script as Administrator.
# Expected: [HIGH CONFIDENCE] alert in CyberSentinel within 30 seconds.

import ctypes
import ctypes.wintypes
import time
import os
import sys

MEM_COMMIT_RESERVE     = 0x3000
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS     = 0x1F0FFF

k32 = ctypes.windll.kernel32

def find_notepad_pid() -> int:
    import psutil
    for proc in psutil.process_iter(["name", "pid"]):
        if proc.info["name"].lower() == "notepad.exe":
            return proc.info["pid"]
    return 0

def main():
    print("[*] TEST: Cross-Process RWX Injection Simulation")
    print("[*] This is how Cobalt Strike and Meterpreter actually stage shellcode.")
    print()

    pid = find_notepad_pid()
    if not pid:
        print("[-] notepad.exe not found. Start notepad.exe first then re-run.")
        sys.exit(1)

    print(f"[*] Found notepad.exe — PID {pid}")
    print(f"[*] Opening process handle with PROCESS_ALL_ACCESS...")

    handle = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        err = k32.GetLastError()
        print(f"[-] OpenProcess failed (error {err}). Run as Administrator.")
        sys.exit(1)

    print(f"[*] Allocating anonymous RWX region in notepad.exe address space...")
    ptr = k32.VirtualAllocEx(
        handle,
        ctypes.c_int(0),
        ctypes.c_int(4096),
        MEM_COMMIT_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not ptr:
        print(f"[-] VirtualAllocEx failed (error {k32.GetLastError()}).")
        k32.CloseHandle(handle)
        sys.exit(1)

    print(f"[+] RWX region allocated in notepad.exe at: {hex(ptr)}")
    print(f"[*] Holding for 90s — CyberSentinel scanner interval is 30s.")
    print(f"[*] Watch for [HIGH CONFIDENCE] alert for notepad.exe in the daemon.")

    time.sleep(90)

    k32.VirtualFreeEx(handle, ctypes.c_void_p(ptr), 0, 0x8000)
    k32.CloseHandle(handle)
    print("[*] Memory freed. Handle closed. Test complete.")

if __name__ == "__main__":
    main()
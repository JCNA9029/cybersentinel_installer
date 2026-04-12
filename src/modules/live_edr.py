# This is the live EDR module that allows users to scan active processes in memory.
import os
import psutil

def get_target_process_path() -> str:
    """
    Enumerates non-system processes and returns the path of the user-selected PID.
    """
    print("\n--- Live Process Memory Triage ---")
    print("[*] Enumerating active processes...")

    suspicious_procs = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info['exe']
            if exe_path and "C:\\Windows" not in exe_path:
                suspicious_procs.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'path': exe_path
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if not suspicious_procs:
        print("[+] No non-system processes found. System appears clean.")
        return None

    print(f"\n{'PID':<10} | {'Process Name':<25} | {'Executable Path'}")
    print("-" * 80)

    for p in suspicious_procs[-20:]:
        display_path = p['path'] if len(p['path']) < 40 else "..." + p['path'][-37:]
        print(f"{p['pid']:<10} | {p['name']:<25} | {display_path}")

    choice = input("\n[?] Enter the PID of the process to scan (or press Enter to cancel): ").strip()
    if not choice.isdigit():
        return None

    target_pid = int(choice)

    for p in suspicious_procs:
        if p['pid'] == target_pid:
            if os.path.exists(p['path']):
                return p['path']

    print("[-] Invalid PID or the process terminated before scanning.")
    return None
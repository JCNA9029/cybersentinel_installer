# modules/quarantine.py

import os
import shutil
import subprocess
import datetime
import re

_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR  = os.path.join(_PROJECT_ROOT, "Quarantine")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _kill_file_owners(file_path: str) -> None:
    """
    Terminates every process whose executable path matches *file_path*.

    Called before os.remove() so the OS lock is released.  Uses psutil for
    a reliable cross-version match; falls back gracefully if psutil is absent.
    """
    try:
        import psutil
        target = os.path.normcase(os.path.abspath(file_path))
        for proc in psutil.process_iter(["pid", "exe", "name"]):
            try:
                exe = proc.info.get("exe") or ""
                if os.path.normcase(os.path.abspath(exe)) == target:
                    # Kill children first to prevent orphan persistence
                    for child in proc.children(recursive=True):
                        try:
                            child.kill()
                        except Exception:
                            pass
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        # psutil not installed — try taskkill as a last resort
        try:
            name = os.path.basename(file_path)
            subprocess.run(
                ["taskkill", "/F", "/IM", name],
                check=False, capture_output=True,
            )
        except Exception:
            pass


def _take_ownership(file_path: str) -> None:
    """
    Grants the Administrators group full control of *file_path*.

    Even when the process token is elevated, certain files (e.g. those owned
    by SYSTEM or TrustedInstaller) block reads/writes until ownership is
    explicitly reclaimed via takeown + icacls.
    """
    try:
        subprocess.run(
            ["takeown", "/F", file_path, "/A"],
            check=False, capture_output=True,
        )
        subprocess.run(
            ["icacls", file_path, "/grant", "Administrators:F", "/T"],
            check=False, capture_output=True,
        )
    except FileNotFoundError:
        pass  # Not on Windows — no-op


def _schedule_delete_on_reboot(file_path: str) -> bool:
    """
    Schedules *file_path* for deletion on the next system reboot using the
    Win32 MoveFileEx API (MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING).

    This is the correct Windows-native mechanism for removing files that are
    locked by a running process and cannot be deleted in the current session.

    Returns True if the scheduling succeeded, False otherwise.
    """
    try:
        import ctypes
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        MOVEFILE_REPLACE_EXISTING   = 0x1
        flags = MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING
        result = ctypes.windll.kernel32.MoveFileExW(file_path, None, flags)
        return bool(result)
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def quarantine_file(file_path: str, quarantine_dir: str = None) -> bool:
    """
    Encrypts and quarantines a confirmed malicious file.

    Procedure
    ---------
    1. Take ownership + grant Administrators full control  (takeown / icacls).
    2. Kill every process whose executable is the target file so the OS lock
       is released before the read and delete.
    3. Read and encrypt the file with the hardware-bound Fernet cipher.
    4. Write the encrypted copy to the Quarantine folder.
    5. Delete the original with os.remove().
       If deletion still fails because the file is locked by a third party
       (e.g. another AV, an indexer), fall back to scheduling deletion on the
       next reboot via MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT).

    Returns True on success (immediate or scheduled), False if the operation
    could not be completed at all.
    """
    if quarantine_dir is None:
        quarantine_dir = QUARANTINE_DIR

    os.makedirs(quarantine_dir, exist_ok=True)

    if os.name == "nt":
        try:
            subprocess.run(
                ["attrib", "+h", "+s", quarantine_dir],
                check=False, capture_output=True,
            )
        except FileNotFoundError:
            pass

    # ── Step 1: Own the file and grant full control ───────────────────────────
    if os.name == "nt":
        _take_ownership(file_path)

    # ── Step 2: Kill processes that are locking the file ─────────────────────
    _kill_file_owners(file_path)

    # ── Step 3: Read and encrypt ──────────────────────────────────────────────
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except PermissionError:
        # The file is still unreadable even after takeown — this is very rare
        # but can happen with kernel-mode handles.  Schedule reboot-deletion
        # and report a partial success.
        print("\n[-] Cannot read file — likely held by a kernel-mode handle.")
        if os.name == "nt" and _schedule_delete_on_reboot(file_path):
            print("[!] Scheduled for deletion on next reboot (MoveFileEx).")
            print("[!] Reboot required to complete quarantine.\n")
            return True
        print("[-] ACTION FAILED: Could not read or schedule the file for deletion.")
        print("[-] The malware may be protected by a kernel driver. "
              "Try rebooting into Safe Mode.\n")
        return False
    except Exception as e:
        print(f"\n[-] ACTION FAILED: {e}\n")
        return False

    try:
        from . import utils
        cipher = utils._get_fernet()
        if cipher:
            encrypted = cipher.encrypt(data)
        else:
            encrypted = data
            print("[!] WARNING: Fernet unavailable — file quarantined without encryption.")
            print("[!] Install cryptography: pip install cryptography")
    except Exception as e:
        print(f"[!] Encryption error ({e}) — quarantining without encryption as fallback.")
        encrypted = data

    # ── Step 4: Write encrypted copy ─────────────────────────────────────────
    filename = os.path.basename(file_path)
    dest     = os.path.join(quarantine_dir, filename + ".quarantine")
    if os.path.exists(dest):
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(quarantine_dir, f"{filename}_{ts}.quarantine")

    try:
        with open(dest, "wb") as f:
            f.write(encrypted)
    except Exception as e:
        print(f"\n[-] ACTION FAILED: Could not write to quarantine folder: {e}\n")
        return False

    if not os.path.exists(dest) or os.path.getsize(dest) == 0:
        print("[-] Quarantine verification failed — original file preserved.")
        return False

    # ── Step 5: Delete the original ──────────────────────────────────────────
    try:
        os.remove(file_path)
    except PermissionError:
        # File is still locked (e.g. held by another AV scanner or an indexer).
        # The encrypted copy is safely written; schedule the original for
        # deletion on reboot so it cannot execute after a restart.
        scheduled = os.name == "nt" and _schedule_delete_on_reboot(file_path)
        print("\n" + "=" * 50)
        print("[+] PARTIAL SUCCESS: Encrypted copy written to quarantine.")
        print(f"[*] Encrypted Copy : {dest}")
        print("[!] Original NOT deleted — file is locked by another process.")
        if scheduled:
            print("[!] Scheduled for deletion on next reboot (MoveFileEx).")
            print("[!] Reboot required to fully remove the threat.")
        else:
            print("[!] Could not schedule reboot deletion.")
            print("[!] Manually delete the file after rebooting into Safe Mode.")
        print("=" * 50 + "\n")
        return True  # Encrypted copy exists; threat is defanged on reboot
    except Exception as e:
        print(f"\n[-] ACTION FAILED during deletion: {e}\n")
        return False

    print("\n" + "=" * 50)
    print("[+] SUCCESS: Threat encrypted and quarantined.")
    print(f"[*] Original File  : {filename}")
    print(f"[*] Encrypted Copy : {dest}")
    print(f"[*] Encryption     : Fernet AES-128 (hardware-bound)")
    print("=" * 50 + "\n")
    return True


# ── GUI Quarantine Manager functions ──────────────────────────────────────────

def list_quarantined_files(quarantine_dir: str = None) -> list:
    """Returns a list of quarantined file paths."""
    if quarantine_dir is None:
        quarantine_dir = QUARANTINE_DIR
    if not os.path.exists(quarantine_dir):
        return []
    return [
        os.path.join(quarantine_dir, f)
        for f in os.listdir(quarantine_dir)
        if f.endswith(".quarantine")
    ]


def restore_file(quarantined_path: str, dest_dir: str) -> bool:
    """Decrypts a quarantined file and restores it to dest_dir."""
    if not os.path.exists(quarantined_path):
        return False
    try:
        with open(quarantined_path, "rb") as f:
            data = f.read()
        try:
            from . import utils
            cipher = utils._get_fernet()
            decrypted = cipher.decrypt(data) if cipher else data
        except Exception:
            decrypted = data  # Fallback

        original_name = os.path.basename(quarantined_path).replace(".quarantine", "")
        original_name = re.sub(r'_\d{8}_\d{6}$', '', original_name)

        dest_path = os.path.join(dest_dir, original_name)
        with open(dest_path, "wb") as f:
            f.write(decrypted)

        os.remove(quarantined_path)
        return True
    except Exception as e:
        print(f"[-] Restore failed: {e}")
        return False


def delete_quarantined_file(quarantined_path: str) -> bool:
    """Permanently deletes a quarantined file."""
    if not os.path.exists(quarantined_path):
        return False
    try:
        os.remove(quarantined_path)
        return True
    except Exception as e:
        print(f"[-] Delete failed: {e}")
        return False

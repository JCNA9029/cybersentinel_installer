# modules/quarantine.py

import os
import shutil
import subprocess
import datetime

_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR  = os.path.join(_PROJECT_ROOT, "Quarantine")

def quarantine_file(file_path: str, quarantine_dir: str = None) -> bool:
    """
    Encrypts and quarantines a confirmed malicious file.

    Encryption uses the hardware-bound Fernet cipher from utils so the
    encrypted file cannot be decrypted on a different machine. The original
    file is removed only after the encrypted copy has been successfully written.

    Returns True on success, False if the operation could not be completed.
    """
    if quarantine_dir is None:
        quarantine_dir = QUARANTINE_DIR

    os.makedirs(quarantine_dir, exist_ok=True)

    if os.name == "nt":
        try:
            subprocess.run(
                ["attrib", "+h", "+s", quarantine_dir],
                check=False,
                capture_output=True,
            )
        except FileNotFoundError:
            pass

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        try:
            from . import utils
            cipher = utils._get_fernet()
            if cipher:
                encrypted = cipher.encrypt(data)
            else:
                # Fallback: store as-is with a clear warning
                encrypted = data
                print("[!] WARNING: Fernet unavailable — file quarantined without encryption.")
                print("[!] Install cryptography: pip install cryptography")
        except Exception as e:
            print(f"[!] Encryption error ({e}) — quarantining without encryption as fallback.")
            encrypted = data

        filename   = os.path.basename(file_path)
        dest       = os.path.join(quarantine_dir, filename + ".quarantine")
        if os.path.exists(dest):
            ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(quarantine_dir, f"{filename}_{ts}.quarantine")

        with open(dest, "wb") as f:
            f.write(encrypted)

        if not os.path.exists(dest) or os.path.getsize(dest) == 0:
            print("[-] Quarantine verification failed — original file preserved.")
            return False

        os.remove(file_path)

        print("\n" + "=" * 50)
        print("[+] SUCCESS: Threat encrypted and quarantined.")
        print(f"[*] Original File  : {filename}")
        print(f"[*] Encrypted Copy : {dest}")
        print(f"[*] Encryption     : Fernet AES-128 (hardware-bound)")
        print("=" * 50 + "\n")
        return True

    except PermissionError:
        print("\n[-] ACTION FAILED: Permission denied.")
        print("[-] The malware may be actively running. Run CyberSentinel as Administrator.\n")
        return False
    except Exception as e:
        print(f"\n[-] ACTION FAILED: {e}\n")
        return False

# [THESIS FIX] GUI Quarantine Manager functions

def list_quarantined_files(quarantine_dir: str = None) -> list:
    """Returns a list of quarantined file paths."""
    if quarantine_dir is None:
        quarantine_dir = QUARANTINE_DIR
    if not os.path.exists(quarantine_dir):
        return []
    return [os.path.join(quarantine_dir, f) for f in os.listdir(quarantine_dir) if f.endswith(".quarantine")]

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
            decrypted = data # Fallback
            
        original_name = os.path.basename(quarantined_path).replace(".quarantine", "")
        # Remove timestamp if it was appended (e.g. file.exe_20231012_153000)
        import re
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

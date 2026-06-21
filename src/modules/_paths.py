# modules/_paths.py

import os
from pathlib import Path

def _resolve_install_dir() -> Path:
    """Return the CyberSentinel root directory."""

    # 1. Registry — set by installer, works regardless of launch location
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\CyberSentinel",
            0,
            winreg.KEY_READ,
        )
        val, _ = winreg.QueryValueEx(key, "InstallDir")
        winreg.CloseKey(key)
        candidate = Path(val)
        if candidate.is_dir():
            return candidate
    except Exception:
        pass  # registry key absent (dev machine / non-installed run)

    # 2. __file__-relative fallback (modules/ -> src/)
    return Path(__file__).resolve().parent.parent

# Public constants — import these instead of recomputing paths
INSTALL_DIR  = _resolve_install_dir()
MODELS_DIR   = INSTALL_DIR / "models"
CONFIG_FILE  = INSTALL_DIR / "config.json"
DB_FILE      = INSTALL_DIR / "threat_cache.db"

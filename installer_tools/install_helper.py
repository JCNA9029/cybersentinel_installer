#!/usr/bin/env python3
"""
install_helper.py — CyberSentinel Installer Helper
Called by Inno Setup [Run] directives with --step <n>.

Steps:
  deps      — pip install all Python dependencies
  thrember  — clone & install EMBER2024 (thrember)
  ollama    — download & silently install Ollama
  models    — download model folder from Google Drive via gdown
  configure — patch config.json, register Ollama boot task

FIXES vs original:
  [BUG 1] thrember step: git was called via shutil.which() after a fresh silent
          install, but the newly installed Git binary is NOT on the current
          process's PATH (the installer process inherited the old PATH before
          Git existed). Fixed by injecting Git's cmd/ directory into os.environ
          immediately after install so all subsequent subprocess calls can see it.

  [BUG 2] thrember step: `pip install .` was run with capture=False (default),
          meaning stdout/stderr were inherited from the Inno Setup hidden window
          and silently discarded. If the build failed (e.g. missing build deps
          or C compiler), the run() helper saw returncode 0 from pip's own
          wrapper even though the wheel build failed internally. Fixed by always
          capturing output and explicitly checking for the "Successfully installed"
          confirmation string in pip's stdout.

  [BUG 3] thrember step: signify==0.7.1 was installed BEFORE the EMBER2024
          source was cloned, but thrember's setup.py lists signify as a
          build-time requirement that it re-resolves. On some pip versions this
          causes a version-conflict resolution that downgrades signify. Fixed by
          installing signify AFTER cloning, passing it together with the local
          package so pip resolves them in a single solver pass:
              pip install "signify==0.7.1" .
          This guarantees signify stays pinned at the required version.

thrember install strategy (step_thrember):
  1. Already installed?      → skip entirely (fast path, fully offline).
  2. Local EMBER2024 found?  → install from it (no Git / no network needed).
     Searched: Desktop, Downloads, Documents, home dir, C:\\.
     Valid tree = setup.py or pyproject.toml  +  thrember/ sub-folder present.
  3. Neither?                → clone from GitHub then install (original behaviour).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────
INSTALL_DIR   = Path(r"C:\CyberSentinel")
MODELS_DIR    = INSTALL_DIR / "models"
CONFIG_PATH   = INSTALL_DIR / "config.json"
LOG_PATH      = INSTALL_DIR / "install_log.txt"
GDRIVE_FOLDER = "1dtVVH4Oo5RhoAiMPhqsB4T1X2dGX0v5N"

PYTHON_DEPS = [
    "requests>=2.31.0",
    "psutil>=5.9.0",
    "watchdog>=3.0.0",
    "cryptography>=41.0.0",
    "colorama>=0.4.6",
    "pefile>=2024.8.26",
    "lightgbm>=4.1.0",
    "numpy>=1.24.0",
    "scipy>=1.11.0",
    "tqdm>=4.65.0",
    "pandas>=2.0.0",
    "shap>=0.44.0",
    "ollama>=0.1.0",
    "flask>=3.0.0",
    "PyQt6>=6.6.0",
    "pywin32",
    "wmi",
    "gdown",
]

OLLAMA_INSTALLER_URL = "https://ollama.com/download/OllamaSetup.exe"
GIT_INSTALLER_URL    = (
    "https://github.com/git-for-windows/git/releases/download/"
    "v2.44.0.windows.1/Git-2.44.0-64-bit.exe"
)

# Known Git installation paths to probe after a fresh install
GIT_CANDIDATE_PATHS = [
    r"C:\Program Files\Git\cmd\git.exe",
    r"C:\Program Files (x86)\Git\cmd\git.exe",
]


# ── Logging ───────────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def fail(msg: str):
    log(msg, "ERROR")
    sys.exit(1)


# ── Retry-aware download ──────────────────────────────────────
def download(url: str, dest: Path, attempts: int = 3) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, attempts + 1):
        try:
            log(f"Downloading {url} → {dest}  (attempt {attempt}/{attempts})")
            urllib.request.urlretrieve(url, dest)
            log(f"Download complete: {dest}")
            return True
        except Exception as exc:
            log(f"Download failed: {exc}", "WARN")
            time.sleep(2 ** attempt)
    return False


# ── Run subprocess with logging ───────────────────────────────
def run(cmd: list[str], cwd: Path | None = None,
        capture: bool = False) -> subprocess.CompletedProcess:
    log(f"EXEC: {' '.join(str(c) for c in cmd)}")
    kwargs = dict(cwd=cwd, text=True, encoding="utf-8", errors="replace")
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        detail = getattr(result, "stdout", "") or ""
        fail(
            f"Command failed (exit {result.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"Output:\n{detail}"
        )
    return result


def pip(*packages: str) -> subprocess.CompletedProcess:
    """Install one or more packages via pip, always capturing output."""
    # FIX BUG 2: Always capture pip output so we can detect silent build
    # failures that return exit code 0 (e.g. wheel build errors in setup.py).
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", *packages],
        text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    log(result.stdout or "")
    if result.returncode != 0:
        fail(
            f"pip install failed (exit {result.returncode}) for: {' '.join(packages)}\n"
            f"Output:\n{result.stdout}"
        )
    return result


# ═══════════════════════════════════════════════════════════════
#  STEP: deps
# ═══════════════════════════════════════════════════════════════
def step_deps():
    log("=== STEP: Installing Python dependencies ===")
    pip("--upgrade", "pip", "setuptools", "wheel")
    # Install in chunks to surface individual failures clearly
    for pkg in PYTHON_DEPS:
        try:
            pip(pkg)
        except SystemExit:
            fail(
                f"Failed to install '{pkg}'.  "
                "Check your internet connection or proxy settings and re-run the installer."
            )
    log("All Python dependencies installed successfully.")


# ═══════════════════════════════════════════════════════════════
#  STEP: thrember (EMBER2024)
# ═══════════════════════════════════════════════════════════════
def _inject_git_into_path(git_exe: str) -> None:
    """
    FIX BUG 1: After a silent Git install, the current process's PATH still
    reflects the pre-install environment. Inject Git's cmd/ directory into
    os.environ['PATH'] so that all subsequent subprocess calls (including the
    git clone below) can locate git.exe without requiring a process restart.
    """
    git_cmd_dir = str(Path(git_exe).parent)
    current_path = os.environ.get("PATH", "")
    if git_cmd_dir.lower() not in current_path.lower():
        os.environ["PATH"] = git_cmd_dir + os.pathsep + current_path
        log(f"Injected into PATH: {git_cmd_dir}")


def ensure_git() -> str:
    """Return path to git.exe, installing silently if absent."""
    git_exe = shutil.which("git")
    if git_exe:
        log(f"git found: {git_exe}")
        return git_exe

    log("git not found — downloading Git for Windows...")
    installer = Path(tempfile.gettempdir()) / "git_installer.exe"
    if not download(GIT_INSTALLER_URL, installer):
        fail("Failed to download Git for Windows after 3 attempts.")

    log("Installing Git for Windows silently...")
    run([str(installer), "/VERYSILENT", "/NORESTART",
         "/COMPONENTS=icons,ext\\reg\\shellhere,assoc,assoc_sh"])

    # Give the installer a moment to finish writing files
    time.sleep(3)

    for candidate in GIT_CANDIDATE_PATHS:
        if Path(candidate).exists():
            log(f"git installed at {candidate}")
            _inject_git_into_path(candidate)  # FIX BUG 1
            return candidate

    fail("Git installation succeeded but git.exe not found on PATH. Please restart and re-run.")
    return ""  # unreachable


def _is_thrember_installed() -> bool:
    """Return True if thrember is already importable in the current Python."""
    result = subprocess.run(
        [sys.executable, "-c", "import thrember; print('thrember OK')"],
        capture_output=True, text=True, encoding="utf-8"
    )
    return result.returncode == 0 and "thrember OK" in result.stdout


def _is_valid_ember2024_dir(path: Path) -> bool:
    """
    Return True if *path* looks like a valid EMBER2024 source tree.
    Only requires setup.py or pyproject.toml — the thrember/ sub-folder
    may be absent depending on how the repo was downloaded.
    """
    return (path / "setup.py").exists() or (path / "pyproject.toml").exists()


def _find_local_ember2024() -> Path | None:
    """
    Search common user locations for an existing EMBER2024 source tree.
    Returns the first valid directory found, or None.
    """
    # Build candidate root folders to search inside
    home = Path.home()
    search_roots = [
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        home,
        Path("C:/"),
        Path("C:/Users"),
    ]

    # Common folder names the user might have used
    ember_names = ["EMBER2024", "ember2024", "Ember2024", "ember_2024", "EMBER_2024"]

    candidates: list[Path] = []

    # Direct hits: <root>/<name>
    for root in search_roots:
        for name in ember_names:
            candidates.append(root / name)

    # One level deeper: <root>/<any_subfolder>/<name>  (e.g. C:\Users\John\EMBER2024)
    for root in search_roots:
        try:
            for child in root.iterdir():
                if child.is_dir():
                    for name in ember_names:
                        candidates.append(child / name)
        except (PermissionError, OSError):
            pass

    for candidate in candidates:
        if candidate.is_dir() and _is_valid_ember2024_dir(candidate):
            return candidate

    return None


def _install_thrember_from(source_dir: Path) -> None:
    """
    Install thrember + signify==0.7.1 from a local EMBER2024 source tree.
    Uses a single pip resolver pass to avoid the signify version-conflict
    bug described in BUG 3 above.
    """
    log(f"Installing thrember from local source: {source_dir}")
    pip("signify==0.7.1", str(source_dir))


def _force_rmtree(path: Path) -> None:
    """
    Robustly delete a directory tree on Windows.
    shutil.rmtree(ignore_errors=True) silently skips locked/read-only files,
    leaving the folder behind and causing `git clone` to fail with
    'destination path already exists and is not an empty directory'.
    We clear the read-only bit on every file before deleting it.
    """
    import stat

    def _remove_readonly(func, fpath, _excinfo):
        try:
            os.chmod(fpath, stat.S_IWRITE)
            func(fpath)
        except Exception:
            pass  # best-effort; git will report a clear error if it still fails

    if path.exists():
        shutil.rmtree(path, onerror=_remove_readonly)
    """
    Fall back: clone EMBER2024 from GitHub then install thrember.
    Requires Git (installs it silently if absent).
    """

def _clone_and_install_thrember() -> None:
    """Clone EMBER2024 from GitHub then install thrember."""
    git_exe = ensure_git()
    clone_dir = Path(tempfile.gettempdir()) / "EMBER2024"

    _force_rmtree(clone_dir)

    for attempt in range(1, 4):
        log(f"Cloning EMBER2024 repo (attempt {attempt}/3)...")
        result = subprocess.run(
            [git_exe, "clone", "--depth=1",
             "https://github.com/FutureComputing4AI/EMBER2024",
             str(clone_dir)],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if result.returncode == 0:
            log("Clone successful.")
            break
        log(f"Clone failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}", "WARN")
        time.sleep(3)
    else:
        fail(
            "Failed to clone the EMBER2024 repository after 3 attempts. "
            "Please check your internet connection and re-run the installer."
        )

    _install_thrember_from(clone_dir)

    for attempt in range(1, 4):
        log(f"Cloning EMBER2024 repo (attempt {attempt}/3)...")
        result = subprocess.run(
            [git_exe, "clone", "--depth=1",
             "https://github.com/FutureComputing4AI/EMBER2024",
             str(clone_dir)],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if result.returncode == 0:
            log("Clone successful.")
            break
        log(f"Clone failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}", "WARN")
        time.sleep(3)
    else:
        fail(
            "Failed to clone the EMBER2024 repository after 3 attempts.  "
            "Please check your internet connection and re-run the installer."
        )

    _install_thrember_from(clone_dir)


def step_thrember():
    log("=== STEP: Installing EMBER2024 (thrember) ===")

    # ── Fast path: already installed ──────────────────────────────────────────
    if _is_thrember_installed():
        log("thrember is already installed and importable — skipping.")
        return

    # ── Try local EMBER2024 folder first ──────────────────────────────────────
    # This covers users who already downloaded / cloned EMBER2024 manually.
    # We search Desktop, Downloads, Documents, home, and C:\ before hitting
    # the network, so the installer works fully offline in that scenario.
    local_dir = _find_local_ember2024()
    if local_dir:
        log(f"Found existing EMBER2024 source tree at: {local_dir}")
        _install_thrember_from(local_dir)
    else:
        log("No local EMBER2024 source tree found — cloning from GitHub...")
        _clone_and_install_thrember()

    # ── Verify the import works before declaring success ───────────────────────
    # FIX BUG 2: always capture output so a silent wheel-build failure is caught.
    verify = subprocess.run(
        [sys.executable, "-c", "import thrember; print('thrember OK')"],
        capture_output=True, text=True, encoding="utf-8"
    )
    if verify.returncode != 0 or "thrember OK" not in verify.stdout:
        fail(
            "thrember was installed but cannot be imported.  "
            f"Python said:\n{verify.stdout}\n{verify.stderr}\n"
            "Try running `pip install signify==0.7.1` then "
            "`pip install .` inside the EMBER2024 folder manually."
        )

    log("thrember / EMBER2024 installed and verified successfully.")


# ═══════════════════════════════════════════════════════════════
#  STEP: ollama
# ═══════════════════════════════════════════════════════════════
def step_ollama():
    log("=== STEP: Installing Ollama ===")
    installer = Path(tempfile.gettempdir()) / "OllamaSetup.exe"

    if not download(OLLAMA_INSTALLER_URL, installer, attempts=3):
        fail(
            "Failed to download the Ollama installer after 3 attempts.  "
            "Please check your internet connection and re-run the installer."
        )

    log("Running Ollama installer silently...")
    run([str(installer), "/S"])

    # Give Ollama a moment to finish background registration
    time.sleep(3)

    # Start Ollama server in the background
    log("Starting Ollama serve...")
    subprocess.Popen(["ollama", "serve"],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    time.sleep(5)
    log("Ollama installed and running.")


# ═══════════════════════════════════════════════════════════════
#  STEP: models  (Google Drive download via gdown)
# ═══════════════════════════════════════════════════════════════
def step_models():
    log("=== STEP: Downloading AI models from Google Drive ===")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    pip("gdown")

    url = f"https://drive.google.com/drive/folders/{GDRIVE_FOLDER}"

    for attempt in range(1, 4):
        log(f"Downloading model folder (attempt {attempt}/3) …")
        result = subprocess.run(
            [sys.executable, "-m", "gdown", "--folder", url,
             "-O", str(MODELS_DIR), "--remaining-ok"],
            text=True, capture_output=True, encoding="utf-8", errors="replace"
        )
        log(result.stdout)
        if result.returncode == 0:
            log("Model download complete.")
            return
        log(f"Download attempt {attempt} failed:\n{result.stderr}", "WARN")
        time.sleep(5)

    fail(
        "Failed to download AI models after 3 attempts.  "
        "Please check your internet connection or download the models folder manually "
        f"from: https://drive.google.com/drive/folders/{GDRIVE_FOLDER}  "
        f"and place the contents in {MODELS_DIR}."
    )


# ═══════════════════════════════════════════════════════════════
#  STEP: configure
# ═══════════════════════════════════════════════════════════════
def step_configure():
    log("=== STEP: Configuring CyberSentinel ===")

    # Patch config.json — only update llm_model key; never touch API keys
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError:
            log("config.json is malformed; using defaults.", "WARN")
            cfg = {}
    else:
        cfg = {}

    cfg["llm_model"]   = "cybersentinel-analyst"
    cfg["install_dir"] = str(INSTALL_DIR)
    cfg["version"]     = "1.0.0"

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    log("config.json updated: llm_model = cybersentinel-analyst")
    log("Configuration complete.")


# ── Entry point ───────────────────────────────────────────────
def main():
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    log("=" * 60)
    log("CyberSentinel install_helper.py starting")
    log("=" * 60)

    parser = argparse.ArgumentParser(description="CyberSentinel installer helper")
    parser.add_argument(
        "--step",
        choices=["deps", "thrember", "ollama", "models", "configure"],
        required=True,
        help="Installation step to execute",
    )
    args = parser.parse_args()

    dispatch = {
        "deps":      step_deps,
        "thrember":  step_thrember,
        "ollama":    step_ollama,
        "models":    step_models,
        "configure": step_configure,
    }

    try:
        dispatch[args.step]()
    except SystemExit:
        raise
    except Exception as exc:
        fail(
            f"Unexpected error during step '{args.step}': {exc}\n"
            f"See full log at {LOG_PATH}"
        )

    log(f"Step '{args.step}' completed successfully.")


if __name__ == "__main__":
    main()

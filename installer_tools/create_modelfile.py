#!/usr/bin/env python3
"""
create_modelfile.py — CyberSentinel Installer Helper
Creates the Ollama Modelfile for the CyberSentinel AI Analyst and
imports the GGUF model into the running Ollama instance.

Expected GGUF location:
    C:\\CyberSentinel\\models\\CyberSentinel-Analyst.gguf
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────
INSTALL_DIR   = Path(r"C:\CyberSentinel")
MODELS_DIR    = INSTALL_DIR / "models"
GGUF_FILE     = MODELS_DIR / "CyberSentinel-Analyst.gguf"
MODELFILE     = INSTALL_DIR / "Modelfile"
CONFIG_PATH   = INSTALL_DIR / "config.json"
LOG_PATH      = INSTALL_DIR / "install_log.txt"
MODEL_NAME    = "cybersentinel-analyst"

# Known Ollama installation paths — ollama.exe is NOT on PATH right after
# a fresh silent install, so we probe known locations before falling back.
OLLAMA_CANDIDATE_PATHS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"),
    r"C:\Program Files\Ollama\ollama.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Ollama\ollama.exe"),
]


def find_ollama_exe() -> str:
    """Return the full path to ollama.exe, probing known locations first."""
    for candidate in OLLAMA_CANDIDATE_PATHS:
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which("ollama")
    if found:
        return found
    return "ollama"  # last resort

# ── System prompt (exactly as specified) ─────────────────────
SYSTEM_PROMPT = (
    'You are a Tier 3 Malware Research Lead. '
    'Output ONLY dense, technical, forensic-grade reports. '
    'STRICT RULES: '
    'ZERO conversational filler. '
    'DO NOT default to T1055 for everything. '
    'Map accurately (e.g., T1082 for Discovery, T1112 for Registry, T1105 for Staging). '
    'Explain the LOGICAL CHAIN (how API A enables API B). '
    'YARA rules MUST include hexadecimal sequences or specific non-standard strings. '
    'Tone: Cold, analytical, and highly technical.'
)

MODELFILE_CONTENT = f"""\
FROM {GGUF_FILE}
SYSTEM \"\"\"{SYSTEM_PROMPT}\"\"\"
PARAMETER temperature 0.1
PARAMETER num_ctx     4096
PARAMETER stop        "<|im_end|>"
PARAMETER stop        "<|endoftext|>"
"""


def log(msg: str, level: str = "INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def fail(msg: str):
    log(msg, "ERROR")
    # Write a sentinel file so Inno Setup can detect failure
    (INSTALL_DIR / "MODELFILE_ERROR.txt").write_text(msg, encoding="utf-8")
    sys.exit(1)


def ensure_ollama_running():
    """Start ollama serve if it's not already listening."""
    ollama_exe = find_ollama_exe()
    log(f"Using ollama at: {ollama_exe}")
    log("Checking if Ollama is running...")
    result = subprocess.run(
        [ollama_exe, "list"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log("Ollama not responding — starting ollama serve...")
        subprocess.Popen(
            [ollama_exe, "serve"],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for _ in range(15):
            time.sleep(2)
            r = subprocess.run([ollama_exe, "list"], capture_output=True)
            if r.returncode == 0:
                log("Ollama is now running.")
                return
        fail(
            "Ollama did not start within 30 seconds.  "
            "Please start Ollama manually (run 'ollama serve' in a terminal) "
            "and then re-run the installer."
        )
    else:
        log("Ollama is running.")


def write_modelfile():
    log(f"Writing Modelfile to {MODELFILE} ...")
    MODELFILE.write_text(MODELFILE_CONTENT, encoding="utf-8")
    log("Modelfile written.")


def import_model():
    """Run: ollama create <name> -f <Modelfile>"""
    log(f"Importing '{MODEL_NAME}' into Ollama — this may take several minutes...")
    log(f"  GGUF source : {GGUF_FILE}")
    log(f"  Modelfile   : {MODELFILE}")

    for attempt in range(1, 4):
        log(f"  Attempt {attempt}/3 ...")
        result = subprocess.run(
            [find_ollama_exe(), "create", MODEL_NAME, "-f", str(MODELFILE)],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        log(f"  stdout: {result.stdout.strip()}")
        if result.returncode == 0:
            log(f"Model '{MODEL_NAME}' imported successfully.")
            return
        log(f"  Import attempt {attempt} failed:\n{result.stderr.strip()}", "WARN")
        time.sleep(5)

    fail(
        f"Failed to import the model after 3 attempts.  "
        f"Please run the following command manually after install:\n"
        f"  ollama create {MODEL_NAME} -f \"{MODELFILE}\""
    )


def patch_config():
    """Set llm_model in config.json without touching other keys."""
    cfg: dict = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log("config.json parse error — using defaults.", "WARN")

    cfg["llm_model"] = MODEL_NAME
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    log(f"config.json → llm_model = {MODEL_NAME}")


def verify_model():
    """Confirm the model appears in 'ollama list'."""
    result = subprocess.run(
        [find_ollama_exe(), "list"], capture_output=True, text=True, encoding="utf-8"
    )
    if MODEL_NAME in result.stdout:
        log(f"Verification passed: '{MODEL_NAME}' found in ollama list.")
    else:
        log(
            f"WARNING: '{MODEL_NAME}' not found in ollama list output.  "
            "The model import may have failed silently.",
            "WARN"
        )


def main():
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    log("=" * 60)
    log("create_modelfile.py — CyberSentinel LLM import")
    log("=" * 60)

    # Sanity check
    if not GGUF_FILE.exists():
        fail(
            f"GGUF file not found: {GGUF_FILE}\n"
            "Ensure the model download step completed successfully before this step."
        )

    ensure_ollama_running()
    write_modelfile()
    import_model()
    patch_config()
    verify_model()

    log("create_modelfile.py completed successfully.")


if __name__ == "__main__":
    main()

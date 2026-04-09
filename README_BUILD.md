# CyberSentinel Installer — Build Guide

> **Target:** Windows 10/11 x64  
> **Output:** `CyberSentinel_Setup.exe` (< 50 MB — models downloaded at runtime)

---

## Prerequisites (developer machine only)

| Tool | Version | Download |
|------|---------|----------|
| Inno Setup | 6.3+ | https://jrsoftware.org/isdl.php |
| Python | 3.12.x | https://python.org |

No other tools are required. The installer handles all end-user dependencies automatically.

---

## Repository layout expected by the .iss script

```
project_root/
├── CyberSentinel_Setup.iss       ← main Inno Setup script
├── LICENSE.txt                   ← required by Inno Setup
├── installer_tools/
│   ├── install_helper.py
│   ├── create_modelfile.py
│   └── check_python.bat
├── assets/
│   ├── icon.ico                  ← 256×256 app icon
│   ├── wizard_banner.bmp         ← 497×314 px, dark-themed splash
│   └── wizard_small.bmp          ← 55×58 px, top-right branding
└── src/                          ← entire CyberSentinel source tree
    ├── CyberSentinel.py
    ├── gui.py
    ├── dashboard.py
    ├── eval_harness.py
    ├── config.json               ← default config (no real API keys)
    ├── requirements.txt
    ├── exclusions.txt
    ├── modules/
    │   └── *.py
    ├── data/
    ├── intel/
    └── Analysis Files/
```

> **Do NOT** include the `models/` folder in `src/`. Models are downloaded from  
> Google Drive at install time (step 7).

---

## Creating the wizard images (optional but recommended)

Use any image editor:

- `wizard_banner.bmp` — 497 × 314 pixels, 24-bit BMP  
  _Tip: dark background (#0d1117) with the CyberSentinel logo centred_
- `wizard_small.bmp` — 55 × 58 pixels, 24-bit BMP  
  _Just the logo mark on a matching background_

If you omit them, Inno Setup uses its built-in defaults.

---

## Compiling the installer

### Option A — GUI (Inno Setup IDE)

1. Open **Inno Setup Compiler** (installed with Inno Setup).
2. `File → Open` → select `CyberSentinel_Setup.iss`.
3. Press **F9** or `Build → Compile`.
4. The output `CyberSentinel_Setup.exe` appears in `Output\`.

### Option B — Command line (CI/CD)

```bat
REM Add Inno Setup to PATH first, or use the full path:
set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

%ISCC% CyberSentinel_Setup.iss
```

Expected output:
```
Compiler: Inno Setup version 6.3.x
...
Successful compile (0.xx sec). 
Output file: Output\CyberSentinel_Setup.exe
```

---

## What happens when the end user runs the installer

| # | Step | Visible label in wizard |
|---|------|-------------------------|
| 1 | Check / silently install Python 3.12 | *"Checking Python 3.12..."* |
| 2 | `pip install` all dependencies | *"Installing Python dependencies..."* |
| 3 | Clone + `pip install` EMBER2024 (thrember) | *"Installing EMBER2024..."* |
| 4 | Download + silently install Ollama | *"Installing Ollama..."* |
| 5 | Download models folder from Google Drive | *"Downloading AI models (~4.5 GB)..."* |
| 6 | Write Modelfile, `ollama create` | *"Importing CyberSentinel AI Analyst..."* |
| 7 | Patch `config.json`, scheduled task | *"Finalising configuration..."* |
| 8 | Create shortcuts | (handled by Inno Setup automatically) |

Total install time on a typical home connection: **10–20 minutes** (dominated by model download).

---

## Installer helper scripts reference

### `install_helper.py`

```
python install_helper.py --step <name>
```

| `--step` | Action |
|----------|--------|
| `deps` | pip-installs all runtime dependencies |
| `thrember` | Installs Git if absent, clones EMBER2024, `pip install .` |
| `ollama` | Downloads OllamaSetup.exe, runs silent install, starts `ollama serve` |
| `models` | Uses `gdown` to download the Google Drive models folder |
| `configure` | Patches `config.json` with correct `llm_model` key |

All steps write to `C:\CyberSentinel\install_log.txt`.  
On failure each step exits with code 1 and a human-readable message.

### `create_modelfile.py`

Standalone script (no `--step` argument) that:
1. Starts Ollama if not already running.
2. Writes `C:\CyberSentinel\Modelfile` with the correct `FROM` path and `SYSTEM` prompt.
3. Runs `ollama create cybersentinel-analyst -f Modelfile`.
4. Patches `config.json → llm_model`.
5. Verifies the model appears in `ollama list`.

### `check_python.bat`

Returns `ERRORLEVEL 0` if Python 3.12.x is on `%PATH%`, else `1`.  
Used by Inno Setup's `PrepareToInstall` Pascal code section to decide  
whether to silently download the Python installer.

---

## Re-installing / upgrading

- **config.json is preserved**: The Inno Setup Pascal code backs up `config.json`  
  before copying new files and restores it afterwards, so your API keys are never  
  overwritten.
- **Models are preserved**: The uninstaller asks before deleting the `models/` folder,  
  so you can skip the 4.5 GB download on a reinstall.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Installer hangs on "Downloading models" | Slow connection or Drive quota | Let it run; retry if it errors after 3 attempts |
| `ollama: command not found` after install | PATH not refreshed | Open a new terminal; or reboot |
| `cybersentinel-analyst` missing from `ollama list` | Ollama import failed | Run `create_modelfile.py` manually |
| Python 3.12 install fails | Admin rights missing | Right-click installer → *Run as administrator* |
| `thrember` import error at runtime | EMBER2024 pip install failed | Check `install_log.txt`; re-run with `--step thrember` |

Full install log: `C:\CyberSentinel\install_log.txt`

---

## Building a signed installer (optional)

To avoid SmartScreen warnings, sign `CyberSentinel_Setup.exe` with a code-signing certificate:

```bat
signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    /f MyCert.pfx /p MyPassword Output\CyberSentinel_Setup.exe
```

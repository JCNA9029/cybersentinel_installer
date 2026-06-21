# CyberSentinel 🛡️ — Installer Guide

> **A locally-hosted, AI-powered malware analysis and endpoint threat detection platform.**  
> CyberSentinel combines a fine-tuned LLM (trained as a Tier-3 SOC Analyst) with real-time EDR capabilities, MITRE ATT&CK mapping, and YARA rule generation — all running entirely offline on your own machine.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [For End Users — Just Run the Installer](#for-end-users--just-run-the-installer)
- [For Developers — Build the Installer from Source](#for-developers--build-the-installer-from-source)
- [What the Installer Does](#what-the-installer-does)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 / 11 (64-bit) | Windows 11 64-bit |
| CPU | Intel Core i5 8th Gen or equivalent | — |
| GPU | NVIDIA GTX 1050 Ti (4 GB VRAM) | NVIDIA RTX 3050 8 GB / RTX 4060 8 GB or better |
| RAM | 8 GB DDR4 | 16 GB DDR4 |
| Storage | 20 GB free | NVMe M.2 SSD (**mandatory** for LLM loading — HDD/SATA SSD causes severe load timeouts) |
| Network | Required during installation only (~4.5 GB model download) | — |

> ⚠️ **NVMe is not optional in practice.** Loading a 4.5 GB GGUF model from a spinning disk or SATA SSD produces multi-second to multi-minute timeouts and can cause the app to fail on first launch.

---

## For End Users — Just Run the Installer

If you have a pre-built `CyberSentinel_Setup.exe`, installation is three steps:

### Step 1 — Download

Download `CyberSentinel_Setup.exe` from the [Releases](../../releases) page.

### Step 2 — Run as Administrator

Right-click `CyberSentinel_Setup.exe` → **"Run as administrator"**.

> Administrator rights are required to install Ollama, register the background service, and write to `C:\CyberSentinel`.

### Step 3 — Follow the Wizard

Click through the setup wizard. Everything happens automatically — no manual installs needed.

**Estimated time: 10–20 minutes** (mostly waiting on the ~4.5 GB AI model download).

### Step 4 — Launch

Use the **CyberSentinel** shortcut on your Desktop or Start Menu. On first launch, allow 15–60 seconds for the AI model to load into memory.

---

## For Developers — Build the Installer from Source

Follow this section to compile `CyberSentinel_Setup.exe` yourself from the repository.

### Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Inno Setup Compiler | 6.3+ | https://jrsoftware.org/isdl.php |
| Python | 3.12.x | https://python.org |

### Repository Layout

Before compiling, make sure the repo looks like this:

```
cybersentinel_installer/
├── CyberSentinel_Setup.iss       ← compile this
├── LICENSE.txt
├── installer_tools/
│   ├── install_helper.py
│   ├── create_modelfile.py
│   └── check_python.bat
└── src/                          ← full CyberSentinel source tree
    ├── CyberSentinel.py
    ├── gui.py
    ├── modules/
    ├── intel/
    └── ...
```

> ⚠️ Do **not** include a `models/` folder inside `src/`. The AI model (~4.5 GB) is downloaded from Google Drive at install time to keep the installer under 50 MB.

### Build — GUI Method (Recommended)

1. Open **Inno Setup Compiler**.
2. `File → Open` → select `CyberSentinel_Setup.iss`.
3. Press **F9** (or `Build → Compile`).
4. The finished installer is at:

```
Output\CyberSentinel_Setup.exe
```

**Run that exe as administrator — installation is done.**

### Build — Command Line (CI/CD)

```bat
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

### Optional: Wizard Branding Images

Place these files in the repo root to customize the installer's appearance:

| File | Size | Notes |
|------|------|-------|
| `wizard_banner.bmp` | 497 × 314 px, 24-bit BMP | Dark background (`#0d1117`) with logo centered |
| `wizard_small.bmp` | 55 × 58 px, 24-bit BMP | Logo mark only |

Omitting these files causes Inno Setup to use its built-in defaults — compilation still succeeds.

### Optional: Code Signing

To prevent the Windows SmartScreen warning on the compiled installer:

```bat
signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    /f MyCert.pfx /p MyPassword Output\CyberSentinel_Setup.exe
```

---

## What the Installer Does

The wizard runs fully automatically. Here's what happens in the background:

| # | Step | Wizard label |
|---|------|--------------|
| 1 | Python 3.12 checked / silently installed | *"Checking Python 3.12..."* |
| 2 | All Python dependencies installed via pip | *"Installing Python dependencies..."* |
| 3 | EMBER2024 (thrember) malware feature library installed | *"Installing EMBER2024..."* |
| 4 | Ollama downloaded and silently installed | *"Installing Ollama..."* |
| 5 | CyberSentinel AI model (~4.5 GB) downloaded | *"Downloading AI models (~4.5 GB)..."* |
| 6 | Model registered with Ollama | *"Importing CyberSentinel AI Analyst..."* |
| 7 | Config written and background task registered | *"Finalising configuration..."* |
| 8 | Desktop and Start Menu shortcuts created | *(automatic)* |

All steps log to `C:\CyberSentinel\install_log.txt`.

**Helper scripts used internally:**

| Script | Purpose |
|--------|---------|
| `install_helper.py --step deps` | Installs all pip dependencies |
| `install_helper.py --step thrember` | Clones and installs EMBER2024 |
| `install_helper.py --step ollama` | Downloads and silently installs Ollama |
| `install_helper.py --step models` | Downloads the GGUF model from Google Drive |
| `install_helper.py --step configure` | Patches `config.json` with the correct model path |
| `create_modelfile.py` | Writes the Ollama Modelfile and runs `ollama create` |
| `check_python.bat` | Returns exit code 0 if Python 3.12 is on PATH |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Installer hangs on *"Downloading AI models"* | Slow connection or Google Drive quota | Let it run — it retries automatically up to 3 times |
| `ollama: command not found` after install | PATH not refreshed | Open a new terminal, or reboot |
| `cybersentinel-analyst` missing in `ollama list` | Model import failed silently | Run `python installer_tools\create_modelfile.py` manually from `C:\CyberSentinel` |
| Python 3.12 installation fails | Missing admin rights | Right-click installer → *Run as administrator* |
| `thrember` import error at runtime | EMBER2024 pip install failed | Check `install_log.txt`; re-run `python installer_tools\install_helper.py --step thrember` |
| AI response very slow | Insufficient GPU VRAM | Reduce `gpu_layers` in `config.json` |
| App hangs on startup | Model loading from HDD/SATA SSD too slow | Move `models/` to an NVMe drive and update `config.json` |
| SmartScreen warning on installer | Installer is unsigned | Click *More info → Run anyway*, or apply code signing (see above) |

**Full install log:** `C:\CyberSentinel\install_log.txt`

---

## Upgrading / Reinstalling

- **`config.json` is preserved** — the installer backs it up before overwriting and restores it afterward. Custom settings and API keys are never lost.
- **The AI model is preserved** — the uninstaller prompts before deleting the `models/` folder so you can skip the 4.5 GB re-download on a reinstall.

---

## License

See [LICENSE.txt](LICENSE.txt) for full terms.

---

*Built as part of a thesis project. The AI model was trained exclusively on publicly available malware behavioral datasets for research and defensive security purposes.*

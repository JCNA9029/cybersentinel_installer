# CyberSentinel 🛡️

> **A locally-hosted, AI-powered malware analysis and endpoint threat detection platform.**  
> CyberSentinel combines a fine-tuned LLM (trained as a Tier-3 SOC Analyst) with real-time EDR capabilities, MITRE ATT&CK mapping, and YARA rule generation — all running entirely offline on your own machine.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation (End Users)](#installation-end-users)
- [Building from Source (Developers)](#building-from-source-developers)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

CyberSentinel is the product of a knowledge distillation pipeline (Project CyberSentinel) in which a large teacher LLM was used to generate 1,308 high-fidelity forensic training samples from raw malware behavioral data. A smaller student model (`Qwen2.5-7B-Instruct`) was then fine-tuned on these samples using LoRA/Unsloth and exported as a 4.5 GB GGUF file. This model is served locally via [Ollama](https://ollama.com) and integrated into a full-featured GUI.

CyberSentinel is designed to run **completely offline** after initial setup — no cloud API calls, no telemetry, no data leaving your machine.

---

## Features

- **AI Forensic Analyst** — Submit malware API traces and receive structured Tier-3 threat reports including MITRE ATT&CK v14+ technique mapping, technical API chaining analysis, forensic impact assessment, and auto-generated YARA rules.
- **Real-Time EDR Monitor** — Process, file system, registry, and network activity monitoring powered by Windows ETW (Event Tracing for Windows).
- **LOLBAS / LOLDrivers Detection** — Detects abuse of Living-Off-the-Land Binaries and vulnerable drivers.
- **C2 Fingerprinting** — JA3 TLS fingerprint matching and Feodo tracker blocklist integration.
- **Adaptive Baseline Engine** — Builds a behavioral baseline for your system to detect anomalous drift over time.
- **Risk Scorer** — Multi-factor risk scoring with SHAP explainability output.
- **Quarantine & Network Isolation** — One-click process quarantine and network isolation for suspected threats.
- **SOC Dashboard** — A Flask-based web dashboard for team-oriented alert review.
- **AMSI Integration** — Hooks into the Windows Antimalware Scan Interface for script-based threat interception.

---

## System Requirements

### Minimum (Functional, but slow)
| Component | Minimum |
|-----------|---------|
| OS | Windows 10 / 11 (64-bit) |
| CPU | Intel Core i5 8th Gen or equivalent |
| GPU | NVIDIA GTX 1050 Ti (4 GB VRAM) |
| RAM | 8 GB DDR4 |
| Storage | 20 GB free (NVMe SSD **strongly** recommended) |
| Network | Required during installation only (~4.5 GB download) |

### Recommended (for smooth AI inference)
| Component | Recommended |
|-----------|-------------|
| GPU | NVIDIA RTX 3050 8 GB / RTX 4060 8 GB or better |
| RAM | 16 GB DDR4 |
| Storage | NVMe M.2 SSD (mandatory for LLM loading — HDD/SATA SSD causes severe timeouts) |

> ⚠️ **Note on HDD/SATA SSD:** Loading a 4.5 GB GGUF model from a spinning disk or even a SATA SSD produces multi-second to multi-minute load times and can cause the application to time out before the model is ready. An NVMe drive is not optional in practice.

---

## Installation (End Users)

The installer handles everything automatically: Python, all Python dependencies, Git, Ollama, and the AI model download. You do not need to install anything beforehand.

**Estimated install time: 10–20 minutes** (depends on your internet connection — the AI model is ~4.5 GB).

### Step 1 — Download the installer

Download `CyberSentinel_Setup.exe` from the [Releases](../../releases) page.

### Step 2 — Run as Administrator

Right-click `CyberSentinel_Setup.exe` and select **"Run as administrator"**.

> Administrator rights are required to install Ollama, register the background service, and write to `C:\CyberSentinel`.

### Step 3 — Follow the setup wizard

The wizard will walk you through the installation. The following steps happen automatically in the background:

| # | What's happening | Wizard label |
|---|-----------------|--------------|
| 1 | Python 3.12 is checked / silently installed | *"Checking Python 3.12..."* |
| 2 | All Python dependencies are installed via pip | *"Installing Python dependencies..."* |
| 3 | EMBER2024 (thrember) malware feature library is installed | *"Installing EMBER2024..."* |
| 4 | Ollama is downloaded and silently installed | *"Installing Ollama..."* |
| 5 | The CyberSentinel AI model (~4.5 GB) is downloaded | *"Downloading AI models (~4.5 GB)..."* |
| 6 | The model is registered with Ollama | *"Importing CyberSentinel AI Analyst..."* |
| 7 | Configuration is written and the background task is registered | *"Finalising configuration..."* |
| 8 | Desktop and Start Menu shortcuts are created | *(automatic)* |

### Step 4 — Launch CyberSentinel

Use the **CyberSentinel** shortcut on your desktop or Start Menu. On first launch, Ollama will load the model into memory — this takes 15–60 seconds depending on your hardware.

---

## Building from Source (Developers)

Use this section if you want to compile the installer yourself from the repository.

### Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| [Inno Setup](https://jrsoftware.org/isdl.php) | 6.3+ | https://jrsoftware.org/isdl.php |
| [Python](https://python.org) | 3.12.x | https://python.org |

### Expected repository layout

Before compiling, ensure the repository is structured as follows:

```
cybersentinel_installer/
├── CyberSentinel_Setup.iss       ← main Inno Setup script (compile this)
├── LICENSE.txt
├── installer_tools/
│   ├── install_helper.py
│   ├── create_modelfile.py
│   └── check_python.bat
├── assets/
│   ├── icon.ico                  ← 256×256 app icon
│   ├── wizard_banner.bmp         ← 497×314 px wizard splash
│   └── wizard_small.bmp          ← 55×58 px top-right branding
└── src/                          ← full CyberSentinel source tree
    ├── CyberSentinel.py
    ├── gui.py
    ├── dashboard.py
    ├── eval_harness.py
    ├── requirements.txt
    ├── exclusions.txt
    ├── modules/
    ├── data/
    └── intel/
```

> ⚠️ Do **not** include a `models/` folder in `src/`. The AI model is downloaded from Google Drive at install time to keep the installer under 50 MB.

### Compiling — GUI method

1. Open **Inno Setup Compiler**.
2. Go to `File → Open` and select `CyberSentinel_Setup.iss`.
3. Press **F9** or go to `Build → Compile`.
4. The compiled installer appears at `Output\CyberSentinel_Setup.exe`.

### Compiling — Command line (CI/CD)

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

### Optional: Wizard images

If you want custom branding in the installer wizard:

- `wizard_banner.bmp` — 497 × 314 px, 24-bit BMP. Recommended: dark background (`#0d1117`) with the CyberSentinel logo centered.
- `wizard_small.bmp` — 55 × 58 px, 24-bit BMP. Just the logo mark.

Omitting these files causes Inno Setup to use its built-in defaults.

### Optional: Code signing

To avoid Windows SmartScreen warnings on the compiled installer:

```bat
signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    /f MyCert.pfx /p MyPassword Output\CyberSentinel_Setup.exe
```

---

## How It Works

### The AI Model

The CyberSentinel AI Analyst is a fine-tuned `Qwen2.5-7B-Instruct` model trained via a knowledge distillation pipeline:

1. **Data preparation** — 1,308 malware samples from the [Polymorphic Malware Dataset](https://www.kaggle.com/datasets/muhammadharis4140/polymorphic-malware-dataset?resource=download) (Kaggle) were cleaned and structured into a JSON corpus, extracting filename, SHA256, malware family, and API call sequences.
2. **Knowledge distillation** — Two teacher models, **Gemma 4 31B** and **Gemma 4 26B**, generated forensic-grade analysis reports for each sample, covering threat classification, API chaining, MITRE ATT&CK mapping, forensic impact, and YARA rules.
3. **Fine-tuning** — The student model was trained on these reports using LoRA (rank 16) on a T4 GPU via Unsloth, with 4-bit quantization to fit within 16 GB VRAM.
4. **Export** — The merged model was exported as `CyberSentinel-Analyst.gguf` (Q4_K_M quantization, ~4.5 GB) and pushed to a private Hugging Face repository.

### Machine Learning Engine

The ML engine is built on the [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) model — a state-of-the-art malware feature extraction and classification framework. Its threat detection capabilities were further enhanced using real-world malware samples sourced from [theZoo](https://github.com/ytisf/thezoo) — a curated repository of live malware specimens maintained for educational and research purposes. This allowed the ML engine to train on authentic, diverse malware behaviors beyond the base dataset, significantly improving detection accuracy across malware families.

At runtime, Ollama serves the GGUF model locally. CyberSentinel communicates with it via the Ollama Python SDK — no internet connection is required after installation.

### Installer helper scripts

| Script | Purpose |
|--------|---------|
| `install_helper.py --step deps` | Installs all pip dependencies |
| `install_helper.py --step thrember` | Clones and installs EMBER2024 |
| `install_helper.py --step ollama` | Downloads and silently installs Ollama |
| `install_helper.py --step models` | Downloads the GGUF model from Google Drive |
| `install_helper.py --step configure` | Patches `config.json` with correct model path |
| `create_modelfile.py` | Writes the Ollama Modelfile and runs `ollama create` |
| `check_python.bat` | Returns exit code 0 if Python 3.12 is on PATH |

All steps log to `C:\CyberSentinel\install_log.txt`.

---

## Project Structure

```
C:\CyberSentinel\                  ← installation root
├── CyberSentinel.py               ← main entry point
├── gui.py                         ← PyQt6 GUI
├── dashboard.py                   ← Flask SOC dashboard
├── eval_harness.py                ← evaluation / benchmark harness
├── config.json                    ← runtime configuration
├── exclusions.txt                 ← process/path exclusion list
├── install_log.txt                ← installer log
├── Modelfile                      ← Ollama model definition
├── models/
│   └── CyberSentinel-Analyst.gguf ← the fine-tuned AI model
├── modules/
│   ├── analysis_manager.py        ← orchestrates AI analysis
│   ├── ml_engine.py               ← LightGBM / EMBER2024 integration
│   ├── risk_scorer.py             ← multi-factor risk scoring
│   ├── adaptive_learner.py        ← behavioral baseline
│   ├── c2_fingerprint.py          ← JA3 / C2 detection
│   ├── lolbas_detector.py         ← LOLBAS abuse detection
│   ├── driver_guard.py / byovd_detector.py ← vulnerable driver detection
│   ├── amsi_hook.py               ← AMSI integration
│   ├── quarantine.py              ← process quarantine
│   ├── network_isolation.py       ← network isolation
│   └── ...
├── intel/
│   ├── lolbas.json
│   ├── loldrivers.json
│   ├── feodo_blocklist.json
│   └── ja3_blocklist.csv
└── data/
    ├── ja3_blocklist.json
    └── lolbas_patterns.json
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Installer hangs on *"Downloading AI models"* | Slow connection or Google Drive quota exceeded | Let it run; it retries automatically up to 3 times |
| `ollama: command not found` after install | PATH not refreshed in current terminal | Open a new terminal window, or reboot |
| `cybersentinel-analyst` not listed in `ollama list` | Ollama model import failed silently | Run `python installer_tools\create_modelfile.py` manually from `C:\CyberSentinel` |
| Python 3.12 installation fails | Missing administrator rights | Right-click the installer → *Run as administrator* |
| `thrember` import error at runtime | EMBER2024 pip install failed during setup | Check `C:\CyberSentinel\install_log.txt`; re-run `python installer_tools\install_helper.py --step thrember` |
| AI response is very slow | GPU VRAM insufficient for full offload | Reduce GPU layers in `config.json` (`gpu_layers`); more layers = more VRAM used |
| Application hangs on startup | Model loading from HDD/SATA SSD is too slow | Move `models/` to an NVMe drive and update `config.json` accordingly |
| SmartScreen warning on installer | Installer is unsigned | Click *More info → Run anyway*, or see code-signing instructions above |

**Full install log:** `C:\CyberSentinel\install_log.txt`

---

## Upgrading / Reinstalling

- **Your `config.json` is preserved** — the installer backs it up before overwriting files and restores it afterward, so API keys and custom settings are never lost.
- **Your AI model is preserved** — the uninstaller prompts before deleting the `models/` folder so you can skip the 4.5 GB re-download on a reinstall.

---

## License

See [LICENSE.txt](LICENSE.txt) for full terms.

---

*Built as part of a thesis project. The AI model was trained exclusively on publicly available malware behavioral datasets for research and defensive security purposes.*

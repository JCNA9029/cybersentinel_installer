; ============================================================
;  CyberSentinel Installer — Inno Setup 6 Script
;  Target OS : Windows 10/11 x64
;  Author    : CyberSentinel Thesis Project
; ============================================================

#define MyAppName      "CyberSentinel"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "CyberSentinel Research"
#define MyAppURL       "https://github.com/CyberSentinel-Thesis"
#define MyInstallDir   "C:\CyberSentinel"
#define MyAppExeName   "gui.py"

[Setup]
AppId={{B7E3F2A1-4C9D-4E8F-B2A3-9D1E5F6C7B8A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={#MyInstallDir}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=no
LicenseFile=LICENSE.txt
OutputBaseFilename=CyberSentinel_Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=no
WizardSizePercent=120
DisableWelcomePage=no
DisableDirPage=no
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
PrivilegesRequired=admin
UninstallDisplayIcon={#MyInstallDir}\assets\icon.ico
UninstallDisplayName={#MyAppName}
CreateUninstallRegKey=yes
; Minimum version: Windows 10
MinVersion=10.0.10240

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.CheckingPython=Checking for Python 3.12...
english.InstallingPython=Installing Python 3.12...
english.EnsuringPip=Ensuring pip is available...
english.InstallingDeps=Installing Python dependencies...
english.InstallingThrember=Installing EMBER2024 (thrember)...
english.InstallingNpcap=Installing Npcap packet-capture driver (required for JA3 TLS monitor)...
english.InstallingOllama=Installing Ollama...
english.DownloadingModels=Downloading AI models (~4.5 GB) — please wait, this may take several minutes...
english.ImportingLLM=Importing CyberSentinel AI Analyst model into Ollama...
english.ConfiguringApp=Configuring CyberSentinel...
english.CreatingShortcuts=Creating shortcuts...
english.SetupComplete=CyberSentinel has been successfully installed!

[Types]
Name: "full";    Description: "Full installation (recommended)"
Name: "compact"; Description: "Compact installation (skip optional tools)"

[Components]
Name: "core";      Description: "Core application files";        Types: full compact; Flags: fixed
Name: "models";    Description: "AI models (requires ~5 GB free)"; Types: full
Name: "shortcuts"; Description: "Desktop and Start Menu shortcuts"; Types: full compact

[Tasks]
Name: "desktopicon";    Description: "Create a &desktop shortcut";          GroupDescription: "Shortcuts:"; Components: shortcuts
Name: "startmenuicon";  Description: "Create &Start Menu shortcuts";         GroupDescription: "Shortcuts:"; Components: shortcuts
Name: "startonboot";    Description: "Start Ollama automatically on &login"; GroupDescription: "Ollama:";    Components: models

[Files]
; ── Application source tree ──────────────────────────────────
Source: "src\*"; DestDir: "{#MyInstallDir}"; Flags: recursesubdirs createallsubdirs ignoreversion; Components: core

; ── Installer helper scripts ─────────────────────────────────
Source: "installer_tools\install_helper.py";   DestDir: "{#MyInstallDir}\installer_tools"; Components: core
Source: "installer_tools\create_modelfile.py"; DestDir: "{#MyInstallDir}\installer_tools"; Components: core
Source: "installer_tools\check_python.bat";    DestDir: "{#MyInstallDir}\installer_tools"; Components: core

; ── Bundled redistributables (fetched/created at build time) ─
; Python 3.12 installer is downloaded in [Code] if absent.
; Ollama installer is downloaded in [Code] if absent.

[Icons]
; Desktop shortcut
; {reg:...} reads the exact Python path saved during install — never picks up a wrong Python from PATH.
Name: "{userdesktop}\CyberSentinel GUI"; Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; Parameters: """{#MyInstallDir}\gui.py"""; WorkingDir: "{#MyInstallDir}"; IconFilename: "{#MyInstallDir}\assets\icon.ico"; Tasks: desktopicon

; Start Menu group
Name: "{group}\CyberSentinel GUI";        Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; Parameters: """{#MyInstallDir}\gui.py""";                                                                          WorkingDir: "{#MyInstallDir}"; IconFilename: "{#MyInstallDir}\assets\icon.ico"; Tasks: startmenuicon
Name: "{group}\CyberSentinel CLI";        Filename: "cmd.exe"; Parameters: "/k ""{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"" ""{#MyInstallDir}\CyberSentinel.py"" --help"; WorkingDir: "{#MyInstallDir}"; Tasks: startmenuicon
Name: "{group}\CyberSentinel Dashboard";  Filename: "cmd.exe"; Parameters: "/k ""{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"" ""{#MyInstallDir}\dashboard.py""";            WorkingDir: "{#MyInstallDir}"; Tasks: startmenuicon
Name: "{group}\Uninstall CyberSentinel";  Filename: "{uninstallexe}"; Tasks: startmenuicon

[Run]
; ── Step 2 & 3: pip deps + thrember ──────────────────────────
; Python 3.12 is already installed and verified in PrepareToInstall.
; pip bootstrap is handled inside install_helper --step deps (_ensure_pip).
; {reg:...} ensures we use the exact Python that was pinned to the registry
; during PrepareToInstall — never relies on whatever is first on PATH.
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step deps"; \
  StatusMsg: "{cm:InstallingDeps}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Python dependencies (this may take 3–5 minutes)...')

Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step thrember"; \
  StatusMsg: "{cm:InstallingThrember}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing EMBER2024 / thrember engine...')

; ── Step 3b: Npcap — packet-capture driver for scapy / JA3 monitor ───────────
; scapy is already installed by the deps step above, but on Windows it also
; needs Npcap (the WinPcap-compatible kernel driver) to actually capture packets.
; Without Npcap, Ja3Monitor silently disables itself at runtime.
; install_helper.py::step_npcap() checks the registry before downloading,
; so this is safe to re-run and won't reinstall if Npcap is already present.
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step npcap"; \
  StatusMsg: "{cm:InstallingNpcap}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Npcap driver for JA3 TLS fingerprinting...')

; ── Step 4: Ollama ───────────────────────────────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step ollama"; \
  StatusMsg: "{cm:InstallingOllama}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Ollama inference engine...')

; ── Step 7: Download models from Google Drive ────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step models"; \
  StatusMsg: "{cm:DownloadingModels}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Downloading AI models (~4.5 GB) — do not close this window...')

; ── Step 5: Import LLM into Ollama ───────────────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\create_modelfile.py"""; \
  StatusMsg: "{cm:ImportingLLM}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Importing CyberSentinel AI Analyst into Ollama (this may take several minutes)...')

; ── Step 6 & 8: Patch config + register Ollama boot task ─────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step configure"; \
  StatusMsg: "{cm:ConfiguringApp}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Finalising configuration...')

; ── Step 9: Register scheduled task for Ollama ───────────────
Filename: "schtasks.exe"; \
  Parameters: "/Create /F /SC ONLOGON /TN ""CyberSentinel\OllamaServer"" /TR ""ollama serve"" /RL HIGHEST /DELAY 0001:00"; \
  Flags: runhidden waituntilterminated; \
  Tasks: startonboot

; ── Launch GUI after install ─────────────────────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; \
  Parameters: """{#MyInstallDir}\gui.py"""; \
  WorkingDir: "{#MyInstallDir}"; \
  Description: "Launch CyberSentinel GUI now"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""CyberSentinel\OllamaServer"""; Flags: runhidden waituntilterminated

[Registry]
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "InstallDir";  ValueData: "{#MyInstallDir}";  Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "Version";     ValueData: "{#MyAppVersion}"
; PythonExe / PythonwExe are written at runtime by ResolvePythonPath in [Code].
; Declaring them here (with empty defaults) ensures they are removed on uninstall.
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "PythonExe";   ValueData: ""; Flags: uninsdeletekeyifempty
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "PythonwExe";  ValueData: ""; Flags: uninsdeletekeyifempty

[Code]
// ─────────────────────────────────────────────────────────────
//  Pascal/Code section — handles dynamic logic
// ─────────────────────────────────────────────────────────────

var
  ProgressPage:  TOutputProgressWizardPage;
  StepLabel:     TNewStaticText;
  LogMemo:       TNewMemo;
  CurrentStep:   String;
  PythonExePath: String;  // Resolved after Python install — used by all [Run] steps and shortcuts

// Reads the first line of a text file into OutStr; returns True on success.
function ReadFileToStr(const FileName: String; var OutStr: String): Boolean;
var
  F: Integer;
  Buf: AnsiString;
begin
  Result := False;
  OutStr := '';
  F := FileOpen(FileName, fmOpenRead);
  if F = -1 then Exit;
  SetLength(Buf, 32767);
  SetLength(Buf, FileRead(F, Buf[1], 32767));
  FileClose(F);
  OutStr := Trim(String(Buf));
  Result := True;
end;

// Called from [Run] BeforeInstall to update the visible label
procedure SetStep(const Msg: String);
begin
  CurrentStep := Msg;
  if Assigned(ProgressPage) then begin
    ProgressPage.SetText(Msg, '');
    ProgressPage.SetProgress(ProgressPage.ProgressBar.Position + 1, 10);
  end;
end;

// ── Custom wizard pages ──────────────────────────────────────
procedure InitializeWizard;
begin
  ProgressPage := CreateOutputProgressPage(
    'Installing CyberSentinel',
    'Please wait while the setup configures your system...'
  );
end;

// ── Python 3.12 detection — runs BEFORE files are installed ─────────────────
// check_python.bat is not on disk yet at PrepareToInstall time ([Files] hasn't
// run yet), so we ask Python directly and parse the version ourselves.
function PythonInstalled: Boolean;
var
  TmpFile:    String;
  VerStr:     String;
  ResultCode: Integer;
begin
  Result  := False;
  TmpFile := ExpandConstant('{tmp}\py_ver_check.txt');
  Exec('cmd.exe',
    '/c python -c "import sys; open(r\"' + TmpFile +
    '\",\"w\").write(\".\".join(map(str,sys.version_info[:2])))"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if FileExists(TmpFile) then begin
    ReadFileToStr(TmpFile, VerStr);
    DeleteFile(TmpFile);
    Result := (VerStr = '3.12');
  end;
end;

function DownloadFile(const URL, Dest: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('powershell.exe',
    Format('-NoProfile -NonInteractive -Command "Invoke-WebRequest -Uri ''%s'' -OutFile ''%s'' -UseBasicParsing"', [URL, Dest]),
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

// ── Resolve the exact Python 3.12 executable path ────────────
// Writes result into PythonExePath and saves it to the registry
// so [Icons] shortcuts and any external tool can read it later.
//
// On a clean PC, a freshly-installed Python 3.12 is NOT yet on the
// current process's PATH (we inherited the old PATH before Python
// was installed). So we probe known install locations FIRST, then
// try PATH as a fallback, not the other way around.
procedure ResolvePythonPath;
var
  PathTxtFile: String;
  Candidate:   String;
  ResultCode:  Integer;
  VerCheck:    String;
begin
  PythonExePath := '';

  // ── 1. Probe all known Python 3.12 install locations first ───────────────
  // These are written by the Python 3.12 installer regardless of PATH state.
  for Candidate in [
    'C:\Program Files\Python312\python.exe',
    'C:\Python312\python.exe',
    ExpandConstant('{localappdata}\Programs\Python\Python312\python.exe'),
    ExpandConstant('{localappdata}\Programs\Python\Python3\python.exe')
  ] do begin
    if FileExists(Candidate) then begin
      PythonExePath := Candidate;
      Break;
    end;
  end;

  // ── 2. If a known path was found, verify it really is 3.12 ───────────────
  if PythonExePath <> '' then begin
    PathTxtFile := ExpandConstant('{tmp}\py_ver_resolve.txt');
    Exec('cmd.exe',
      '/c "' + PythonExePath + '" -c "import sys; open(r\"' + PathTxtFile +
      '\",\"w\").write(\".\".join(map(str,sys.version_info[:2])))"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if FileExists(PathTxtFile) then begin
      ReadFileToStr(PathTxtFile, VerCheck);
      DeleteFile(PathTxtFile);
      if VerCheck <> '3.12' then
        PythonExePath := '';   // found file but wrong version; keep searching
    end else
      PythonExePath := '';     // couldn't run it
  end;

  // ── 3. Fallback: ask whatever 'python' is on PATH ────────────────────────
  // This covers the case where the user had Python 3.12 already installed
  // before running the installer (PATH was inherited correctly).
  if PythonExePath = '' then begin
    PathTxtFile := ExpandConstant('{tmp}\py_path_resolve.txt');
    Exec('cmd.exe',
      '/c python -c "import sys; open(r\"' + PathTxtFile +
      '\",\"w\").write(sys.executable)"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if FileExists(PathTxtFile) then begin
      ReadFileToStr(PathTxtFile, PythonExePath);
      DeleteFile(PathTxtFile);
    end;
  end;

  // ── 4. Last resort — bare 'python.exe' and hope for the best ─────────────
  if PythonExePath = '' then begin
    Log('WARNING: Could not locate python.exe; falling back to bare python.exe on PATH.');
    PythonExePath := 'python.exe';
  end;

  // Persist to registry so shortcuts survive PATH changes after install.
  RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonExe', PythonExePath);

  // Also derive pythonw.exe (GUI launcher, no console window) from the same dir.
  RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonwExe',
    ExtractFilePath(PythonExePath) + 'pythonw.exe');
end;

// ── Pre-install checks ────────────────────────────────────────
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  PythonInstaller: String;
  ResultCode:      Integer;
  Attempts:        Integer;
begin
  Result := '';

  // ── Ensure Python 3.12 is present ──
  if not PythonInstalled then begin
    SetStep('Python 3.12 not found — downloading installer...');
    PythonInstaller := ExpandConstant('{tmp}\python312_installer.exe');

    Attempts := 0;
    while Attempts < 3 do begin
      if DownloadFile(
        'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe',
        PythonInstaller) then Break;
      Attempts := Attempts + 1;
      if Attempts = 3 then begin
        Result := 'Failed to download Python 3.12 after 3 attempts. Please check your internet connection and re-run the installer.';
        Exit;
      end;
    end;

    SetStep('Installing Python 3.12 (this may take a minute)...');
    if not Exec(PythonInstaller,
      '/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
      or (ResultCode <> 0) then begin
      Result := Format('Python 3.12 installation failed (exit code %d). Please install Python 3.12 manually from python.org and re-run this installer.', [ResultCode]);
      Exit;
    end;
  end;

  // ── Pin the exact Python path used for all subsequent steps ──
  // Must run AFTER Python is confirmed installed.
  ResolvePythonPath;

  // ── Verify pip is available, bootstrap if not ────────────────
  // Catches the edge case where Python was installed without pip
  // (e.g. per-user install with pip checkbox unchecked).
  SetStep('Verifying pip is available...');
  if not Exec(PythonExePath, '-m pip --version',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    or (ResultCode <> 0) then begin
    log('pip missing — running ensurepip...');
    Exec(PythonExePath, '-m ensurepip --upgrade',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // If ensurepip also fails, install_helper._ensure_pip() will
    // attempt the get-pip.py fallback during the deps step.
  end;
end;

// ── Guard against overwriting existing config.json ───────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath:  String;
  BackupPath:  String;
begin
  if CurStep = ssInstall then begin
    ConfigPath := ExpandConstant('{#MyInstallDir}\config.json');
    BackupPath  := ExpandConstant('{#MyInstallDir}\config.json.bak');
    // Back up existing config so it isn't overwritten
    if FileExists(ConfigPath) then
      RenameFile(ConfigPath, BackupPath);
  end;

  if CurStep = ssPostInstall then begin
    // Restore config backup if it exists (preserves user API keys)
    ConfigPath := ExpandConstant('{#MyInstallDir}\config.json');
    BackupPath  := ExpandConstant('{#MyInstallDir}\config.json.bak');
    if FileExists(BackupPath) then begin
      DeleteFile(ConfigPath);
      RenameFile(BackupPath, ConfigPath);
    end;
  end;
end;

// ── Uninstall: prompt to remove user data ────────────────────
function InitializeUninstall: Boolean;
var
  Answer: Integer;
begin
  Result := True;
  Answer := MsgBox(
    'Do you also want to remove downloaded AI models and user data in C:\CyberSentinel?' + #13#10 +
    '(Choose "No" to keep your models for a future reinstall.)',
    mbConfirmation, MB_YESNO);
  if Answer = IDYES then
    DelTree(ExpandConstant('{#MyInstallDir}\models'), True, True, True);
end;

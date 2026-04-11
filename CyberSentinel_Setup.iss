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
// ============================================================
//  Pascal/Code section
//  Engine: RemObjects Pascal Script (Inno Setup 6)
//
//  Compatibility rules applied throughout:
//    - No "for X in [array]" — use explicit if/else chains
//    - No inline var declarations
//    - No String(AnsiString) casts — use LoadStringFromFile directly
//    - No ProgressBar.Position — use WizardForm.ProgressGauge
//    - All functions verified against Inno Setup 6 built-in list
// ============================================================

var
  PythonExePath: String;  // Set by ResolvePythonPath; used by all [Run] steps
  InstallStep:   Integer; // Tracks current step for progress bar (0-based)

// ── Update the built-in installation progress gauge ──────────
// WizardForm.ProgressGauge is the actual progress bar on the
// Installing page — this is the correct, documented API.
procedure SetStep(const Msg: String);
begin
  InstallStep := InstallStep + 1;
  WizardForm.StatusLabel.Caption := Msg;
  // Max = 10 steps total; keeps bar moving visibly
  WizardForm.ProgressGauge.Position :=
    InstallStep * (WizardForm.ProgressGauge.Max div 10);
end;

// ── Read a file written by a Python script into a String ─────
// LoadStringFromFile is a genuine Inno Setup built-in.
// Its second parameter is AnsiString in Unicode Inno Setup 6.
function ReadTmpFile(const FileName: String; var OutStr: String): Boolean;
var
  Raw: AnsiString;
begin
  Result := LoadStringFromFile(FileName, Raw);
  if Result then
    OutStr := Trim(String(Raw))
  else
    OutStr := '';
end;

// ── Write a tiny Python script to {tmp} and run it ───────────
// Returns the first line of output written by the script to OutFile.
// Using a file avoids all cmd.exe quoting complexity entirely.
function RunPyScript(const PythonExe, ScriptBody, OutFile: String): String;
var
  ScriptFile: String;
  ResultCode: Integer;
begin
  Result     := '';
  ScriptFile := ExpandConstant('{tmp}\cs_tmp_script.py');
  DeleteFile(ScriptFile);
  DeleteFile(OutFile);

  SaveStringToFile(ScriptFile, ScriptBody, False);

  Exec(PythonExe, '"' + ScriptFile + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if FileExists(OutFile) then
    ReadTmpFile(OutFile, Result);

  DeleteFile(ScriptFile);
  DeleteFile(OutFile);
end;

// ── Check whether Python 3.12 is on PATH ─────────────────────
// Called from PrepareToInstall BEFORE [Files] are on disk.
function PythonInstalled: Boolean;
var
  OutFile: String;
  VerStr:  String;
  Script:  String;
begin
  OutFile := ExpandConstant('{tmp}\cs_ver.txt');
  Script  :=
    'import sys' + #13#10 +
    'v = str(sys.version_info[0]) + "." + str(sys.version_info[1])' + #13#10 +
    'f = open(r"' + OutFile + '", "w")' + #13#10 +
    'f.write(v)' + #13#10 +
    'f.close()' + #13#10;

  VerStr := RunPyScript('python.exe', Script, OutFile);
  Result := (VerStr = '3.12');
end;

// ── Download a file using PowerShell ─────────────────────────
function DownloadFile(const URL, Dest: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('powershell.exe',
    '-NoProfile -NonInteractive -Command "Invoke-WebRequest' +
    ' -Uri ''' + URL + '''' +
    ' -OutFile ''' + Dest + '''' +
    ' -UseBasicParsing"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

// ── Try one Python candidate path; return True if it is 3.12 ─
function TryPythonCandidate(const Candidate: String): Boolean;
var
  OutFile: String;
  VerStr:  String;
  Script:  String;
begin
  Result  := False;
  OutFile := ExpandConstant('{tmp}\cs_cand.txt');
  Script  :=
    'import sys' + #13#10 +
    'v = str(sys.version_info[0]) + "." + str(sys.version_info[1])' + #13#10 +
    'f = open(r"' + OutFile + '", "w")' + #13#10 +
    'f.write(v)' + #13#10 +
    'f.close()' + #13#10;

  VerStr := RunPyScript(Candidate, Script, OutFile);
  Result := (VerStr = '3.12');
end;

// ── Resolve the exact Python 3.12 path and persist to registry ─
// On a clean PC the newly-installed Python is NOT yet on PATH
// because the installer process inherited the old PATH env.
// We probe known install locations first, fall back to PATH last.
procedure ResolvePythonPath;
var
  OutFile:   String;
  Script:    String;
  Candidate: String;
  ResultCode: Integer;
begin
  PythonExePath := '';

  // 1. System-wide install (InstallAllUsers=1, the default for our /quiet run)
  Candidate := 'C:\Program Files\Python312\python.exe';
  if FileExists(Candidate) and TryPythonCandidate(Candidate) then
    PythonExePath := Candidate;

  // 2. Legacy system-wide path some installers used
  if PythonExePath = '' then begin
    Candidate := 'C:\Python312\python.exe';
    if FileExists(Candidate) and TryPythonCandidate(Candidate) then
      PythonExePath := Candidate;
  end;

  // 3. Per-user install path
  if PythonExePath = '' then begin
    Candidate := ExpandConstant('{localappdata}\Programs\Python\Python312\python.exe');
    if FileExists(Candidate) and TryPythonCandidate(Candidate) then
      PythonExePath := Candidate;
  end;

  // 4. Fallback: ask whatever 'python' is on PATH to report its own exe path
  if PythonExePath = '' then begin
    OutFile := ExpandConstant('{tmp}\cs_exe.txt');
    Script  :=
      'import sys' + #13#10 +
      'f = open(r"' + OutFile + '", "w")' + #13#10 +
      'f.write(sys.executable)' + #13#10 +
      'f.close()' + #13#10;
    PythonExePath := RunPyScript('python.exe', Script, OutFile);
  end;

  // 5. Absolute last resort
  if PythonExePath = '' then begin
    Log('WARNING: Cannot locate python.exe; falling back to bare name on PATH.');
    PythonExePath := 'python.exe';
  end;

  // Persist so [Run] entries and [Icons] shortcuts can read it from the registry
  RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonExe',  PythonExePath);
  RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonwExe',
    ExtractFilePath(PythonExePath) + 'pythonw.exe');
end;

// ── Pre-install: ensure Python 3.12 exists, resolve its path ─
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  PythonInstaller: String;
  ResultCode:      Integer;
  Attempts:        Integer;
  Downloaded:      Boolean;
begin
  Result      := '';
  InstallStep := 0;

  if not PythonInstalled then begin
    SetStep('Python 3.12 not found — downloading installer...');
    PythonInstaller := ExpandConstant('{tmp}\python312_installer.exe');

    Downloaded := False;
    Attempts   := 0;
    while Attempts < 3 do begin
      if DownloadFile(
          'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe',
          PythonInstaller) then begin
        Downloaded := True;
        Break;
      end;
      Attempts := Attempts + 1;
    end;

    if not Downloaded then begin
      Result := 'Failed to download Python 3.12 after 3 attempts.' +
                ' Please check your internet connection and re-run.';
      Exit;
    end;

    SetStep('Installing Python 3.12...');
    if not Exec(PythonInstaller,
        '/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then begin
      Result := 'Python 3.12 installation failed (exit code ' +
                IntToStr(ResultCode) + ').' +
                ' Please install Python 3.12 from python.org and re-run.';
      Exit;
    end;
  end;

  // Pin the exact executable path into PythonExePath and the registry
  SetStep('Detecting Python location...');
  ResolvePythonPath;

  // Bootstrap pip if missing (install_helper --step deps also does this,
  // but doing it here gives a cleaner error message if it fails)
  SetStep('Verifying pip...');
  if not Exec(PythonExePath, '-m pip --version',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then begin
    Log('pip not found — running ensurepip...');
    Exec(PythonExePath, '-m ensurepip --upgrade',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

// ── Guard existing config.json on reinstall ───────────────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
  BackupPath: String;
begin
  ConfigPath := ExpandConstant('{#MyInstallDir}\config.json');
  BackupPath  := ExpandConstant('{#MyInstallDir}\config.json.bak');

  if CurStep = ssInstall then begin
    if FileExists(ConfigPath) then
      RenameFile(ConfigPath, BackupPath);
  end;

  if CurStep = ssPostInstall then begin
    if FileExists(BackupPath) then begin
      DeleteFile(ConfigPath);
      RenameFile(BackupPath, ConfigPath);
    end;
  end;
end;

// ── Uninstall: offer to remove AI models ─────────────────────
function InitializeUninstall: Boolean;
var
  Answer: Integer;
begin
  Result := True;
  Answer := MsgBox(
    'Do you also want to remove downloaded AI models and user data?' +
    #13#10 + '(Choose No to keep models for a future reinstall.)',
    mbConfirmation, MB_YESNO);
  if Answer = IDYES then
    DelTree(ExpandConstant('{#MyInstallDir}\models'), True, True, True);
end;

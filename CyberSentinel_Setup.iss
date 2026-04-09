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
english.InstallingDeps=Installing Python dependencies...
english.InstallingThrember=Installing EMBER2024 (thrember)...
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
Name: "{userdesktop}\CyberSentinel GUI"; Filename: "pythonw.exe"; Parameters: """{#MyInstallDir}\gui.py"""; WorkingDir: "{#MyInstallDir}"; IconFilename: "{#MyInstallDir}\assets\icon.ico"; Tasks: desktopicon

; Start Menu group
Name: "{group}\CyberSentinel GUI";        Filename: "pythonw.exe";  Parameters: """{#MyInstallDir}\gui.py""";         WorkingDir: "{#MyInstallDir}"; IconFilename: "{#MyInstallDir}\assets\icon.ico"; Tasks: startmenuicon
Name: "{group}\CyberSentinel CLI";        Filename: "cmd.exe";      Parameters: "/k python ""{#MyInstallDir}\CyberSentinel.py"" --help"; WorkingDir: "{#MyInstallDir}"; Tasks: startmenuicon
Name: "{group}\CyberSentinel Dashboard";  Filename: "cmd.exe";      Parameters: "/k python ""{#MyInstallDir}\dashboard.py""";            WorkingDir: "{#MyInstallDir}"; Tasks: startmenuicon
Name: "{group}\Uninstall CyberSentinel";  Filename: "{uninstallexe}"; Tasks: startmenuicon

[Run]
; ── Step 1: Check / install Python 3.12 ──────────────────────
Filename: "{#MyInstallDir}\installer_tools\check_python.bat"; \
  StatusMsg: "{cm:CheckingPython}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Checking Python 3.12...')

; ── Step 2 & 3: pip deps + thrember ──────────────────────────
Filename: "python.exe"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step deps"; \
  StatusMsg: "{cm:InstallingDeps}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Python dependencies (this may take 3–5 minutes)...')

Filename: "python.exe"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step thrember"; \
  StatusMsg: "{cm:InstallingThrember}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing EMBER2024 / thrember engine...')

; ── Step 4: Ollama ───────────────────────────────────────────
Filename: "python.exe"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step ollama"; \
  StatusMsg: "{cm:InstallingOllama}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Ollama inference engine...')

; ── Step 7: Download models from Google Drive ────────────────
Filename: "python.exe"; \
  Parameters: """{#MyInstallDir}\installer_tools\install_helper.py"" --step models"; \
  StatusMsg: "{cm:DownloadingModels}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Downloading AI models (~4.5 GB) — do not close this window...')

; ── Step 5: Import LLM into Ollama ───────────────────────────
Filename: "python.exe"; \
  Parameters: """{#MyInstallDir}\installer_tools\create_modelfile.py"""; \
  StatusMsg: "{cm:ImportingLLM}"; \
  WorkingDir: "{#MyInstallDir}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Importing CyberSentinel AI Analyst into Ollama (this may take several minutes)...')

; ── Step 6 & 8: Patch config + register Ollama boot task ─────
Filename: "python.exe"; \
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
Filename: "pythonw.exe"; \
  Parameters: """{#MyInstallDir}\gui.py"""; \
  WorkingDir: "{#MyInstallDir}"; \
  Description: "Launch CyberSentinel GUI now"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""CyberSentinel\OllamaServer"""; Flags: runhidden waituntilterminated

[Registry]
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "InstallDir"; ValueData: "{#MyInstallDir}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "Version";    ValueData: "{#MyAppVersion}"

[Code]
// ─────────────────────────────────────────────────────────────
//  Pascal/Code section — handles dynamic logic
// ─────────────────────────────────────────────────────────────

var
  ProgressPage: TOutputProgressWizardPage;
  StepLabel:    TNewStaticText;
  LogMemo:      TNewMemo;
  CurrentStep:  String;

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

// ── Python 3.12 detection & silent download ──────────────────
function PythonInstalled: Boolean;
var
  ResultCode: Integer;
begin
  // Try running check_python.bat (returns 0 if Python 3.12 found)
  Result := Exec(ExpandConstant('{#MyInstallDir}\installer_tools\check_python.bat'),
                 '', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
             and (ResultCode = 0);
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

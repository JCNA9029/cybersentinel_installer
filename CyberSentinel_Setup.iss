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
WindowVisible=yes
WizardStyle=modern
WizardResizable=no
WizardSizePercent=120
DisableWelcomePage=no
DisableDirPage=no
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\assets\icon.ico
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
english.NpcapMissing=Npcap was not installed on your system.%n%nThe JA3 TLS fingerprint monitor (which detects C2 beaconing via TLS fingerprints) will be disabled until Npcap is installed.%n%nTo enable it later, download and install Npcap from:%nhttps://npcap.com/#download%n%nEverything else in CyberSentinel works without Npcap.
english.InstallingOllama=Installing Ollama...
english.ModelDownloadFailed=AI model download failed.%n%nCyberSentinel has been installed, but the AI Analyst model could not be downloaded from Google Drive.%n%nTo fix this:%n  1. Check your internet connection.%n  2. Re-run the installer, or manually run:%n       python installer_tools\install_helper.py --step models --install-dir "C:\CyberSentinel"%n%nAll other features work without the AI model.
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
Source: "src\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion; Excludes: "__pycache__,*.pyc,*.pyo"; Components: core

; ── Installer helper scripts ─────────────────────────────────
Source: "installer_tools\install_helper.py";   DestDir: "{app}\installer_tools"; Components: core
Source: "installer_tools\create_modelfile.py"; DestDir: "{app}\installer_tools"; Components: core
Source: "installer_tools\check_python.bat";    DestDir: "{app}\installer_tools"; Components: core

; ── Bundled redistributables (fetched/created at build time) ─
; Python 3.12 installer is downloaded in [Code] if absent.
; Ollama installer is downloaded in [Code] if absent.

[Icons]
; Desktop shortcut
; {reg:...} reads the exact Python path saved during install — never picks up a wrong Python from PATH.
Name: "{userdesktop}\CyberSentinel GUI"; Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; Parameters: """{app}\gui.py"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; AppUserModelID: "CyberSentinel.GUI"; Tasks: desktopicon

; Start Menu group
Name: "{group}\CyberSentinel GUI";        Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; Parameters: """{app}\gui.py""";                                                                          WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: startmenuicon
Name: "{group}\CyberSentinel GUI";        Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; Parameters: """{app}\gui.py"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; AppUserModelID: "CyberSentinel.GUI"; Tasks: startmenuicon
Name: "{group}\CyberSentinel Dashboard";  Filename: "cmd.exe"; Parameters: "/k python.exe ""{app}\dashboard.py"""; WorkingDir: "{app}"; Tasks: startmenuicon
Name: "{group}\Uninstall CyberSentinel";  Filename: "{uninstallexe}"; Tasks: startmenuicon

[Run]
; ── Step 2 & 3: pip deps + thrember ──────────────────────────
; Python 3.12 is already installed and verified in PrepareToInstall.
; pip bootstrap is handled inside install_helper --step deps (_ensure_pip).
; {reg:...} ensures we use the exact Python that was pinned to the registry
; during PrepareToInstall — never relies on whatever is first on PATH.
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step deps --install-dir ""{app}"""; \
  StatusMsg: "{cm:InstallingDeps}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Python dependencies (this may take 3–5 minutes)...')

Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step thrember --install-dir ""{app}"""; \
  StatusMsg: "{cm:InstallingThrember}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing EMBER2024 / thrember engine...')

; ── Step 3b: Npcap — packet-capture driver for scapy / JA3 monitor ───────────
; scapy is already installed by the deps step above, but on Windows it also
; needs Npcap (the WinPcap-compatible kernel driver) to actually capture packets.
; Without Npcap, Ja3Monitor silently disables itself at runtime.
; install_helper.py::step_npcap() checks the registry before downloading,
; so this is safe to re-run and won't reinstall if Npcap is already present.
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step npcap --install-dir ""{app}"""; \
  StatusMsg: "{cm:InstallingNpcap}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Npcap driver for JA3 TLS fingerprinting...')

; ── Step 4: Ollama ───────────────────────────────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step ollama --install-dir ""{app}"""; \
  StatusMsg: "{cm:InstallingOllama}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Installing Ollama inference engine...')

; ── Step 7: Download models from Google Drive ────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step models --install-dir ""{app}"""; \
  StatusMsg: "{cm:DownloadingModels}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Downloading AI models (~4.5 GB) — do not close this window...')

; ── Step 5: Import LLM into Ollama ───────────────────────────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\create_modelfile.py"""; \
  StatusMsg: "{cm:ImportingLLM}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  Components: models; \
  BeforeInstall: SetStep('Importing CyberSentinel AI Analyst into Ollama (this may take several minutes)...')

; ── Step 6 & 8: Patch config + register Ollama boot task ─────
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"; \
  Parameters: """{app}\installer_tools\install_helper.py"" --step configure --install-dir ""{app}"""; \
  StatusMsg: "{cm:ConfiguringApp}"; \
  WorkingDir: "{app}"; \
  Flags: runhidden waituntilterminated; \
  BeforeInstall: SetStep('Finalising configuration...')

; ── Step 9: Register scheduled task for Ollama ───────────────
; FIX: added skipifdoesntexist so the step degrades gracefully on
; domain-joined machines where Group Policy strips /RL HIGHEST from
; the elevated token, which would otherwise produce code 5.
Filename: "schtasks.exe"; \
  Parameters: "/Create /F /SC ONLOGON /TN ""CyberSentinel\OllamaServer"" /TR ""ollama serve"" /RL HIGHEST /DELAY 0001:00"; \
  Flags: runhidden waituntilterminated skipifdoesntexist; \
  Tasks: startonboot

; ── Launch GUI after install ─────────────────────────────────
; FIX: replaced runasoriginaluser with shellexec.
; runasoriginaluser calls IShellDispatch2 to de-elevate, which returns
; ERROR_ACCESS_DENIED (code 5) on many Windows 10/11 configurations.
; shellexec hands the launch to the shell with appropriate privileges instead.
Filename: "{reg:HKLM\SOFTWARE\{#MyAppName},PythonwExe|pythonw.exe}"; \
  Parameters: """{app}\gui.py"""; \
  WorkingDir: "{app}"; \
  Description: "Launch CyberSentinel GUI now"; \
  Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""CyberSentinel\OllamaServer"""; Flags: runhidden waituntilterminated

[Registry]
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "InstallDir";  ValueData: "{app}";  Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "Version";     ValueData: "{#MyAppVersion}"
; PythonExe / PythonwExe cleanup on uninstall — written here so Inno Setup's
; uninstaller removes them. The values themselves are populated at runtime by
; ResolvePythonPath (never pre-initialized to "" to avoid Error 87 on [Run]).
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: none; ValueName: "PythonExe";  Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: none; ValueName: "PythonwExe"; Flags: uninsdeletevalue

; ── Explorer Context Menu (Right-Click "Scan with CyberSentinel") ──
Root: HKCR; Subkey: "*\shell\CyberSentinel"; ValueType: string; ValueData: "Scan with CyberSentinel"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\CyberSentinel"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\assets\icon.ico"
Root: HKCR; Subkey: "*\shell\CyberSentinel\command"; ValueType: string; ValueData: """{reg:HKLM\SOFTWARE\{#MyAppName},PythonExe|python.exe}"" ""{app}\CyberSentinel.py"" --scan ""%1"""


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
  NpcapMissing:  Boolean; // Set in ssPostInstall if npcap_missing.flag exists
  const
  GWL_STYLE     = -16;
  WS_MINIMIZEBOX = $00020000;

function GetWindowLong(hWnd: HWND; nIndex: Integer): LongInt;
  external 'GetWindowLongW@user32.dll stdcall';

function SetWindowLong(hWnd: HWND; nIndex: Integer; dwNewLong: LongInt): LongInt;
  external 'SetWindowLongW@user32.dll stdcall';

// ── Update the built-in installation progress gauge ──────────
// WizardForm.ProgressGauge is the actual progress bar on the
// Installing page — this is the correct, documented API.
procedure SetStep(const Msg: String);
begin
  InstallStep := InstallStep + 1;
  WizardForm.StatusLabel.Caption := Msg;
  // Guard: ProgressGauge is only meaningful on the Installing page.
  // During PrepareToInstall the control exists but is not visible;
  // skip the update to avoid AV on Max=0 edge case.
  if WizardForm.ProgressGauge.Max > 0 then
    WizardForm.ProgressGauge.Position :=
      InstallStep * (WizardForm.ProgressGauge.Max div 10);
end;

procedure InitializeWizard();
begin
  // Enable minimize button on the installer window
  SetWindowLong(
    WizardForm.Handle,
    GWL_STYLE,
    GetWindowLong(WizardForm.Handle, GWL_STYLE) or WS_MINIMIZEBOX
  );
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

// ── Check whether Python 3.10+ is on PATH ────────────────────
// Accepts 3.10, 3.11, 3.12, 3.13 so users with any recent Python
// do not trigger an unnecessary re-download.
function PythonInstalled: Boolean;
var
  OutFile:  String;
  VerStr:   String;
  Script:   String;
  SpacePos: Integer;
  MajorVer: Integer;
  MinorVer: Integer;
begin
  OutFile := ExpandConstant('{tmp}\cs_ver.txt');
  Script  :=
    'import sys' + #13#10 +
    'f = open(r"' + OutFile + '", "w")' + #13#10 +
    'f.write(str(sys.version_info[0]) + " " + str(sys.version_info[1]))' + #13#10 +
    'f.close()' + #13#10;
  VerStr   := RunPyScript('python.exe', Script, OutFile);
  SpacePos := Pos(' ', VerStr);
  if SpacePos > 0 then begin
    MajorVer := StrToIntDef(Copy(VerStr, 1, SpacePos - 1), 0);
    MinorVer := StrToIntDef(Trim(Copy(VerStr, SpacePos + 1, Length(VerStr))), 0);
    Result   := (MajorVer = 3) and (MinorVer >= 10);
  end else
    Result := False;
end;

function ShouldAbortInstallation: Boolean;
begin
  Result := False;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if CurPageID = wpInstalling then
  begin
    if MsgBox(
      'Download is still in progress.' + #13#10 +
      'Cancelling now will leave CyberSentinel incomplete.' + #13#10 + #13#10 +
      'Are you sure you want to cancel?',
      mbConfirmation, MB_YESNO) = IDYES then
    begin
      Cancel  := True;
      Confirm := False;   // suppress the second default confirm dialog
    end
    else
    begin
      Cancel  := False;
      Confirm := False;
    end;
  end;
end;

// ── Download a file using PowerShell ─────────────────────────
function DownloadFile(const URL, Dest: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('powershell.exe',
    '-ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "Invoke-WebRequest' +
    ' -Uri ''' + URL + '''' +
    ' -OutFile ''' + Dest + '''' +
    ' -UseBasicParsing"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

// ── Try one Python candidate path; return True if it is 3.10+ ─
function TryPythonCandidate(const Candidate: String): Boolean;
var
  OutFile:  String;
  VerStr:   String;
  Script:   String;
  SpacePos: Integer;
  MajorVer: Integer;
  MinorVer: Integer;
begin
  Result  := False;
  OutFile := ExpandConstant('{tmp}\cs_cand.txt');
  Script  :=
    'import sys' + #13#10 +
    'f = open(r"' + OutFile + '", "w")' + #13#10 +
    'f.write(str(sys.version_info[0]) + " " + str(sys.version_info[1]))' + #13#10 +
    'f.close()' + #13#10;
  VerStr   := RunPyScript(Candidate, Script, OutFile);
  SpacePos := Pos(' ', VerStr);
  if SpacePos > 0 then begin
    MajorVer := StrToIntDef(Copy(VerStr, 1, SpacePos - 1), 0);
    MinorVer := StrToIntDef(Trim(Copy(VerStr, SpacePos + 1, Length(VerStr))), 0);
    Result   := (MajorVer = 3) and (MinorVer >= 10);
  end;
end;

// ── Resolve the exact Python 3.10+ path and persist to registry ─
// On a clean PC the newly-installed Python is NOT yet on PATH
// because the installer process inherited the old PATH env.
// We probe known install locations first, fall back to PATH last.
// Checks Python 3.13 down to 3.10 so any recent install is found.
procedure ResolvePythonPath;
var
  OutFile:   String;
  Script:    String;
  Candidate: String;
  MinorVer:  Integer;
begin
  PythonExePath := '';

  // 1. System-wide installs: Python 3.13 down to 3.10
  MinorVer := 13;
  while (PythonExePath = '') and (MinorVer >= 10) do begin
    Candidate := 'C:\Program Files\Python3' + IntToStr(MinorVer) + '\python.exe';
    if FileExists(Candidate) and TryPythonCandidate(Candidate) then
      PythonExePath := Candidate;
    if PythonExePath = '' then begin
      Candidate := 'C:\Python3' + IntToStr(MinorVer) + '\python.exe';
      if FileExists(Candidate) and TryPythonCandidate(Candidate) then
        PythonExePath := Candidate;
    end;
    MinorVer := MinorVer - 1;
  end;

  // 2. Per-user installs: Python 3.13 down to 3.10
  MinorVer := 13;
  while (PythonExePath = '') and (MinorVer >= 10) do begin
    Candidate := ExpandConstant('{localappdata}\Programs\Python\Python3' +
                   IntToStr(MinorVer) + '\python.exe');
    if FileExists(Candidate) and TryPythonCandidate(Candidate) then
      PythonExePath := Candidate;
    MinorVer := MinorVer - 1;
  end;

  // 3. Fallback: ask whatever 'python' is on PATH to report its own exe path
  if PythonExePath = '' then begin
    OutFile := ExpandConstant('{tmp}\cs_exe.txt');
    Script  :=
      'import sys' + #13#10 +
      'f = open(r"' + OutFile + '", "w")' + #13#10 +
      'f.write(sys.executable)' + #13#10 +
      'f.close()' + #13#10;
    PythonExePath := RunPyScript('python.exe', Script, OutFile);
  end;

  // 4. Absolute last resort — bare name on PATH
  if PythonExePath = '' then begin
    Log('WARNING: Cannot locate python.exe; falling back to bare name on PATH.');
    PythonExePath := 'python.exe';
  end;

  // FIX: Guard the PythonwExe write against the bare-name fallback.
  // When PythonExePath = 'python.exe', ExtractFilePath() returns '' so
  // PythonwExe would be written as the bare string 'pythonw.exe'.
  // CreateProcess with a bare name fails with ERROR_ACCESS_DENIED (code 5)
  // in an elevated installer session where the session PATH is stripped.
  // We only derive the path from ExtractFilePath when fully-qualified.
  RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonExe', PythonExePath);
  if ExtractFilePath(PythonExePath) <> '' then
    RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonwExe',
      ExtractFilePath(PythonExePath) + 'pythonw.exe')
  else begin
    Log('WARNING: PythonExePath is a bare name — PythonwExe will also be bare.' +
        ' GUI shortcut may fail to launch on some systems.');
    RegWriteStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'PythonwExe', 'pythonw.exe');
  end;
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
    SetStep('Python 3.10+ not found — downloading Python 3.12 installer...');
    PythonInstaller := ExpandConstant('{tmp}\python312_installer.exe');

    Downloaded := False;
    Attempts   := 0;
    while Attempts < 3 do begin
      if DownloadFile(
          'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe',
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
// ── Set "Run as administrator" flag on a .lnk file ───────────
// Inno Setup has no built-in [Icons] flag for this. Instead we patch the
// LinkFlags DWORD in the .lnk file header directly.
//
// .lnk file layout (Shell Link Binary File Format, MS-SHLLINK §2.1):
//   Offset 0x00–0x03 : HeaderSize (always 0x4C)
//   Offset 0x14–0x17 : LinkFlags  (DWORD, little-endian)
//
// SLDF_RUNAS_USER = 0x00002000  (bit 13 of LinkFlags)
//   = bit 5 (0x20) of the byte at offset 0x15 (the second byte of LinkFlags).
//
// In Inno Setup Pascal strings are 1-indexed, so:
//   byte at offset 0x15 (0-based) == Content[0x16] (1-based) == Content[22].
procedure SetShortcutRunAsAdmin(const LnkPath: String);
var
  Content: AnsiString;
begin
  if not FileExists(LnkPath) then Exit;
  if not LoadStringFromFile(LnkPath, Content) then Exit;
  if Length(Content) < 24 then Exit;           // sanity-check: header must be present
  Content[22] := Chr(Ord(Content[22]) or $20); // set SLDF_RUNAS_USER bit
  SaveStringToFile(LnkPath, Content, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
  BackupPath: String;
begin
  ConfigPath := ExpandConstant('{app}\config.json');
  BackupPath  := ExpandConstant('{app}\config.json.bak');

  if CurStep = ssInstall then begin
    if FileExists(ConfigPath) then
      RenameFile(ConfigPath, BackupPath);
  end;

  if CurStep = ssPostInstall then begin
    if FileExists(BackupPath) then begin
      DeleteFile(ConfigPath);
      RenameFile(BackupPath, ConfigPath);
    end;

    // ── Npcap missing warning ─────────────────────────────────────────────
    // install_helper.py::step_npcap() writes this flag when Npcap is absent.
    // We show a non-blocking informational popup so the user knows JA3
    // fingerprinting is disabled and how to enable it.
    if FileExists(ExpandConstant('{app}\npcap_missing.flag')) then begin
      DeleteFile(ExpandConstant('{app}\npcap_missing.flag'));
      MsgBox(
        'Npcap was not installed.' + #13#10 + #13#10 +
        'CyberSentinel has been installed successfully, but the JA3 TLS ' +
        'fingerprint monitor requires Npcap to capture network packets.' + #13#10 + #13#10 +
        'To enable it:' + #13#10 +
        '  1. Download Npcap from https://npcap.com/#download' + #13#10 +
        '  2. Run the installer and restart CyberSentinel.' + #13#10 + #13#10 +
        'All other features (file scanning, ML engine, AI analyst, ' +
        'cloud APIs) work normally without Npcap.',
        mbInformation, MB_OK
      );
    end;

    // ── Model download failure warning ────────────────────────────────────
    // install_helper.py::step_models() writes this flag when the GDrive
    // download fails, so the user knows the AI Analyst will be unavailable.
    if FileExists(ExpandConstant('{app}\model_download_failed.flag')) then begin
      DeleteFile(ExpandConstant('{app}\model_download_failed.flag'));
      MsgBox(
        'AI model download failed.' + #13#10 + #13#10 +
        'CyberSentinel has been installed, but the AI Analyst model could ' +
        'not be downloaded from Google Drive.' + #13#10 + #13#10 +
        'To fix this:' + #13#10 +
        '  1. Check your internet connection.' + #13#10 +
        '  2. Re-run the installer, or manually run:' + #13#10 +
        '       python installer_tools\install_helper.py --step models' +
        ' --install-dir "C:\CyberSentinel"' + #13#10 + #13#10 +
        'All other features (file scanning, ML engine, network monitor) ' +
        'work normally without the AI model.',
        mbError, MB_OK
      );
    end;

    // ── ETW configuration failure warning ─────────────────────────────────
    // install_helper.py::step_configure() writes this flag when auditpol or
    // the command-line capture registry key could not be applied.
    // Affects: daemon ETW thread (Event 4688), LoLBin detection of short-lived
    // processes, and AMSI script scanning from the ETW path.
    if FileExists(ExpandConstant('{app}\etw_config_failed.flag')) then begin
      DeleteFile(ExpandConstant('{app}\etw_config_failed.flag'));
      MsgBox(
        'ETW / Process Creation audit configuration failed.' + #13#10 + #13#10 +
        'CyberSentinel has been installed, but one or more Windows audit ' +
        'policy settings could not be applied automatically.' + #13#10 + #13#10 +
        'This affects the daemon''s ability to detect short-lived LOLBin ' +
        'abuse (e.g. sub-100ms certutil or mshta calls).' + #13#10 + #13#10 +
        'To fix manually, run both commands as Administrator:' + #13#10 +
        '  auditpol /set /subcategory:"Process Creation" /success:enable' + #13#10 +
        '  reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"' + #13#10 +
        '      /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f' + #13#10 + #13#10 +
        'See install_log.txt in C:\CyberSentinel for details.',
        mbError, MB_OK
      );
    end;

    // ── ScriptBlock logging failure warning ────────────────────────────────
    // install_helper.py::step_configure() writes this flag when the
    // PowerShell ScriptBlock logging registry key could not be applied.
    // Affects: AmsiMonitor (Event ID 4104) — obfuscated PowerShell detection.
    if FileExists(ExpandConstant('{app}\scriptblock_config_failed.flag')) then begin
      DeleteFile(ExpandConstant('{app}\scriptblock_config_failed.flag'));
      MsgBox(
        'PowerShell ScriptBlock logging could not be enabled.' + #13#10 + #13#10 +
        'CyberSentinel has been installed, but the registry key that enables ' +
        'PowerShell Event ID 4104 could not be written.' + #13#10 + #13#10 +
        'This means the AMSI monitor will not detect obfuscated PowerShell ' +
        'execution until this is corrected.' + #13#10 + #13#10 +
        'To fix manually, run as Administrator:' + #13#10 +
        '  reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"' + #13#10 +
        '      /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f' + #13#10 + #13#10 +
        'See install_log.txt in C:\CyberSentinel for details.',
        mbError, MB_OK
      );
    end;
  end;

  // ── After all shortcuts are written, mark GUI ones as "Run as admin" ──
  // This is the correct Inno Setup way to set the elevation bit on a shortcut.
  // We cannot use Flags: runasadmin in [Icons] — that flag does not exist.
  // ssDone fires after [Icons] entries have been created on disk.
  if CurStep = ssDone then begin
    if IsTaskSelected('desktopicon') then
      SetShortcutRunAsAdmin(ExpandConstant('{userdesktop}\CyberSentinel GUI.lnk'));
    if IsTaskSelected('startmenuicon') then
      SetShortcutRunAsAdmin(ExpandConstant('{group}\CyberSentinel GUI.lnk'));
  end;
end;


// ── Uninstall: offer to remove AI models ─────────────────────
function InitializeUninstall: Boolean;
var
  Answer: Integer;
begin
  Result := True;
  Answer := MsgBox(
    'Do you also want to remove downloaded AI models and user data?' + #13#10 +
    '(Choose No to keep models for a future reinstall.)',
    mbConfirmation, MB_YESNO);
  if Answer = IDYES then
    DelTree(ExpandConstant('{app}\models'), True, True, True);
end;

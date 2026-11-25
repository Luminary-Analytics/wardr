#ifndef WardrVersion
  #error Define WardrVersion with /DWardrVersion=major.minor.patch.
#endif
#ifndef WardrPayload
  #error Define WardrPayload with /DWardrPayload=absolute-path-to-payload.
#endif
#ifndef WardrDesktopExe
  #define WardrDesktopExe "..\..\desktop\target\release\wardr-desktop.exe"
#endif
#ifndef WardrArch
  #define WardrArch "x64"
#endif
#if WardrArch == "x64"
  #define WindowsArch "x64compatible"
#elif WardrArch == "arm64"
  #define WindowsArch "arm64"
#else
  #error WardrArch must be x64 or arm64.
#endif

[Setup]
AppId={{6D656C45-42C3-46A0-B0E9-F37C9E6A4274}
AppName=Wardr
AppVersion={#WardrVersion}
AppPublisher=Luminary Analytics
AppPublisherURL=https://getwardr.com/
AppSupportURL=https://getwardr.com/
AppUpdatesURL=https://getwardr.com/
DefaultDirName={localappdata}\Programs\Wardr
DisableDirPage=yes
DisableProgramGroupPage=yes
AllowNetworkDrive=no
AllowRootDirectory=no
AllowUNCPath=no
PrivilegesRequired=lowest
ArchitecturesAllowed={#WindowsArch}
ArchitecturesInstallIn64BitMode={#WindowsArch}
MinVersion=10.0
CloseApplications=no
RestartApplications=no
SetupMutex=Local\LuminaryAnalytics.Wardr.Setup
LicenseFile=..\..\LICENSE
SetupIconFile=wardr.ico
UninstallDisplayIcon={app}\wardr.ico
WizardStyle=modern
SetupLogging=yes
Compression=lzma2
SolidCompression=yes
OutputDir=..\..\dist
OutputBaseFilename=wardr-{#WardrVersion}-windows-{#WardrArch}-setup
VersionInfoVersion={#WardrVersion}
#ifdef WardrSignTool
SignTool=wardr
SignedUninstaller=yes
#endif

[Files]
Source: "{#WardrPayload}\python\*"; DestDir: "{tmp}\payload\python"; Flags: dontcopy noencryption recursesubdirs
Source: "{#WardrPayload}\wheelhouse\*.whl"; DestDir: "{tmp}\payload\wheelhouse"; Flags: dontcopy noencryption
Source: "{#WardrPayload}\install.py"; DestDir: "{tmp}\payload"; Flags: dontcopy noencryption
Source: "wardr.ico"; DestDir: "{app}"; Flags: ignoreversion
#ifdef WardrSignTool
Source: "{#WardrDesktopExe}"; DestDir: "{app}"; DestName: "Wardr.exe"; Flags: ignoreversion signonce
#else
Source: "{#WardrDesktopExe}"; DestDir: "{app}"; DestName: "Wardr.exe"; Flags: ignoreversion
#endif

[Icons]
Name: "{userprograms}\Wardr"; Filename: "{app}\Wardr.exe"; WorkingDir: "{app}"; IconFilename: "{app}\wardr.ico"; Comment: "Open Wardr"

[Run]
Filename: "{app}\Wardr.exe"; WorkingDir: "{app}"; Description: "Launch Wardr"; Flags: nowait postinstall skipifsilent

[Code]
const
  OwnershipMarker = '.wardr-native-install';
  OwnershipRecord = 'Luminary Analytics Wardr native installer v1' + #10;

function OwnsRuntime(): Boolean;
var
  Contents: AnsiString;
begin
  Result := LoadStringFromFile(ExpandConstant('{app}\') + OwnershipMarker, Contents);
  if Result then
    Result := Contents = OwnershipRecord;
end;

function InterpreterInUse(const Filename: String): Boolean;
var
  Stream: TFileStream;
begin
  Result := False;
  if not FileExists(Filename) then
    Exit;
  try
    Stream := TFileStream.Create(Filename, fmOpenReadWrite or fmShareExclusive);
    Stream.Free;
  except
    Result := True;
  end;
end;

function RuntimeInUse(): Boolean;
begin
  Result := InterpreterInUse(ExpandConstant('{app}\Wardr.exe')) or
    InterpreterInUse(ExpandConstant('{app}\venv\Scripts\python.exe')) or
    InterpreterInUse(ExpandConstant('{app}\python\python.exe'));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  PayloadDir, Parameters: String;
  ExitCode: Integer;
begin
  Result := '';
  try
    if OwnsRuntime() and RuntimeInUse() then begin
      Result := 'Quit Wardr from the system tray, then run Setup again.';
      Exit;
    end;
    ExtractTemporaryFiles('{tmp}\payload\*');
    PayloadDir := ExpandConstant('{tmp}\payload');
    Parameters := '-I "' + PayloadDir + '\install.py" --install-dir "' + ExpandConstant('{app}') + '"';
    if not ExecAndLogOutput(PayloadDir + '\python\python.exe', Parameters, PayloadDir,
      SW_HIDE, ewWaitUntilTerminated, ExitCode, nil) then
      Result := 'Wardr could not start its private Python installer. Check the Setup log.'
    else if ExitCode <> 0 then
      Result := 'Wardr could not prepare its private installation. Quit Wardr and check the Setup log (exit code ' + IntToStr(ExitCode) + ').';
  except
    Result := 'Wardr could not prepare the installer files. ' + GetExceptionMessage;
  end;
end;

procedure RemoveRuntimeDirectory(const Directory: String);
begin
  if DirExists(Directory) and not DelTree(Directory, True, True, True) then
    RaiseException('Quit Wardr from the system tray, then run the uninstaller again.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  LockPath: String;
begin
  if CurUninstallStep <> usUninstall then
    Exit;
  if not OwnsRuntime() then begin
    Log('Wardr runtime folders were kept because their installation marker was missing or invalid.');
    Exit;
  end;
  if RuntimeInUse() then
    RaiseException('Quit Wardr from the system tray, then run the uninstaller again.');
  RemoveRuntimeDirectory(ExpandConstant('{app}\venv'));
  RemoveRuntimeDirectory(ExpandConstant('{app}\python'));
  LockPath := ExpandConstant('{app}\.wardr-native-install.lock');
  if FileExists(LockPath) and not DeleteFile(LockPath) then
    RaiseException('Wardr could not remove its installation lock.');
  if not DeleteFile(ExpandConstant('{app}\') + OwnershipMarker) then
    RaiseException('Wardr could not remove its installation marker.');
end;

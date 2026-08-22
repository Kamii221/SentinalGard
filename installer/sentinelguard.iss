; Inno Setup script for SentinelGuard.
;
; Wraps the PyInstaller onedir build (dist/SentinelGuard/, produced by
; ../sentinelguard.spec) into a standard Windows installer: Program Files
; install, Start Menu + optional desktop shortcut, and an uninstaller
; that asks before deleting local data.
;
; This script only runs through Inno Setup's compiler (ISCC.exe), which
; is Windows-only -- it can't be compiled in this repo's Linux dev
; environment. Build it on Windows, or via the
; .github/workflows/build-windows-installer.yml CI workflow. See the
; README's "Windows installer" section for the full build steps.
;
; Usage (from a Windows machine, after `pyinstaller sentinelguard.spec`
; has already produced dist\SentinelGuard\ at the repo root):
;   iscc installer\sentinelguard.iss
;   iscc /DMyAppVersion=1.2.3 installer\sentinelguard.iss   (override version)

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif

#define MyAppName "SentinelGuard"
#define MyAppPublisher "SentinelGuard"
#define MyAppExeName "SentinelGuard.exe"
; Fixed GUID identifying this app across versions -- Inno Setup and
; Windows use it to recognize an existing install and offer an
; upgrade-in-place rather than a side-by-side reinstall. Do not change
; this once the installer has shipped.
#define MyAppId "{{D2D42AA5-5078-4E17-90AE-23BA492C24D8}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; The agent monitors processes, the registry, services, scheduled tasks,
; and the Windows Event Log, and needs to write into Program Files --
; all of which need an elevated install.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=SentinelGuard-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
; The PyInstaller onedir bundle -- the .exe plus its bundled Python
; runtime, PySide6/Qt plugins, and the config/rules/yara data files.
Source: "..\dist\SentinelGuard\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--gui"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--gui"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--gui"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent unchecked

[Code]
// Local data (the SQLite database, logs, and any quarantined files)
// lives under %APPDATA%\SentinelGuard, outside {app}, so the normal
// file-list uninstall never touches it. Ask explicitly instead of
// either silently deleting a user's alert history or silently leaving
// it behind forever.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{userappdata}\SentinelGuard');
    if DirExists(DataDir) then
    begin
      if MsgBox('Also delete SentinelGuard''s local data (database, logs, and quarantined files) in' + #13#10 + DataDir + '?' + #13#10#13#10 + 'This cannot be undone.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;

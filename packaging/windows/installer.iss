; Inno Setup script for Network Companion.
;
; This builds the actual thing an end user downloads and runs: a normal
; Windows installer (NetworkCompanionSetup.exe) that copies the already
;-built "Network Companion.exe" (see network-companion.spec / build.bat)
; into Program Files, adds Start Menu + Desktop shortcuts, and registers
; an uninstaller -- no Python, no pip, no build step on their machine.
;
; Build order (see build.bat, which now runs both steps):
;   1. pyinstaller network-companion.spec   -> dist\Network Companion.exe
;   2. iscc installer.iss                   -> Output\NetworkCompanionSetup.exe
;
; Requires Inno Setup (https://jrsoftware.org/isinfo.php) with its
; compiler, iscc.exe, on PATH.

#define MyAppName "Network Companion"
#define MyAppExeName "Network Companion.exe"
#define MyAppPublisher "Network Companion"

[Setup]
AppId={{6E9F1B1A-9C6D-4E9A-8C0A-2E9E9F5C7B21}}
AppName={#MyAppName}
AppVersion=1.0.0
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=NetworkCompanionSetup
OutputDir=Output
Compression=lzma2
SolidCompression=yes
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
; Packet capture needs administrator, and installing into Program Files
; does too, so require elevation for the installer itself up front rather
; than leaving the app to self-elevate on every single launch.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent

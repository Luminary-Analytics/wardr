# Windows setup

Build on Windows using Python 3.12 or later and [Inno Setup](https://jrsoftware.org/isinfo.php) 6.5 or later. Install `cryptography` in the build interpreter and put `ISCC.exe` on `PATH`. The shared payload builder verifies the published Wardr wheel and the bundled Python runtime before staging the offline installer files.

Run from the repository root. Set `$version` to the Wardr release you are packaging.

```powershell
$version = '0.2.1'
$payload = Join-Path $env:TEMP ('Wardr payload ' + [guid]::NewGuid())
$output = Join-Path (Get-Location) 'dist'
python -m pip install 'cryptography==50.0.2'
python packaging/build_payload.py --version $version --output $payload
if ($LASTEXITCODE -ne 0) { throw 'Unable to stage the Wardr payload' }
New-Item -ItemType Directory -Force $output | Out-Null
ISCC.exe "/DWardrVersion=$version" "/DWardrPayload=$payload" '/DWardrArch=x64' "/O$output" packaging/windows/wardr.iss
if ($LASTEXITCODE -ne 0) { throw 'Unable to build Wardr Setup' }
```

The setup file is `dist/wardr-<version>-windows-x64-setup.exe`. It installs into `%LOCALAPPDATA%\Programs\Wardr` for the current user and creates a Start menu shortcut. Open **Wardr** from Start to launch the dashboard. Keep its console open while Wardr monitors the machine. Press Ctrl+C in the console to stop it before running Setup or uninstalling.

Wardr uses its private virtual environment for the dashboard and signed in-app updates. The installed interpreter can also run terminal commands directly.

```powershell
& "$env:LOCALAPPDATA\Programs\Wardr\venv\Scripts\python.exe" -I -m wardr --help
& "$env:LOCALAPPDATA\Programs\Wardr\venv\Scripts\python.exe" -I -m wardr update --check
```

For install verification on a disposable Windows account or runner, use a new temporary path with spaces. Silent setup skips the dashboard launch. The path can be used again to verify a repeated installation.

```powershell
$setup = Join-Path $output "wardr-$version-windows-x64-setup.exe"
$testDir = Join-Path $env:TEMP ('Wardr install test ' + [guid]::NewGuid())
$args = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=`"$testDir`""
$process = Start-Process -FilePath $setup -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Wardr Setup failed with exit code $($process.ExitCode)" }
& "$testDir\venv\Scripts\python.exe" -I -c 'from wardr.updater import installation_problem; assert installation_problem() is None'
if ($LASTEXITCODE -ne 0) { throw 'Installed Wardr cannot update its private environment' }
```

Uninstall Wardr from Windows **Installed apps**. Setup removes its launcher and owned runtime folders. Reports and settings in `%LOCALAPPDATA%\Wardr` are retained. Windows Setup logs are available in `%TEMP%`.

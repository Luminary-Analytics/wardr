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

## Authenticode release signing

Use a Windows signing machine with Windows SDK `signtool.exe` and the official Microsoft Artifact Signing client. Complete organization identity validation, create a **Public Trust** certificate profile, and assign **Artifact Signing Certificate Profile Signer** for that profile to the signing identity. Record the full certificate subject from the approved profile independently of the file you are verifying. [Microsoft Artifact Signing setup](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) · [Signing client setup](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations)

The client metadata file specifies the region endpoint, account name and certificate profile name. Authenticate on the Windows signing machine through the client or through GitHub Actions with OpenID Connect. Keep credentials out of the metadata file, source control and build output. [Microsoft’s GitHub Actions integration](https://github.com/Azure/artifact-signing-action)

For new release builds, pass `'/DWardrSignTool'` to the build command and configure the named Inno Setup Sign Tool. The tool signs Setup and the uninstaller during compilation. Here `$signTool`, `$dlib` and `$metadata` are the absolute paths to SDK SignTool, the Artifact Signing client library and its metadata file.

```powershell
$signingCommand = 'wardr=$q{0}$q sign /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib $q{1}$q /dmdf $q{2}$q $f' -f $signTool, $dlib, $metadata
ISCC.exe "/DWardrVersion=$version" "/DWardrPayload=$payload" '/DWardrArch=x64' '/DWardrSignTool' "/S$signingCommand" "/O$output" packaging/windows/wardr.iss
if ($LASTEXITCODE -ne 0) { throw 'Unable to build and sign Wardr Setup' }
```

To sign an existing tested installer’s outer executable, pass its approved unsigned SHA-256 and an existing output directory. The script creates and verifies a separate signed copy. The compiled installer’s embedded uninstaller and temporary Setup copies need compile-time signing for their own signatures. [Inno Setup SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)

```powershell
./packaging/windows/Authenticode.ps1 -Installer $setup -ExpectedSha256 $approvedUnsignedSha256 `
  -ExpectedPublisherSubject $approvedSubject -SignToolPath $signTool `
  -AzureDlibPath $dlib -AzureMetadataPath $metadata -OutputDirectory $signedOutput -Json
```

Verify the final release installer on a current, clean Windows machine. Run the same verification for the installed `unins000.exe` from the signed setup smoke test. The output includes the final SHA-256, exact signer subject, certificate thumbprint and timestamp signer.

```powershell
./packaging/windows/Authenticode.ps1 -Installer $signedSetup `
  -ExpectedPublisherSubject $approvedSubject -SignToolPath $signTool -Json
```

In Windows File Explorer, use **Properties → Digital Signatures → Details** to confirm the trusted signature and the verified publisher’s legal name. The Windows SDK verifies embedded trust with `signtool verify /pa /all /tw /v`. Use the returned SHA-256 of the signed installer in release metadata. [Microsoft SignTool verification](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature)

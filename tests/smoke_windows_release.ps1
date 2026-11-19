#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\z')]
    [string]$BaselineVersion,

    [Parameter(Mandatory)]
    [ValidatePattern('\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\z')]
    [string]$TargetVersion
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

function Assert-WardrSignature {
    param([string]$Setup)

    $signature = Get-AuthenticodeSignature -LiteralPath $Setup
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw "Expected a valid, timestamped Authenticode signature on $Setup. Status: $($signature.StatusMessage)"
    }
    $publisher = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($publisher -cne 'Luminary Analytics, LLC') {
        throw "Unexpected Authenticode publisher on ${Setup}: $publisher"
    }
    $digest = (Get-FileHash -LiteralPath $Setup -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Verified timestamped Authenticode on $(Split-Path -Leaf $Setup) ($publisher, SHA-256 $digest)."
}

function Install-Wardr {
    param([string]$Setup, [string]$Location, [string]$Log)

    # A different /DIR still shares the product's registry entry and Start menu shortcut.
    $registration = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{6D656C45-42C3-46A0-B0E9-F37C9E6A4274}_is1'
    $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    if ((Test-Path -LiteralPath $registration) -or
        ($programs -and (Test-Path -LiteralPath (Join-Path $programs 'Wardr.lnk')))) {
        throw 'Setup smoke requires a Windows account without an existing Wardr setup registration or Start menu shortcut.'
    }

    $installer = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList (
        "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=`"$Location`" /LOG=`"$Log`"")
    if ($installer.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $Log -PathType Leaf) {
            Get-Content -LiteralPath $Log -Tail 40 | Write-Host
        }
        throw "Wardr setup exited with code $($installer.ExitCode)."
    }
    $interpreter = Join-Path $Location 'venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $interpreter -PathType Leaf)) {
        throw "Wardr setup did not create the isolated Python interpreter at $interpreter."
    }
    return $interpreter
}

function Remove-WardrInstallation {
    param([string]$Location, [switch]$AllowMissing)

    $uninstaller = Join-Path $Location 'unins000.exe'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        if ($AllowMissing) {
            return
        }
        throw "Wardr setup did not create its uninstaller at $uninstaller."
    }
    $process = Start-Process -FilePath $uninstaller -Wait -PassThru -ArgumentList (
        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART')
    if ($process.ExitCode -ne 0) {
        throw "Wardr uninstall exited with code $($process.ExitCode)."
    }
}

function Assert-WardrVersion {
    param([string]$Interpreter, [string]$ExpectedVersion)

    $inspection = & $Interpreter -I -c 'import json; from wardr.updater import current_version, installation_problem; print(json.dumps(dict(version=current_version(), problem=installation_problem())))'
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot import Wardr from the installed environment ($LASTEXITCODE)."
    }
    $installed = $inspection | ConvertFrom-Json
    if ($installed.version -cne $ExpectedVersion -or $null -ne $installed.problem) {
        throw "Expected an update-eligible Wardr $ExpectedVersion, found $($installed.version). $($installed.problem)"
    }
    Write-Host "Verified update-eligible Wardr $ExpectedVersion in the installed environment."
}

function Assert-WardrDashboard {
    param([string]$Interpreter, [string]$ExpectedVersion, [string]$Scratch)

    $stateDir = Join-Path $Scratch 'fresh target state'
    $stdout = Join-Path $Scratch 'target-dashboard.stdout'
    $stderr = Join-Path $Scratch 'target-dashboard.stderr'
    $dashboard = Start-Process -FilePath $Interpreter -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList (
            "-I -u -m wardr --state-dir `"$stateDir`" serve --port 0 --no-browser")
    try {
        # The access token is intentionally kept out of diagnostic output.
        $urlPattern = '(?m)^Wardr is running at http://127\.0\.0\.1:([0-9]{1,5})/#access=([A-Za-z0-9_-]{43})\r?$'
        $launchUrl = [regex]::Match('', $urlPattern)
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        do {
            if ($dashboard.HasExited) {
                throw "The Wardr dashboard exited before startup ($($dashboard.ExitCode))."
            }
            $output = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
            if ($output) {
                $launchUrl = [regex]::Match($output, $urlPattern)
                if ($launchUrl.Success) {
                    break
                }
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $launchUrl.Success) {
            throw 'Timed out waiting for the Wardr dashboard to start.'
        }

        $origin = 'http://127.0.0.1:' + $launchUrl.Groups[1].Value
        $headers = @{ 'X-Wardr-Token' = $launchUrl.Groups[2].Value; Origin = $origin }
        $request = @{ NoProxy = $true; MaximumRedirection = 0; TimeoutSec = 30 }
        $dashboardPage = Invoke-WebRequest @request -Uri "$origin/"
        if ($dashboardPage.StatusCode -ne 200 -or $dashboardPage.Content -notmatch 'id="updates-button"') {
            throw 'The installed dashboard did not expose the Updates control.'
        }
        $accepted = Invoke-RestMethod @request -Uri "$origin/api/update/check" -Method Post `
            -Headers $headers -ContentType 'application/json' -Body '{}'
        if ($accepted.ok -ne $true) {
            throw 'The installed dashboard did not accept the update check.'
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(110)
        do {
            $update = Invoke-RestMethod @request -Uri "$origin/api/update" -Headers $headers
            if ($update.state -cne 'checking') {
                break
            }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($update.state -cne 'current' -or $update.current_version -cne $ExpectedVersion) {
            throw "Fresh Wardr $ExpectedVersion did not report current after checking the signed live feed. $($update.message)"
        }
        Write-Host "Fresh Wardr $ExpectedVersion served its dashboard and the signed live update check reported current."
    }
    finally {
        if (-not $dashboard.HasExited) {
            $dashboard.Kill($true)
            if (-not $dashboard.WaitForExit(10000)) {
                throw 'Timed out stopping the disposable Wardr dashboard.'
            }
        }
        $dashboard.Dispose()
    }
}

if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [System.Runtime.InteropServices.Architecture]::X64) {
    throw 'This smoke test requires a native Windows x64 runner.'
}
if ([version]$TargetVersion -le [version]$BaselineVersion) {
    throw 'The target release must be newer than the baseline.'
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) "Wardr release smoke $([Guid]::NewGuid().ToString('N'))"
$downloads = Join-Path $scratch 'downloads'
$targetInstall = Join-Path $scratch 'fresh target install'
$baselineInstall = Join-Path $scratch 'upgrade baseline install'
$activeInstall = $null
try {
    New-Item -ItemType Directory -Path $downloads | Out-Null
    & python -I (Join-Path $PSScriptRoot 'fetch_live_release.py') `
        --platform windows --arch x64 --output $downloads $BaselineVersion $TargetVersion
    if ($LASTEXITCODE -ne 0) {
        throw "Fetching and verifying live signed release files failed ($LASTEXITCODE)."
    }

    $baselineWheel = Join-Path $downloads "wardr-$BaselineVersion-py3-none-any.whl"
    $baselineSetup = Join-Path $downloads "wardr-$BaselineVersion-windows-x64-setup.exe"
    $targetSetup = Join-Path $downloads "wardr-$TargetVersion-windows-x64-setup.exe"
    Assert-WardrSignature $baselineSetup
    Assert-WardrSignature $targetSetup

    $activeInstall = $targetInstall
    $targetPython = Install-Wardr $targetSetup $targetInstall (Join-Path $scratch 'target-install.log')
    Assert-WardrVersion $targetPython $TargetVersion
    Assert-WardrDashboard $targetPython $TargetVersion $scratch
    # The two installers share Inno Setup's per-user app registration.
    Remove-WardrInstallation $targetInstall
    $activeInstall = $baselineInstall
    $baselinePython = Install-Wardr $baselineSetup $baselineInstall (Join-Path $scratch 'baseline-install.log')
    Assert-WardrVersion $baselinePython $BaselineVersion
    & $baselinePython -I (Join-Path $PSScriptRoot 'smoke_update.py') `
        --installed-python $baselinePython --live-target $TargetVersion $baselineWheel
    if ($LASTEXITCODE -ne 0) {
        throw "The live Windows dashboard upgrade exited with code $LASTEXITCODE."
    }
    Assert-WardrVersion $baselinePython $TargetVersion
    Remove-WardrInstallation $baselineInstall
    $activeInstall = $null
    Write-Host "Verified native Windows x64 setup and live in-place update from Wardr $BaselineVersion to $TargetVersion."
}
finally {
    if ($activeInstall) {
        try {
            Remove-WardrInstallation $activeInstall -AllowMissing
        }
        catch {
            Write-Warning "Could not uninstall the disposable Wardr setup. $_"
        }
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory)] [string] $Installer,
    [Parameter(Mandatory)] [string] $ExpectedPublisherSubject,
    [Parameter(Mandatory)] [string] $SignToolPath,
    [Parameter(ParameterSetName = 'Verify')]
    [Parameter(Mandatory, ParameterSetName = 'Azure')]
    [ValidatePattern('\A[0-9a-fA-F]{64}\z')] [string] $ExpectedSha256,
    [Parameter(Mandatory, ParameterSetName = 'Azure')] [string] $OutputDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Azure')] [string] $AzureDlibPath,
    [Parameter(Mandatory, ParameterSetName = 'Azure')] [string] $AzureMetadataPath,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run Authenticode verification and signing on Windows.'
}

function Get-LocalFile([string] $Path) {
    $item = Get-Item -LiteralPath $Path
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular file at $Path."
    }
    return $item
}

function Invoke-SignTool([string[]] $Arguments) {
    $messages = & $signTool.FullName @Arguments 2>&1
    $code = $LASTEXITCODE
    Write-Verbose ($messages -join [Environment]::NewLine)
    if ($code -ne 0) {
        throw "SignTool $($Arguments[0]) failed or reported warnings (exit code $code)."
    }
}

function Assert-ExpectedHash([string] $Path) {
    if ($ExpectedSha256 -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        throw 'The installer SHA-256 differs from the approved artifact.'
    }
}

function Confirm-Publisher([string] $Path) {
    Invoke-SignTool @('verify', '/pa', '/all', '/tw', '/v', $Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw 'The installer must have a valid embedded Authenticode signature and trusted timestamp.'
    }
    if ($signature.SignerCertificate.Subject -cne $ExpectedPublisherSubject) {
        throw 'The signer certificate subject differs from the approved Windows publisher.'
    }
    return [pscustomobject]@{
        File = $Path
        Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        PublisherSubject = $signature.SignerCertificate.Subject
        PublisherThumbprint = $signature.SignerCertificate.Thumbprint
        TimestampSubject = $signature.TimeStamperCertificate.Subject
    }
}

$installerFile = Get-LocalFile $Installer
$signTool = Get-LocalFile $SignToolPath
if ($signTool.Name -ne 'signtool.exe') {
    throw 'SignToolPath must point to Windows SDK signtool.exe.'
}
$setupName = '\Awardr-[0-9]+\.[0-9]+\.[0-9]+-windows-(x64|arm64)-setup\.exe\z'
if ($installerFile.Name -notmatch $setupName -and $installerFile.Name -notmatch '\Aunins[0-9]{3}\.exe\z') {
    throw 'Specify a Wardr Windows setup executable or the generated uninstaller.'
}

if ($PSCmdlet.ParameterSetName -eq 'Azure') {
    if ($installerFile.Name -notmatch $setupName) {
        throw 'Only a canonical Wardr Windows setup executable can be signed by this script.'
    }
    $dlib = Get-LocalFile $AzureDlibPath
    if ($dlib.Name -ne 'Azure.CodeSigning.Dlib.dll') {
        throw 'AzureDlibPath must point to the official Azure Artifact Signing client library.'
    }
    $metadataFile = Get-LocalFile $AzureMetadataPath
    $metadata = Get-Content -LiteralPath $metadataFile.FullName -Raw | ConvertFrom-Json
    if ($metadata.Endpoint -notmatch '\Ahttps://[a-z0-9]+\.codesigning\.azure\.net/?\z' -or
        [string]::IsNullOrWhiteSpace($metadata.CodeSigningAccountName) -or
        [string]::IsNullOrWhiteSpace($metadata.CertificateProfileName)) {
        throw 'The Azure metadata must name a Microsoft Artifact Signing endpoint, account, and profile.'
    }

    $outputDir = Get-Item -LiteralPath $OutputDirectory
    if ($outputDir -isnot [IO.DirectoryInfo]) {
        throw 'Choose an existing output directory for the signed installer.'
    }
    $outputPath = Join-Path $outputDir.FullName $installerFile.Name
    if (Test-Path -LiteralPath $outputPath) {
        throw 'The signed output already exists. Choose a different output directory.'
    }
    $staging = Join-Path $outputDir.FullName ('.wardr-sign-' + [guid]::NewGuid())
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        $stagedFile = Join-Path $staging $installerFile.Name
        [IO.File]::Copy($installerFile.FullName, $stagedFile)
        Assert-ExpectedHash $stagedFile
        if ((Get-AuthenticodeSignature -LiteralPath $stagedFile).Status -ne 'NotSigned') {
            throw 'The approved setup executable already has a signature.'
        }
        Invoke-SignTool @('sign', '/fd', 'SHA256', '/tr', 'http://timestamp.acs.microsoft.com',
            '/td', 'SHA256', '/dlib', $dlib.FullName, '/dmdf', $metadataFile.FullName, $stagedFile)
        $proof = Confirm-Publisher $stagedFile
        [IO.File]::Move($stagedFile, $outputPath)
        $proof.File = $outputPath
    }
    finally {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
else {
    Assert-ExpectedHash $installerFile.FullName
    $proof = Confirm-Publisher $installerFile.FullName
}

if ($Json) {
    $proof | ConvertTo-Json
}
else {
    $proof
}

$ErrorActionPreference = "Stop"
# Keep this script ASCII-only so Windows PowerShell 5.1 can run it both as a file and through irm | iex.

function Get-Sha256([string]$Path) {
    $Stream = [System.IO.File]::OpenRead($Path)
    try {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($Hasher.ComputeHash($Stream))).Replace("-", "").ToLowerInvariant()
        } finally {
            $Hasher.Dispose()
        }
    } finally {
        $Stream.Dispose()
    }
}

function Invoke-YanxuVersion([string]$Path) {
    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Path
    $StartInfo.Arguments = "--version"
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) { throw "could not start the downloaded yanxu.exe" }
        $Stdout = $Process.StandardOutput.ReadToEnd()
        $Stderr = $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $Process.ExitCode
            Text = ($Stdout + $Stderr).Trim()
        }
    } finally {
        $Process.Dispose()
    }
}

$Repository = if ($env:YANXU_REPOSITORY) { $env:YANXU_REPOSITORY } else { "YanXuLang/yanxu" }
$Version = if ($env:YANXU_VERSION) { $env:YANXU_VERSION } else { "latest" }
$InstallDir = if ($env:YANXU_INSTALL_DIR) { $env:YANXU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\Yanxu\bin" }
$AssetDir = if ($env:YANXU_ASSET_DIR) { [System.IO.Path]::GetFullPath($env:YANXU_ASSET_DIR) } else { $null }
try {
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
} catch {
    throw "Yanxu installation failed: invalid installation directory: $($_.Exception.Message)"
}

$Architecture = if ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}
switch ($Architecture) {
    "AMD64" { $Target = "x86_64-pc-windows-msvc" }
    "ARM64" { $Target = "aarch64-pc-windows-msvc" }
    default { throw "Yanxu installation failed: unsupported processor architecture $Architecture" }
}

$Asset = "yanxu-$Target.zip"
$ChecksumAsset = "yanxu-$Target.sha256"
if ($AssetDir -and $Version -eq "latest") {
    throw "Yanxu installation failed: YANXU_VERSION is required when YANXU_ASSET_DIR is set"
} elseif ($Version -eq "latest") {
    try {
        $ApiHeaders = @{
            Accept = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
        }
        if ($env:YANXU_GITHUB_TOKEN) {
            $ApiHeaders.Authorization = "Bearer $($env:YANXU_GITHUB_TOKEN)"
        }
        $Release = Invoke-RestMethod -Headers $ApiHeaders -Uri "https://api.github.com/repos/$Repository/releases/latest"
        if (-not $Release.tag_name) { throw "the repository has no installable stable release" }
        $Tag = $Release.tag_name
    } catch {
        throw "Yanxu installation failed: could not query the latest release: $($_.Exception.Message)"
    }
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
    $VersionLabel = "latest release $Tag"
} else {
    $Tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
    $VersionLabel = $Tag
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("yanxu-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $TempDir | Out-Null
$StagedPath = $null

try {
    Write-Host "Installing Yanxu $VersionLabel ($Target)..."
    $ArchivePath = Join-Path $TempDir $Asset
    $ChecksumPath = Join-Path $TempDir $ChecksumAsset
    if ($AssetDir) {
        $LocalArchive = Join-Path $AssetDir $Asset
        $LocalChecksum = Join-Path $AssetDir $ChecksumAsset
        if (-not (Test-Path $LocalArchive)) { throw "local asset directory is missing $Asset" }
        if (-not (Test-Path $LocalChecksum)) { throw "local asset directory is missing $ChecksumAsset" }
        Copy-Item $LocalArchive $ArchivePath
        Copy-Item $LocalChecksum $ChecksumPath
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Asset" -OutFile $ArchivePath
        Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$ChecksumAsset" -OutFile $ChecksumPath
    }

    $Expected = ((Get-Content $ChecksumPath -Raw).Trim() -split "\s+")[0]
    if ($Expected -notmatch "^[0-9A-Fa-f]{64}$") { throw "invalid SHA-256 checksum file" }
    $Expected = $Expected.ToLowerInvariant()
    $Actual = Get-Sha256 $ArchivePath
    if ($Expected -ne $Actual) { throw "SHA-256 checksum mismatch" }

    $Expanded = Join-Path $TempDir "expanded"
    Expand-Archive -Path $ArchivePath -DestinationPath $Expanded
    $Binary = Get-ChildItem -Path $Expanded -Filter "yanxu.exe" -Recurse | Select-Object -First 1
    if (-not $Binary) { throw "the release archive does not contain yanxu.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $InstalledPath = Join-Path $InstallDir "yanxu.exe"
    $StagedPath = Join-Path $InstallDir (".yanxu-" + [guid]::NewGuid() + ".exe")
    Copy-Item $Binary.FullName $StagedPath
    $VersionProbe = Invoke-YanxuVersion $StagedPath
    if ($VersionProbe.ExitCode -ne 0) { throw "the downloaded yanxu.exe cannot run on this system: $($VersionProbe.Text)" }
    $VersionText = $VersionProbe.Text
    if (-not $VersionText) { throw "the downloaded yanxu.exe returned no version information" }
    $ProductName = [string]::Concat([char]0x8A00, [char]0x5E8F)
    $ExpectedVersion = "$ProductName " + $Tag.TrimStart("v")
    if ($VersionText -ne $ExpectedVersion) { throw "release tag $Tag does not match binary version: $VersionText" }
    Move-Item -Force $StagedPath $InstalledPath
    $StagedPath = $null

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = @($UserPath -split ";" | Where-Object { $_ })
    if ($PathParts -notcontains $InstallDir) {
        $NewPath = (($PathParts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        Write-Host "Added $InstallDir to the user PATH; it will be available in new terminals."
    }
    $ProcessPathParts = @($env:Path -split ";" | Where-Object { $_ })
    if ($ProcessPathParts -notcontains $InstallDir) { $env:Path = "$env:Path;$InstallDir" }
    Write-Host "Yanxu was installed to $InstalledPath"
    Write-Host "Verified: $VersionText"
} catch {
    Write-Error "Yanxu installation failed: $($_.Exception.Message)"
    exit 1
} finally {
    if ($StagedPath) { Remove-Item -Force -ErrorAction SilentlyContinue $StagedPath }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
}

$ErrorActionPreference = "Stop"

$Repository = if ($env:YANXU_REPOSITORY) { $env:YANXU_REPOSITORY } else { "YanXuLang/yanxu" }
$Version = if ($env:YANXU_VERSION) { $env:YANXU_VERSION } else { "latest" }
$InstallDir = if ($env:YANXU_INSTALL_DIR) { $env:YANXU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\Yanxu\bin" }

$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($Architecture) {
    "X64" { $Target = "x86_64-pc-windows-msvc" }
    "Arm64" { $Target = "aarch64-pc-windows-msvc" }
    default { throw "言序安装失败：暂不支持处理器架构 $Architecture" }
}

$Asset = "yanxu-$Target.zip"
$ChecksumAsset = "yanxu-$Target.sha256"
if ($Version -eq "latest") {
    try {
        $Releases = @(Invoke-RestMethod -Headers @{ Accept = "application/vnd.github+json" } -Uri "https://api.github.com/repos/$Repository/releases?per_page=1")
        if (-not $Releases -or -not $Releases[0].tag_name) { throw "仓库尚未发布可安装版本" }
        $Tag = $Releases[0].tag_name
    } catch {
        throw "言序安装失败：无法查询最新发行版：$($_.Exception.Message)"
    }
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
    $VersionLabel = "最新版 $Tag"
} else {
    $Tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
    $VersionLabel = $Tag
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("yanxu-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    Write-Host "正在安装言序 $VersionLabel（$Target）…"
    $ArchivePath = Join-Path $TempDir $Asset
    $ChecksumPath = Join-Path $TempDir $ChecksumAsset
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Asset" -OutFile $ArchivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$ChecksumAsset" -OutFile $ChecksumPath

    $Expected = ((Get-Content $ChecksumPath -Raw).Trim() -split "\s+")[0].ToLowerInvariant()
    $Actual = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()
    if ($Expected -ne $Actual) { throw "SHA-256 校验不一致" }

    $Expanded = Join-Path $TempDir "expanded"
    Expand-Archive -Path $ArchivePath -DestinationPath $Expanded
    $Binary = Get-ChildItem -Path $Expanded -Filter "yanxu.exe" -Recurse | Select-Object -First 1
    if (-not $Binary) { throw "发行包内没有 yanxu.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force $Binary.FullName (Join-Path $InstallDir "yanxu.exe")

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = @($UserPath -split ";" | Where-Object { $_ })
    if ($PathParts -notcontains $InstallDir) {
        $NewPath = (($PathParts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "已把 $InstallDir 加入用户 PATH；新终端会自动生效。"
    }
    Write-Host "言序已安装到 $(Join-Path $InstallDir 'yanxu.exe')"
    Write-Host "运行 yanxu --version 验证安装。"
} catch {
    Write-Error "言序安装失败：$($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
}

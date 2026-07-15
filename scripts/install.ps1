$ErrorActionPreference = "Stop"

$Repository = if ($env:YANXU_REPOSITORY) { $env:YANXU_REPOSITORY } else { "YanXuLang/yanxu" }
$Version = if ($env:YANXU_VERSION) { $env:YANXU_VERSION } else { "latest" }
$InstallDir = if ($env:YANXU_INSTALL_DIR) { $env:YANXU_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\Yanxu\bin" }
$AssetDir = if ($env:YANXU_ASSET_DIR) { [System.IO.Path]::GetFullPath($env:YANXU_ASSET_DIR) } else { $null }
try {
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
} catch {
    throw "言序安装失败：安装目录无效：$($_.Exception.Message)"
}

$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($Architecture) {
    "X64" { $Target = "x86_64-pc-windows-msvc" }
    "Arm64" { $Target = "aarch64-pc-windows-msvc" }
    default { throw "言序安装失败：暂不支持处理器架构 $Architecture" }
}

$Asset = "yanxu-$Target.zip"
$ChecksumAsset = "yanxu-$Target.sha256"
if ($AssetDir -and $Version -eq "latest") {
    throw "言序安装失败：使用 YANXU_ASSET_DIR 时必须通过 YANXU_VERSION 指定版本"
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
        if (-not $Release.tag_name) { throw "仓库尚未发布可安装的稳定版本" }
        $Tag = $Release.tag_name
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
$StagedPath = $null

try {
    Write-Host "正在安装言序 $VersionLabel（$Target）…"
    $ArchivePath = Join-Path $TempDir $Asset
    $ChecksumPath = Join-Path $TempDir $ChecksumAsset
    if ($AssetDir) {
        $LocalArchive = Join-Path $AssetDir $Asset
        $LocalChecksum = Join-Path $AssetDir $ChecksumAsset
        if (-not (Test-Path $LocalArchive)) { throw "本地制品目录缺少 $Asset" }
        if (-not (Test-Path $LocalChecksum)) { throw "本地制品目录缺少 $ChecksumAsset" }
        Copy-Item $LocalArchive $ArchivePath
        Copy-Item $LocalChecksum $ChecksumPath
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Asset" -OutFile $ArchivePath
        Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$ChecksumAsset" -OutFile $ChecksumPath
    }

    $Expected = ((Get-Content $ChecksumPath -Raw).Trim() -split "\s+")[0]
    if ($Expected -notmatch "^[0-9A-Fa-f]{64}$") { throw "SHA-256 校验文件格式无效" }
    $Expected = $Expected.ToLowerInvariant()
    $Actual = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()
    if ($Expected -ne $Actual) { throw "SHA-256 校验不一致" }

    $Expanded = Join-Path $TempDir "expanded"
    Expand-Archive -Path $ArchivePath -DestinationPath $Expanded
    $Binary = Get-ChildItem -Path $Expanded -Filter "yanxu.exe" -Recurse | Select-Object -First 1
    if (-not $Binary) { throw "发行包内没有 yanxu.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $InstalledPath = Join-Path $InstallDir "yanxu.exe"
    $StagedPath = Join-Path $InstallDir (".yanxu-" + [guid]::NewGuid() + ".exe")
    Copy-Item $Binary.FullName $StagedPath
    $VersionOutput = @(& $StagedPath --version 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "下载的 yanxu.exe 无法在当前系统运行：$($VersionOutput -join [Environment]::NewLine)" }
    $VersionText = ($VersionOutput -join " ").Trim()
    if (-not $VersionText) { throw "下载的 yanxu.exe 没有返回版本信息" }
    $ExpectedVersion = "言序 " + $Tag.TrimStart("v")
    if ($VersionText -ne $ExpectedVersion) { throw "发行标签 $Tag 与二进制版本不一致：$VersionText" }
    Move-Item -Force $StagedPath $InstalledPath
    $StagedPath = $null

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = @($UserPath -split ";" | Where-Object { $_ })
    if ($PathParts -notcontains $InstallDir) {
        $NewPath = (($PathParts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        Write-Host "已把 $InstallDir 加入用户 PATH；新终端会自动生效。"
    }
    $ProcessPathParts = @($env:Path -split ";" | Where-Object { $_ })
    if ($ProcessPathParts -notcontains $InstallDir) { $env:Path = "$env:Path;$InstallDir" }
    Write-Host "言序已安装到 $InstalledPath"
    Write-Host "已验证：$VersionText"
} catch {
    Write-Error "言序安装失败：$($_.Exception.Message)"
    exit 1
} finally {
    if ($StagedPath) { Remove-Item -Force -ErrorAction SilentlyContinue $StagedPath }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
}

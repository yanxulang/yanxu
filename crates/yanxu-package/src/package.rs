//! 言序包清单、锁文件与可复现依赖解析。
//!
//! `言序.toml` 可以声明路径、Git 和中央索引依赖；`言序.lock` 固定最终
//! 版本、Git 修订和内容 SHA-256。解析器在使用锁文件时仍会校验缓存内容，
//! 因而损坏或被悄悄改写的依赖不会进入模块执行。

mod archive;

use crate::path_policy::{
    ModuleAuthority, PACKAGE_PATH_NON_PORTABLE_CODE, PackagePathDecision, PackagePathError,
    PackagePathPurpose, PackagePathReason, PortablePackagePaths, ResolvedPackageFile,
    TrustedPackageRoots, package_path_decision, portable_case_fold, portable_package_path,
    resolve_existing_package_path, resolve_existing_portable_relative_path,
};
#[cfg(target_os = "wasi")]
use crate::path_policy::{WasiPackageDirectory, WasiPackageDirectoryEntry, WasiPackageEntry};
use archive::{
    ARCHIVE_LIMITS, ArchiveLimits, extract_archive_bytes_safely, find_manifest_root,
    validate_archive_relative_path, validate_existing_package_archive,
};
#[cfg(test)]
use archive::{extract_archive_safely, extract_archive_with_limits};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use unicode_normalization::UnicodeNormalization;

#[cfg(not(target_os = "wasi"))]
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};

pub const MANIFEST_NAME: &str = "言序.toml";
pub const LOCK_NAME: &str = "言序.lock";
pub const MANIFEST_FORMAT_VERSION: u32 = 2;
pub const LOCK_FORMAT_VERSION: u32 = 2;
pub const SUPPORTED_MANIFEST_FORMATS: &[u32] = &[1, 2];
pub const SUPPORTED_LOCK_FORMATS: &[u32] = &[1, 2];
pub const DEFAULT_REGISTRY: &str = "https://get.yanxu.dev/packages/v1";
pub const ARCHIVE_MAX_COMPRESSED_BYTES: u64 = 32 * 1024 * 1024;
pub const ARCHIVE_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const ARCHIVE_MAX_EXPANDED_BYTES: u64 = 128 * 1024 * 1024;
pub const ARCHIVE_MAX_ENTRIES: usize = 4_096;
pub const ARCHIVE_MAX_PATH_BYTES: usize = 512;
pub const NATIVE_ARTIFACT_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const NATIVE_ARTIFACT_MAX_COUNT: usize = 32;
pub const NATIVE_ARTIFACT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const PACKAGE_TREE_MAX_FILE_BYTES: u64 = NATIVE_ARTIFACT_MAX_BYTES;
const PACKAGE_TREE_MAX_BYTES: u64 = NATIVE_ARTIFACT_MAX_TOTAL_BYTES + ARCHIVE_MAX_EXPANDED_BYTES;
const PACKAGE_TREE_MAX_ENTRIES: usize = 100_000;
const PACKAGE_TREE_MAX_DEPTH: usize = 128;
const REGISTRY_INDEX_MAX_VERSIONS: usize = 10_000;
const REGISTRY_RELEASE_URL_MAX_BYTES: usize = 4_096;
const REGISTRY_VULNERABILITY_MAX_COUNT: usize = 1_024;
const REGISTRY_VULNERABILITY_ID_MAX_BYTES: usize = 256;
const REGISTRY_VULNERABILITY_SUMMARY_MAX_BYTES: usize = 8_192;
const MANIFEST_TOML_SYNTAX_ERROR: &str = "TOML 格式无效；请检查对应行的语法";
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub name: String,
    pub version: Version,
    pub entry: PathBuf,
    pub description: Option<String>,
    pub license: Option<String>,
    pub authors: Vec<String>,
    pub minimum_yanxu: Option<VersionReq>,
    pub dependencies: BTreeMap<String, Dependency>,
    pub dependency_packages: BTreeMap<String, String>,
    pub dev_dependencies: BTreeMap<String, Dependency>,
    pub dev_dependency_packages: BTreeMap<String, String>,
    pub exports: BTreeMap<String, PathBuf>,
    pub resources: Vec<PathBuf>,
    pub build: BuildConfig,
    pub application: Option<ApplicationConfig>,
    pub workspace_members: Vec<PathBuf>,
    pub native: Option<NativePackage>,
    pub permissions: crate::permissions::PermissionSet,
    pub root: PathBuf,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationConfig {
    pub kind: ApplicationKind,
    pub name: String,
    pub identifier: String,
    pub version: Version,
    pub icon: Option<PathBuf>,
    pub company: Option<String>,
    pub minimum_system_version: Option<String>,
    pub window: WindowConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationKind {
    CommandLine,
    Graphical,
}

impl ApplicationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandLine => "命令行",
            Self::Graphical => "图形",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowConfig {
    pub width: u32,
    pub height: u32,
    pub minimum_width: u32,
    pub minimum_height: u32,
    pub maximum_width: Option<u32>,
    pub maximum_height: Option<u32>,
    pub resizable: bool,
    pub high_dpi: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationConfigEdit {
    pub kind: ApplicationKind,
    pub name: String,
    pub identifier: String,
    pub version: String,
    pub icon: Option<PathBuf>,
    pub company: Option<String>,
    pub minimum_system_version: Option<String>,
    pub window: WindowConfig,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            width: 960,
            height: 640,
            minimum_width: 1,
            minimum_height: 1,
            maximum_width: None,
            maximum_height: None,
            resizable: true,
            high_dpi: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildConfig {
    pub target: String,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            target: "字节码".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePackage {
    pub abi_version: u32,
    pub artifacts: BTreeMap<String, NativeArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeArtifact {
    #[serde(default = "default_native_abi")]
    pub abi: u32,
    pub target: String,
    pub path: String,
    pub checksum: String,
    #[serde(default)]
    pub size: u64,
}

const fn default_native_abi() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dependency {
    Path {
        path: PathBuf,
        requirement: Option<VersionReq>,
    },
    Git {
        url: String,
        revision: String,
        requirement: Option<VersionReq>,
    },
    Registry {
        requirement: VersionReq,
        registry: String,
    },
}

impl fmt::Display for Dependency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { path, requirement } => {
                let path = safe_local_source_path_for_display(path);
                write!(
                    formatter,
                    "路径 {path}{}",
                    requirement
                        .as_ref()
                        .map_or_else(String::new, |version| format!(" ({version})"))
                )
            }
            Self::Git {
                url,
                revision,
                requirement,
            } => {
                let url = safe_git_source_value_for_display(url);
                let revision = safe_git_revision_for_display(revision);
                write!(
                    formatter,
                    "Git {url}#{revision}{}",
                    requirement
                        .as_ref()
                        .map_or_else(String::new, |version| format!(" ({version})"))
                )
            }
            Self::Registry {
                requirement,
                registry,
            } => write!(
                formatter,
                "索引 {} ({requirement})",
                safe_registry_source_value_for_display(registry)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockFile {
    pub lock_version: u32,
    pub manifest_checksum: String,
    #[serde(default = "current_target")]
    pub target: String,
    #[serde(default = "package_core_version")]
    pub generator: String,
    #[serde(default)]
    pub root_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub root_dev_dependencies: BTreeMap<String, String>,
    #[serde(rename = "package", default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub checksum: String,
    pub entry: String,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub exports: BTreeMap<String, String>,
    #[serde(default)]
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_yanxu: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RegistryIndex {
    versions: Vec<RegistryRelease>,
}

#[derive(Debug, Clone, Deserialize)]
struct RegistryRelease {
    version: String,
    url: String,
    checksum: String,
    #[serde(default)]
    yanked: Option<bool>,
    #[serde(default)]
    vulnerabilities: Option<Vec<RegistryVulnerability>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[doc(hidden)]
pub struct RegistryVulnerability {
    pub id: String,
    pub severity: String,
    pub summary: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub withdrawn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RegistryReleaseMetadata {
    pub url: String,
    pub checksum: String,
    pub yanked: Option<bool>,
    pub vulnerabilities: Option<Vec<RegistryVulnerability>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependency {
    pub locked: LockedPackage,
    /// 已经规范化并通过清单、版本与内容校验的包根目录。
    pub root: PathBuf,
    pub entry: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionGraph {
    pub root_dependencies: BTreeMap<String, String>,
    pub root_dev_dependencies: BTreeMap<String, String>,
    pub packages: BTreeMap<String, ResolvedDependency>,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageArtifact {
    pub path: PathBuf,
    pub checksum: String,
    pub bytes: u64,
    pub entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorManifest {
    pub format_version: u32,
    pub target: String,
    pub packages: BTreeMap<String, VendorPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorPackage {
    pub path: String,
    pub checksum: String,
    pub source: String,
    pub revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub message: String,
    pub path: PathBuf,
    pub line: Option<usize>,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(
                formatter,
                "包清单有误：{}:{line}：{}",
                self.path.display(),
                self.message
            ),
            None => write!(
                formatter,
                "包解析有误：{}：{}",
                self.path.display(),
                self.message
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

impl ManifestError {
    #[doc(hidden)]
    pub fn code(&self) -> &'static str {
        match self.message.split_once(']').map(|(code, _)| code) {
            Some("[PACKAGE_MODULE_RESERVED_PATH") => {
                crate::path_policy::PACKAGE_MODULE_RESERVED_PATH_CODE
            }
            Some("[PACKAGE_PATH_NON_PORTABLE") => {
                crate::path_policy::PACKAGE_PATH_NON_PORTABLE_CODE
            }
            Some("[PACKAGE_PATH_INVALID") => crate::path_policy::PACKAGE_PATH_INVALID_CODE,
            Some("[PACKAGE_ROOT_INVALID") => crate::path_policy::PACKAGE_ROOT_INVALID_CODE,
            Some("[PACKAGE_MODULE_OUTSIDE_ROOT") => {
                crate::path_policy::PACKAGE_MODULE_OUTSIDE_ROOT_CODE
            }
            Some("[PACKAGE_PATH_RESERVED") => crate::path_policy::PACKAGE_PATH_RESERVED_CODE,
            Some("[PACKAGE_PATH_COLLISION") => crate::path_policy::PACKAGE_PATH_COLLISION_CODE,
            _ => "PACKAGE000",
        }
    }

    #[doc(hidden)]
    pub fn diagnostic_message(&self) -> &str {
        self.message
            .strip_prefix('[')
            .and_then(|message| message.split_once("] ").map(|(_, message)| message))
            .unwrap_or(&self.message)
    }
}

/// 模块导入解析结果。可信包内容在解析阶段已经打开；包外路径必须先由宿主
/// 权限系统授权，再调用 [`Self::open`] 建立绑定最终对象的文件令牌。
#[derive(Debug)]
#[doc(hidden)]
pub struct ResolvedImportFile {
    inner: ResolvedImportFileInner,
}

#[derive(Debug)]
enum ResolvedImportFileInner {
    Package(ResolvedPackageFile),
    External(PathBuf),
}

impl ResolvedImportFile {
    fn package(resolved: ResolvedPackageFile) -> Self {
        Self {
            inner: ResolvedImportFileInner::Package(resolved),
        }
    }

    fn external(path: PathBuf) -> Self {
        Self {
            inner: ResolvedImportFileInner::External(path),
        }
    }

    pub fn path(&self) -> &Path {
        match &self.inner {
            ResolvedImportFileInner::Package(resolved) => resolved.path(),
            ResolvedImportFileInner::External(path) => path,
        }
    }

    pub fn open(self) -> Result<ResolvedPackageFile, ManifestError> {
        match self.inner {
            ResolvedImportFileInner::Package(resolved) => Ok(resolved),
            ResolvedImportFileInner::External(path) => open_external_module_file(&path),
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8], kind: &str) -> Result<(), ManifestError> {
    crate::storage::atomic_write(path, bytes)
        .map_err(|error| manifest_error(path, None, format!("不能原子写入{kind}：{error}")))
}

fn acquire_project_lock(root: &Path) -> Result<crate::storage::ProjectLock, ManifestError> {
    crate::storage::ProjectLock::acquire(root)
        .map_err(|error| manifest_error(root, None, format!("不能取得包项目锁：{error}")))
}

pub fn discover(start: impl AsRef<Path>) -> Result<Option<Manifest>, ManifestError> {
    let start = start.as_ref();
    let absolute_start = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| manifest_error(start, None, format!("不能定位当前目录：{error}")))?
            .join(start)
    };
    let absolute_start = absolute_normalized(&absolute_start)?;
    let host_candidates = discovery_manifest_candidates(&absolute_start);
    let Some(host_nearest) = host_candidates.first() else {
        return Ok(None);
    };
    let Some(outer_root) = host_candidates
        .last()
        .and_then(|manifest| manifest.parent())
    else {
        return load(host_nearest).map(Some);
    };
    let Some(resolved_start) = resolve_discovery_start_within_root(outer_root, &absolute_start)?
    else {
        return load(host_nearest).map(Some);
    };
    let resolved_candidates = discovery_manifest_candidates(&resolved_start);
    load(resolved_candidates.first().unwrap_or(host_nearest)).map(Some)
}

fn discovery_manifest_candidates(start: &Path) -> Vec<PathBuf> {
    let mut directory = if start.is_dir() {
        start.to_path_buf()
    } else {
        start
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    let mut manifests = Vec::new();
    loop {
        let candidate = directory.join(MANIFEST_NAME);
        if candidate.is_file() {
            manifests.push(candidate);
        }
        if !directory.pop() {
            break;
        }
    }
    manifests
}

fn resolve_discovery_start_within_root(
    root: &Path,
    requested: &Path,
) -> Result<Option<PathBuf>, ManifestError> {
    let Ok(relative) = requested.strip_prefix(root) else {
        return Ok(None);
    };
    let mut probe = relative.to_path_buf();
    loop {
        match resolve_existing_portable_relative_path(root, &probe) {
            Ok(path) => return Ok(Some(path)),
            Err(error)
                if error.code == crate::path_policy::PACKAGE_PATH_INVALID_CODE
                    && error.message.contains("不存在") => {}
            Err(error) => return Err(package_path_manifest_error(requested, error)),
        }
        if !probe.pop() {
            return Ok(fs::canonicalize(root).ok());
        }
    }
}

fn resolve_existing_discovered_path(path: &Path) -> Result<Option<PathBuf>, ManifestError> {
    let absolute = absolute_normalized(path)?;
    let candidates = discovery_manifest_candidates(&absolute);
    let Some(outer_root) = candidates.last().and_then(|manifest| manifest.parent()) else {
        return Ok(None);
    };
    let Ok(relative) = absolute.strip_prefix(outer_root) else {
        return Ok(None);
    };
    match resolve_existing_portable_relative_path(outer_root, relative) {
        Ok(resolved) => Ok(Some(resolved)),
        Err(error)
            if error.code == crate::path_policy::PACKAGE_PATH_INVALID_CODE
                && error.message.contains("不存在") =>
        {
            Ok(None)
        }
        Err(error) => Err(package_path_manifest_error(path, error)),
    }
}

impl TrustedPackageRoots {
    /// 发现包含 `start` 的最深包并把其规范根加入当前授权集合。
    ///
    /// 模块加载器在校验普通文件导入前调用此方法，可识别尚未通过 `包:`
    /// 导入访问过的嵌套路径依赖，避免把依赖私有源码误当成应用自身内容。
    #[doc(hidden)]
    pub fn insert_discovered(
        &mut self,
        start: impl AsRef<Path>,
    ) -> Result<Option<Manifest>, ManifestError> {
        let start = start.as_ref();
        let manifest = discover(start)?;
        if let Some(manifest) = &manifest {
            self.insert(&manifest.root)
                .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
            let absolute_start = if start.is_absolute() {
                start.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| {
                        manifest_error(start, None, format!("不能定位当前目录：{error}"))
                    })?
                    .join(start)
            };
            let manifest_identity = fs::canonicalize(&manifest.path).map_err(|error| {
                manifest_error(
                    &manifest.path,
                    None,
                    format!("不能复验发现的包清单：{error}"),
                )
            })?;
            if let Some(alias_root) = discovery_manifest_candidates(&absolute_start)
                .into_iter()
                .find(|candidate| {
                    fs::canonicalize(candidate).is_ok_and(|path| path == manifest_identity)
                })
                .and_then(|candidate| candidate.parent().map(Path::to_path_buf))
            {
                self.insert_alias(&alias_root, &manifest.root)
                    .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
            }
        }
        Ok(manifest)
    }

    /// 在文件系统读取前准备普通或 `包:` 导入的可信根并完成词法授权。
    fn prepare_import(
        &mut self,
        current_base: &Path,
        requested_or_joined: &Path,
        allow_cross_package: bool,
    ) -> Result<(), ManifestError> {
        self.validate_requested_portability(requested_or_joined)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
        if let Err(discovery_error) = self.insert_discovered(requested_or_joined) {
            self.validate_requested_import(current_base, requested_or_joined, allow_cross_package)
                .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
            return Err(discovery_error);
        }
        self.validate_requested_import(current_base, requested_or_joined, allow_cross_package)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))
    }

    /// 完成模块导入授权并返回解析阶段已经打开的最终文件句柄。
    #[doc(hidden)]
    pub fn resolve_import_file(
        &mut self,
        current_base: &Path,
        requested_or_joined: &Path,
        allow_cross_package: bool,
    ) -> Result<(ResolvedImportFile, ModuleAuthority), ManifestError> {
        self.prepare_import(current_base, requested_or_joined, allow_cross_package)?;
        let resolved_requested = resolve_existing_discovered_path(requested_or_joined)?;
        let requested_for_resolution = resolved_requested.as_deref().unwrap_or(requested_or_joined);
        let resolved = match self
            .resolve_existing_module_file(requested_for_resolution)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?
        {
            Some(resolved) => ResolvedImportFile::package(resolved),
            None => {
                let canonical = fs::canonicalize(requested_for_resolution).map_err(|error| {
                    manifest_error(
                        requested_or_joined,
                        None,
                        format!("不能定位模块路径：{error}"),
                    )
                })?;
                self.insert_discovered(&canonical)?;
                match self
                    .resolve_existing_module_file(&canonical)
                    .map_err(|error| package_path_manifest_error(&canonical, error))?
                {
                    Some(resolved) => ResolvedImportFile::package(resolved),
                    None => ResolvedImportFile::external(canonical),
                }
            }
        };
        let canonical = resolved.path().to_path_buf();
        self.insert_discovered(&canonical)?;
        let resolved_current = resolve_existing_discovered_path(current_base)?;
        let current_for_authority = resolved_current.as_deref().unwrap_or(current_base);
        let authority = self
            .authorize_import(
                current_for_authority,
                requested_for_resolution,
                &canonical,
                allow_cross_package,
            )
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
        Ok((resolved, authority))
    }
}

fn open_external_module_file(path: &Path) -> Result<ResolvedPackageFile, ManifestError> {
    open_external_module_file_with_hook(path, || Ok(()))
}

fn open_external_module_file_with_hook(
    path: &Path,
    before_bound_open: impl FnOnce() -> Result<(), ManifestError>,
) -> Result<ResolvedPackageFile, ManifestError> {
    let canonical = path.to_path_buf();
    let before_file = open_regular_file_for_snapshot(&canonical)
        .map_err(|error| manifest_error(&canonical, None, format!("不能预先打开模块：{error}")))?;
    let before = before_file.metadata().map_err(|error| {
        manifest_error(&canonical, None, format!("不能检查预先打开的模块：{error}"))
    })?;
    if !is_regular_file_metadata(&before) {
        return Err(manifest_error(
            &canonical,
            None,
            "模块必须是普通文件，不得为符号链接或特殊文件",
        ));
    }
    before_bound_open()?;
    let file = open_regular_file_for_snapshot(&canonical)
        .map_err(|error| manifest_error(&canonical, None, format!("不能打开模块：{error}")))?;
    let opened = file.metadata().map_err(|error| {
        manifest_error(&canonical, None, format!("不能检查已打开的模块：{error}"))
    })?;
    let verified = fs::canonicalize(path)
        .map_err(|error| manifest_error(path, None, format!("不能复验模块路径：{error}")))?;
    let verification = open_regular_file_for_snapshot(&verified).map_err(|error| {
        manifest_error(
            &verified,
            None,
            format!("不能重新打开模块以复验身份：{error}"),
        )
    })?;
    let verified_metadata = verification
        .metadata()
        .map_err(|error| manifest_error(&verified, None, format!("不能复验模块身份：{error}")))?;
    let before_matches_opened =
        same_opened_file_identity(&before_file, &file).map_err(|error| {
            manifest_error(
                &canonical,
                None,
                format!("不能比较模块打开前后的身份：{error}"),
            )
        })?;
    let opened_matches_verified =
        same_opened_file_identity(&file, &verification).map_err(|error| {
            manifest_error(&canonical, None, format!("不能复验模块文件身份：{error}"))
        })?;
    if verified != canonical
        || !is_regular_file_metadata(&opened)
        || !is_regular_file_metadata(&verified_metadata)
        || !before_matches_opened
        || !opened_matches_verified
    {
        return Err(manifest_error(
            &canonical,
            None,
            "模块在解析期间被替换或经目录重定向改变了身份",
        ));
    }
    Ok(ResolvedPackageFile::new(canonical, file))
}

pub fn load(path: impl AsRef<Path>) -> Result<Manifest, ManifestError> {
    let path = path.as_ref().to_path_buf();
    let text = fs::read_to_string(&path)
        .map_err(|error| manifest_error(&path, None, format!("不能读取：{error}")))?;
    let root = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    parse(&text, path, root)
}

pub fn resolve_dependency(base: &Path, name: &str) -> Result<PathBuf, ManifestError> {
    resolve_dependency_info(base, name).map(|dependency| dependency.entry)
}

/// 解析依赖并同时返回它经过锁文件校验的包根与入口。
pub fn resolve_dependency_info(
    base: &Path,
    name: &str,
) -> Result<ResolvedDependency, ManifestError> {
    let manifest = discover(base)?.ok_or_else(|| {
        manifest_error(
            base,
            None,
            format!("引用包“{name}”时未找到 {MANIFEST_NAME}"),
        )
    })?;
    resolve_dependency_scoped(Some(&manifest.root), base, name)
}

/// 在一次顶层包执行或检查中解析依赖。
///
/// 依赖只能通过顶层预解析图与各包锁定的依赖边访问；不再于运行时回退读取
/// 任意传递包清单，也不能绕过公开导出表访问包内文件。
pub fn resolve_dependency_scoped(
    package_root: Option<&Path>,
    current_base: &Path,
    name: &str,
) -> Result<ResolvedDependency, ManifestError> {
    let manifest = match package_root {
        Some(root) => discover(root)?,
        None => discover(current_base)?,
    }
    .ok_or_else(|| {
        manifest_error(
            current_base,
            None,
            format!("引用包“{name}”时未找到 {MANIFEST_NAME}"),
        )
    })?;
    let offline = std::env::var_os("YANXU_OFFLINE").is_some();
    let graph = cached_or_resolve_graph(&manifest, offline)?;
    let canonical_base =
        fs::canonicalize(current_base).unwrap_or_else(|_| current_base.to_path_buf());
    let canonical_manifest_root =
        fs::canonicalize(&manifest.root).unwrap_or_else(|_| manifest.root.clone());
    let current_is_application_source = canonical_base.starts_with(&canonical_manifest_root);
    let (alias, export) = name
        .split_once('/')
        .map_or((name, None), |(alias, export)| (alias, Some(export)));
    let dependency_edges = graph
        .packages
        .values()
        .filter(|dependency| {
            canonical_base.starts_with(&dependency.root)
                && (!current_is_application_source
                    || (dependency.root != canonical_manifest_root
                        && dependency.root.starts_with(&canonical_manifest_root)))
        })
        .max_by_key(|dependency| dependency.root.components().count())
        .map_or(&graph.root_dependencies, |dependency| {
            &dependency.locked.dependencies
        });
    let id = dependency_edges.get(alias).ok_or_else(|| {
        manifest_error(
            &manifest.path,
            None,
            format!("当前包未声明依赖别名“{alias}”；请先执行 yanbao 加 {alias}"),
        )
    })?;
    let mut dependency = graph.packages.get(id).cloned().ok_or_else(|| {
        manifest_error(
            manifest.root.join(LOCK_NAME),
            None,
            format!("锁文件依赖边指向不存在的包“{id}”"),
        )
    })?;
    let export_name = export.unwrap_or("默认");
    let exported = dependency.locked.exports.get(export_name).ok_or_else(|| {
        manifest_error(
            &manifest.path,
            None,
            format!(
                "包“{}”未公开导出模块“{export_name}”；可用导出：{}",
                dependency.locked.name,
                dependency
                    .locked
                    .exports
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        )
    })?;
    package_path_decision(Path::new(exported), PackagePathPurpose::ModuleSource)
        .map_err(|error| package_path_manifest_error(&dependency.root, error))?;
    let entry = resolve_existing_package_path(
        &dependency.root,
        Path::new(exported),
        PackagePathPurpose::ModuleSource,
    )
    .map_err(|error| package_path_manifest_error(&dependency.root, error))?;
    let metadata = fs::symlink_metadata(&entry).map_err(|error| {
        manifest_error(&entry, None, format!("不能检查锁定包导出模块：{error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(manifest_error(
            &entry,
            None,
            "锁定包导出模块必须是普通文件，不得为目录、符号链接或特殊文件",
        ));
    }
    let mut roots = TrustedPackageRoots::default();
    roots
        .insert(&dependency.root)
        .map_err(|error| package_path_manifest_error(&entry, error))?;
    roots
        .authorize_module(&entry, &entry)
        .map_err(|error| package_path_manifest_error(&entry, error))?;
    dependency.entry = entry;
    Ok(dependency)
}

/// 解析全部依赖并写入或验证 `言序.lock`。
pub fn ensure_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let graph = resolve_graph(manifest, offline)?;
    cache_graph(manifest, graph.clone());
    direct_dependencies(&graph, &graph.root_dependencies, &manifest.path)
}

pub fn ensure_lock_with_dev(
    manifest: &Manifest,
    offline: bool,
) -> Result<ResolutionGraph, ManifestError> {
    let graph = resolve_graph(manifest, offline)?;
    cache_graph(manifest, graph.clone());
    Ok(graph)
}

pub fn resolve_graph(manifest: &Manifest, offline: bool) -> Result<ResolutionGraph, ManifestError> {
    resolve_graph_mode(manifest, offline, true, true)
}

/// 在不改写锁文件和运行时图缓存的前提下重新选择依赖，用于更新预演。
pub fn plan_update(manifest: &Manifest, offline: bool) -> Result<ResolutionGraph, ManifestError> {
    resolve_graph_mode(manifest, offline, false, false)
}

fn resolve_graph_mode(
    manifest: &Manifest,
    offline: bool,
    use_existing: bool,
    write: bool,
) -> Result<ResolutionGraph, ManifestError> {
    let _project_lock = write
        .then(|| acquire_project_lock(&manifest.root))
        .transpose()?;
    resolve_graph_mode_locked(manifest, offline, use_existing, write)
}

fn resolve_graph_mode_locked(
    manifest: &Manifest,
    offline: bool,
    use_existing: bool,
    write: bool,
) -> Result<ResolutionGraph, ManifestError> {
    let manifest_checksum = file_checksum(&manifest.path)?;
    resolve_graph_mode_locked_with_checksum(
        manifest,
        offline,
        use_existing,
        write,
        manifest_checksum,
    )
}

fn resolve_graph_mode_locked_with_checksum(
    manifest: &Manifest,
    offline: bool,
    use_existing: bool,
    write: bool,
    manifest_checksum: String,
) -> Result<ResolutionGraph, ManifestError> {
    let lock_path = manifest.root.join(LOCK_NAME);
    let existing = use_existing
        .then(|| read_optional_lock(&lock_path))
        .transpose()?
        .flatten()
        .filter(|lock| {
            lock.lock_version == LOCK_FORMAT_VERSION
                && lock.manifest_checksum == manifest_checksum
                && lock.target == current_target()
        });
    let mut builder = GraphBuilder {
        offline,
        existing: existing.as_ref(),
        packages: BTreeMap::new(),
        visiting: Vec::new(),
        target: current_target(),
        native_allowed: manifest.permissions.native_extensions_allowed(),
    };
    let root_dependencies = builder.resolve_table(
        manifest,
        &manifest.dependencies,
        &manifest.dependency_packages,
    )?;
    let root_dev_dependencies = builder.resolve_table(
        manifest,
        &manifest.dev_dependencies,
        &manifest.dev_dependency_packages,
    )?;
    let graph = ResolutionGraph {
        root_dependencies,
        root_dev_dependencies,
        packages: builder.packages,
        target: builder.target,
    };
    let mut packages = graph
        .packages
        .values()
        .map(|dependency| dependency.locked.clone())
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.id.cmp(&right.id));
    let lock = LockFile {
        lock_version: LOCK_FORMAT_VERSION,
        manifest_checksum,
        target: graph.target.clone(),
        generator: package_core_version(),
        root_dependencies: graph.root_dependencies.clone(),
        root_dev_dependencies: graph.root_dev_dependencies.clone(),
        packages,
    };
    if write && existing.as_ref() != Some(&lock) {
        write_lock(&lock_path, &lock)?;
    }
    Ok(graph)
}

/// 在项目跨进程锁的整个生命周期内解析依赖并执行构建操作。
///
/// 调用方应把所有清单、锁文件、源码和资源读取放在闭包中，避免依赖解析
/// 完成后被并发的安装、更新或清单编辑替换输入。闭包不得再次调用会取得同一
/// 项目锁的包写操作。
pub fn with_locked_resolution<T, E>(
    manifest: &Manifest,
    offline: bool,
    operation: impl FnOnce(ResolutionGraph) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<ManifestError>,
{
    let _project_lock = acquire_project_lock(&manifest.root).map_err(E::from)?;
    let graph = resolve_graph_mode_locked(manifest, offline, true, true).map_err(E::from)?;
    cache_graph(manifest, graph.clone());
    operation(graph)
}

pub fn update_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let graph = resolve_graph_mode(manifest, offline, false, true)?;
    graph_cache()
        .lock()
        .expect("graph cache poisoned")
        .insert(graph_cache_key(&manifest.root), graph.clone());
    direct_dependencies(&graph, &graph.root_dependencies, &manifest.path)
}

pub fn read_lock(path: impl AsRef<Path>) -> Result<LockFile, ManifestError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| manifest_error(path, None, format!("不能检查锁文件：{error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(manifest_error(
            path,
            None,
            "锁文件必须是普通文件，不得为符号链接或特殊文件",
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| manifest_error(path, None, format!("不能读取锁文件：{error}")))?;
    let lock: LockFile = toml::from_str(&text)
        .map_err(|_| manifest_error(path, None, "锁文件格式无效；请检查或重新生成锁文件"))?;
    validate_lock_source_security(path, &lock)?;
    if !SUPPORTED_LOCK_FORMATS.contains(&lock.lock_version) {
        return Err(manifest_error(
            path,
            None,
            format!(
                "不支持锁文件版本 {}，本工具支持版本 1、2",
                lock.lock_version
            ),
        ));
    }
    Ok(lock)
}

fn read_optional_lock(path: &Path) -> Result<Option<LockFile>, ManifestError> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_lock(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(manifest_error(
            path,
            None,
            format!("不能检查锁文件：{error}"),
        )),
    }
}

/// 只读检查锁文件与当前清单、目标和格式是否一致，不解析或下载依赖。
pub fn validate_lock(manifest: &Manifest) -> Result<LockFile, ManifestError> {
    let path = manifest.root.join(LOCK_NAME);
    let lock = read_lock(&path)?;
    if lock.lock_version != LOCK_FORMAT_VERSION {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "锁文件格式 {} 应迁移为 {LOCK_FORMAT_VERSION}",
                lock.lock_version
            ),
        ));
    }
    if lock.target != current_target() {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "锁文件目标 {} 与当前目标 {} 不符",
                lock.target,
                current_target()
            ),
        ));
    }
    let checksum = file_checksum(&manifest.path)?;
    if lock.manifest_checksum != checksum {
        return Err(manifest_error(
            &path,
            None,
            "锁文件与清单不一致；请运行 yanbao install",
        ));
    }
    Ok(lock)
}

/// 生成格式 2 的最小项目清单。创建目录与源码模板仍由上层工程工具负责。
pub fn manifest_template(name: &str) -> Result<String, String> {
    validate_package_name(name)?;
    Ok(format!(
        "[包]\n格式 = 2\n名称 = {name:?}\n版本 = \"0.1.0\"\n言序 = \">=1.1.7\"\n入口 = \"src/主.yx\"\n\n[依赖]\n\n[权限]\n文件 = []\n网络 = []\n本地网络 = false\nTCP监听 = []\nUDP绑定 = []\n环境 = []\n进程 = false\n原生扩展 = false\n图形界面 = false\n剪贴板 = false\n文件对话框 = false\n系统通知 = false\n托盘 = false\n打开外部地址 = false\n全局快捷键 = false\n\n[导出]\n默认 = \"src/主.yx\"\n\n[构建]\n目标 = \"字节码\"\n"
    ))
}

/// Generate the official graphical application template consumed by yanbao.
/// Registry resolution is the release default; a path may be supplied by
/// workspace tooling and tests without changing package semantics.
pub fn gui_manifest_template(name: &str, gui_path: Option<&Path>) -> Result<String, String> {
    validate_package_name(name)?;
    let identifier = format!("dev.yanxu.app-{}", &short_hash(name)[..12]);
    let dependency = gui_path.map_or_else(
        || "言窗 = { 包 = \"yanxu-gui\", 版 = \"^1.0\" }".to_string(),
        |path| {
            format!(
                "言窗 = {{ 包 = \"yanxu-gui\", 路径 = {:?}, 版 = \"^1.0\" }}",
                path.to_string_lossy()
            )
        },
    );
    Ok(format!(
        "[包]\n格式 = 2\n名称 = {name:?}\n版本 = \"0.1.0\"\n言序 = \">=1.1.15\"\n入口 = \"src/主.yx\"\n\n[依赖]\n{dependency}\n\n[应用]\n类型 = \"图形\"\n名称 = {name:?}\n标识 = {identifier:?}\n版本 = \"0.1.0\"\n\n[应用.窗口]\n宽 = 800\n高 = 600\n最小宽 = 480\n最小高 = 320\n可缩放 = true\n高分屏 = true\n\n[权限]\n文件 = []\n网络 = []\n本地网络 = false\nTCP监听 = []\nUDP绑定 = []\n环境 = []\n进程 = false\n原生扩展 = true\n图形界面 = true\n剪贴板 = false\n文件对话框 = false\n系统通知 = false\n托盘 = false\n打开外部地址 = false\n全局快捷键 = false\n\n[导出]\n默认 = \"src/主.yx\"\n\n[构建]\n目标 = \"字节码\"\n"
    ))
}

/// 使用包核心的唯一清单语义增删依赖。写入后会立即重新加载验证；失败时恢复原文。
pub fn edit_dependency(
    manifest_path: impl AsRef<Path>,
    alias: &str,
    package_name: Option<&str>,
    dependency: Option<&Dependency>,
    development: bool,
) -> Result<Manifest, ManifestError> {
    validate_package_name(alias)
        .map_err(|message| manifest_error(manifest_path.as_ref(), None, message))?;
    if let Some(dependency) = dependency {
        validate_dependency_source_security(dependency)
            .map_err(|message| manifest_error(manifest_path.as_ref(), None, message))?;
    }
    let manifest_path = manifest_path.as_ref();
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let _project_lock = acquire_project_lock(root)?;
    let original = fs::read_to_string(manifest_path)
        .map_err(|error| manifest_error(manifest_path, None, format!("不能读取以修改：{error}")))?;
    load(manifest_path)?;
    let normalized = normalize_manifest_toml(&original);
    let mut document: toml::Value = toml::from_str(&normalized)
        .map_err(|error| sanitized_manifest_toml_error(manifest_path, &normalized, &error))?;
    let root = document
        .as_table_mut()
        .ok_or_else(|| manifest_error(manifest_path, None, "清单根必须为 TOML 表"))?;
    let aliases = if development {
        ["开发依赖", "dev-dependencies"]
    } else {
        ["依赖", "dependencies"]
    };
    let table_key = aliases
        .iter()
        .find(|key| root.contains_key(**key))
        .copied()
        .unwrap_or(aliases[0]);
    if !root.contains_key(table_key) {
        root.insert(table_key.into(), toml::Value::Table(toml::map::Map::new()));
    }
    let table = root
        .get_mut(table_key)
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| manifest_error(manifest_path, None, format!("【{table_key}】须为表")))?;
    match dependency {
        Some(dependency) => {
            let actual = package_name.unwrap_or(alias);
            validate_package_name(actual)
                .map_err(|message| manifest_error(manifest_path, None, message))?;
            table.insert(
                alias.into(),
                dependency_manifest_value(alias, actual, dependency),
            );
        }
        None => {
            if table.remove(alias).is_none() {
                return Err(manifest_error(
                    manifest_path,
                    None,
                    format!("未声明依赖别名“{alias}”"),
                ));
            }
        }
    }
    let updated = toml::to_string_pretty(&document)
        .map_err(|error| manifest_error(manifest_path, None, format!("不能生成清单：{error}")))?;
    atomic_write(manifest_path, updated.as_bytes(), "清单")?;
    match load(manifest_path) {
        Ok(manifest) => {
            graph_cache()
                .lock()
                .expect("graph cache poisoned")
                .remove(&graph_cache_key(&manifest.root));
            Ok(manifest)
        }
        Err(error) => {
            let _ = atomic_write(manifest_path, original.as_bytes(), "清单回滚");
            Err(error)
        }
    }
}

/// 通过包核心原子写入或移除应用配置，写入后使用同一清单解析器复核。
pub fn edit_application(
    manifest_path: impl AsRef<Path>,
    application: Option<&ApplicationConfigEdit>,
) -> Result<Manifest, ManifestError> {
    let manifest_path = manifest_path.as_ref();
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let _project_lock = acquire_project_lock(root)?;
    let original = fs::read_to_string(manifest_path)
        .map_err(|error| manifest_error(manifest_path, None, format!("不能读取以修改：{error}")))?;
    load(manifest_path)?;
    let normalized = normalize_manifest_toml(&original);
    let mut document: toml::Value = toml::from_str(&normalized)
        .map_err(|error| sanitized_manifest_toml_error(manifest_path, &normalized, &error))?;
    let document = document
        .as_table_mut()
        .ok_or_else(|| manifest_error(manifest_path, None, "清单根必须为 TOML 表"))?;
    document.remove("应用");
    document.remove("application");
    if let Some(application) = application {
        let mut table = toml::map::Map::new();
        table.insert(
            "类型".into(),
            toml::Value::String(application.kind.as_str().into()),
        );
        table.insert("名称".into(), toml::Value::String(application.name.clone()));
        table.insert(
            "标识".into(),
            toml::Value::String(application.identifier.clone()),
        );
        table.insert(
            "版本".into(),
            toml::Value::String(application.version.clone()),
        );
        if let Some(icon) = &application.icon {
            table.insert(
                "图标".into(),
                toml::Value::String(icon.to_string_lossy().into_owned()),
            );
        }
        if let Some(company) = &application.company {
            table.insert("公司".into(), toml::Value::String(company.clone()));
        }
        if let Some(version) = &application.minimum_system_version {
            table.insert("最低系统版本".into(), toml::Value::String(version.clone()));
        }
        let window = &application.window;
        let mut window_table = toml::map::Map::new();
        for (name, value) in [
            ("宽", window.width),
            ("高", window.height),
            ("最小宽", window.minimum_width),
            ("最小高", window.minimum_height),
        ] {
            window_table.insert(name.into(), toml::Value::Integer(i64::from(value)));
        }
        if let Some(value) = window.maximum_width {
            window_table.insert("最大宽".into(), toml::Value::Integer(i64::from(value)));
        }
        if let Some(value) = window.maximum_height {
            window_table.insert("最大高".into(), toml::Value::Integer(i64::from(value)));
        }
        window_table.insert("可缩放".into(), toml::Value::Boolean(window.resizable));
        window_table.insert("高分屏".into(), toml::Value::Boolean(window.high_dpi));
        table.insert("窗口".into(), toml::Value::Table(window_table));
        document.insert("应用".into(), toml::Value::Table(table));
    }
    let updated = toml::to_string_pretty(&document)
        .map_err(|error| manifest_error(manifest_path, None, format!("不能生成清单：{error}")))?;
    atomic_write(manifest_path, updated.as_bytes(), "清单")?;
    match load(manifest_path) {
        Ok(manifest) => {
            graph_cache()
                .lock()
                .expect("graph cache poisoned")
                .remove(&graph_cache_key(&manifest.root));
            Ok(manifest)
        }
        Err(error) => {
            let _ = atomic_write(manifest_path, original.as_bytes(), "清单回滚");
            Err(error)
        }
    }
}

fn dependency_manifest_value(
    alias: &str,
    package_name: &str,
    dependency: &Dependency,
) -> toml::Value {
    let mut table = toml::map::Map::new();
    if alias != package_name {
        table.insert("包".into(), toml::Value::String(package_name.into()));
    }
    match dependency {
        Dependency::Path { path, requirement } => {
            table.insert(
                "路径".into(),
                toml::Value::String(path.to_string_lossy().into_owned()),
            );
            if let Some(requirement) = requirement {
                table.insert("版".into(), toml::Value::String(requirement.to_string()));
            }
        }
        Dependency::Git {
            url,
            revision,
            requirement,
        } => {
            table.insert("git".into(), toml::Value::String(url.clone()));
            table.insert("修订".into(), toml::Value::String(revision.clone()));
            if let Some(requirement) = requirement {
                table.insert("版".into(), toml::Value::String(requirement.to_string()));
            }
        }
        Dependency::Registry {
            requirement,
            registry,
        } => {
            table.insert("版".into(), toml::Value::String(requirement.to_string()));
            if registry != DEFAULT_REGISTRY {
                table.insert("源".into(), toml::Value::String(registry.clone()));
            }
        }
    }
    toml::Value::Table(table)
}

fn direct_dependencies(
    graph: &ResolutionGraph,
    edges: &BTreeMap<String, String>,
    path: &Path,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    edges
        .iter()
        .map(|(alias, id)| {
            graph
                .packages
                .get(id)
                .cloned()
                .map(|dependency| (alias.clone(), dependency))
                .ok_or_else(|| {
                    manifest_error(path, None, format!("依赖边“{alias}”指向不存在的“{id}”"))
                })
        })
        .collect()
}

static GRAPH_CACHE: OnceLock<Mutex<HashMap<PathBuf, ResolutionGraph>>> = OnceLock::new();

fn graph_cache() -> &'static Mutex<HashMap<PathBuf, ResolutionGraph>> {
    GRAPH_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn graph_cache_key(root: &Path) -> PathBuf {
    fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

fn cache_graph(manifest: &Manifest, graph: ResolutionGraph) {
    graph_cache()
        .lock()
        .expect("graph cache poisoned")
        .insert(graph_cache_key(&manifest.root), graph);
}

fn cached_or_resolve_graph(
    manifest: &Manifest,
    offline: bool,
) -> Result<ResolutionGraph, ManifestError> {
    if let Some(graph) = graph_cache()
        .lock()
        .expect("graph cache poisoned")
        .get(&graph_cache_key(&manifest.root))
        .cloned()
    {
        return Ok(graph);
    }
    let graph = resolve_graph(manifest, offline)?;
    cache_graph(manifest, graph.clone());
    Ok(graph)
}

fn parse(text: &str, path: PathBuf, root: PathBuf) -> Result<Manifest, ManifestError> {
    let normalized = normalize_manifest_toml(text);
    let document: toml::Value = toml::from_str(&normalized)
        .map_err(|error| sanitized_manifest_toml_error(&path, &normalized, &error))?;
    let package = table_alias(&document, &["包", "package"])
        .ok_or_else(|| manifest_error(&path, None, "缺少【包】表"))?;
    let format_version = integer_alias(package, &["格式", "format"]).unwrap_or(1);
    if !SUPPORTED_MANIFEST_FORMATS.contains(&(format_version as u32)) {
        return Err(manifest_error(
            &path,
            None,
            format!("不支持包清单格式版本 {format_version}，本运行时支持版本 1、2"),
        ));
    }
    let name = string_alias(package, &["名", "名称", "name"])
        .ok_or_else(|| manifest_error(&path, None, "【包】缺少字符串“名”"))?;
    validate_package_name(name).map_err(|message| manifest_error(&path, None, message))?;
    let raw_version = string_alias(package, &["版", "版本", "version"])
        .ok_or_else(|| manifest_error(&path, None, "【包】缺少字符串“版”"))?;
    let version = Version::parse(raw_version)
        .map_err(|error| manifest_error(&path, None, format!("包版本须为语义化版本：{error}")))?;
    let entry = manifest_relative_path(
        string_alias(package, &["入口", "entry"])
            .ok_or_else(|| manifest_error(&path, None, "【包】缺少字符串“入口”"))?,
        &path,
        "入口",
    )?;
    validate_entry(&entry).map_err(|message| manifest_error(&path, None, message))?;
    let description = string_alias(package, &["说明", "description"]).map(str::to_owned);
    let license = string_alias(package, &["许可", "license"]).map(str::to_owned);
    let authors = array_alias(package, &["作者", "authors"])
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect();

    let minimum_yanxu = string_alias(package, &["言序", "yanxu"])
        .map(VersionReq::parse)
        .transpose()
        .map_err(|error| manifest_error(&path, None, format!("最低言序版本要求无效：{error}")))?;

    let mut dependencies = BTreeMap::new();
    let mut dependency_packages = BTreeMap::new();
    if let Some(table) = table_alias(&document, &["依赖", "dependencies"]) {
        for (dependency_name, value) in table {
            validate_package_name(dependency_name)
                .map_err(|message| manifest_error(&path, None, message))?;
            dependencies.insert(
                dependency_name.clone(),
                parse_dependency(value, &path, dependency_name)?,
            );
            dependency_packages.insert(
                dependency_name.clone(),
                dependency_package_name(value, dependency_name, &path)?,
            );
        }
    }
    let mut dev_dependencies = BTreeMap::new();
    let mut dev_dependency_packages = BTreeMap::new();
    if let Some(table) = table_alias(&document, &["开发依赖", "dev-dependencies"]) {
        for (dependency_name, value) in table {
            validate_package_name(dependency_name)
                .map_err(|message| manifest_error(&path, None, message))?;
            dev_dependencies.insert(
                dependency_name.clone(),
                parse_dependency(value, &path, dependency_name)?,
            );
            dev_dependency_packages.insert(
                dependency_name.clone(),
                dependency_package_name(value, dependency_name, &path)?,
            );
        }
    }

    let mut exports = BTreeMap::new();
    if let Some(table) = table_alias(&document, &["导出", "exports"]) {
        for (name, value) in table {
            let export = value.as_str().ok_or_else(|| {
                manifest_error(&path, None, format!("导出“{name}”须为相对 .yx 文卷"))
            })?;
            let export = manifest_relative_path(export, &path, &format!("导出“{name}”"))?;
            validate_entry(&export).map_err(|message| manifest_error(&path, None, message))?;
            exports.insert(name.clone(), export);
        }
    }
    exports
        .entry("默认".into())
        .or_insert_with(|| entry.clone());

    let resources = table_alias(&document, &["资源", "resources"])
        .and_then(|table| array_alias(table, &["目录", "directories"]))
        .unwrap_or_default()
        .into_iter()
        .map(|resource| {
            let resource = manifest_relative_path(resource, &path, "资源")?;
            validate_relative_path(&resource, "资源")?;
            Ok(resource)
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;

    let build = BuildConfig {
        target: table_alias(&document, &["构建", "build"])
            .and_then(|table| string_alias(table, &["目标", "target"]))
            .unwrap_or("字节码")
            .to_owned(),
    };
    if !matches!(build.target.as_str(), "字节码" | "bytecode") {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "言序 {} 仅支持“字节码”构建目标，不支持“{}”",
                env!("CARGO_PKG_VERSION"),
                build.target
            ),
        ));
    }

    let workspace_members = table_alias(&document, &["工作区", "workspace"])
        .and_then(|table| array_alias(table, &["成员", "members"]))
        .unwrap_or_default()
        .into_iter()
        .map(|member| {
            let member = manifest_relative_path(member, &path, "工作区成员")?;
            validate_relative_path(&member, "工作区成员")?;
            Ok(member)
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;

    let native = parse_native_package(&document, &path)?;
    let application = parse_application_config(&document, &path, &root)?;
    let mut permissions = crate::permissions::PermissionSet::sandboxed();
    if let Some(table) = table_alias(&document, &["权限", "permissions"]) {
        for permission_path in array_alias(table, &["文件", "file"]).unwrap_or_default() {
            let permission_path = manifest_relative_path(permission_path, &path, "权限文件")?;
            permissions = permissions.allow_file(root.join(permission_path));
        }
        for host in array_alias(table, &["网络", "network"]).unwrap_or_default() {
            permissions = permissions.allow_network(host);
        }
        if bool_alias(table, &["本地网络", "local_network"]).unwrap_or(false) {
            permissions = permissions.allow_local_network();
        }
        for host in array_alias(table, &["TCP监听", "tcp_listen"]).unwrap_or_default() {
            permissions = permissions.allow_tcp_listen(host);
        }
        for host in array_alias(table, &["UDP绑定", "udp_bind"]).unwrap_or_default() {
            permissions = permissions.allow_udp_bind(host);
        }
        for variable in array_alias(table, &["环境", "environment"]).unwrap_or_default() {
            permissions = permissions.allow_environment(variable);
        }
        if bool_alias(table, &["进程", "process"]).unwrap_or(false) {
            permissions = permissions.allow_process();
        }
        if bool_alias(table, &["原生扩展", "native_extensions"]).unwrap_or(false) {
            permissions = permissions.allow_native_extensions();
        }
        if bool_alias(table, &["图形界面", "gui", "graphical_interface"]).unwrap_or(false) {
            permissions = permissions.allow_graphical_interface();
        }
        if bool_alias(table, &["剪贴板", "clipboard"]).unwrap_or(false) {
            permissions = permissions.allow_clipboard();
        }
        if bool_alias(table, &["文件对话框", "file_dialog"]).unwrap_or(false) {
            permissions = permissions.allow_file_dialog();
        }
        if bool_alias(table, &["系统通知", "system_notifications"]).unwrap_or(false) {
            permissions = permissions.allow_system_notifications();
        }
        if bool_alias(table, &["托盘", "tray"]).unwrap_or(false) {
            permissions = permissions.allow_tray();
        }
        if bool_alias(table, &["打开外部地址", "open_external_url"]).unwrap_or(false) {
            permissions = permissions.allow_open_external_url();
        }
        if bool_alias(table, &["全局快捷键", "global_shortcuts"]).unwrap_or(false) {
            permissions = permissions.allow_global_shortcuts();
        }
    }
    if application
        .as_ref()
        .is_some_and(|application| application.kind == ApplicationKind::Graphical)
        && !permissions.graphical_interface_allowed()
    {
        return Err(manifest_error(
            &path,
            None,
            "图形应用必须在【权限】中声明“图形界面 = true”",
        ));
    }
    Ok(Manifest {
        format_version: format_version as u32,
        name: name.into(),
        version,
        entry,
        description,
        license,
        authors,
        minimum_yanxu,
        dependencies,
        dependency_packages,
        dev_dependencies,
        dev_dependency_packages,
        exports,
        resources,
        build,
        application,
        workspace_members,
        native,
        permissions,
        root,
        path,
    })
}

fn sanitized_manifest_toml_error(
    path: &Path,
    normalized: &str,
    error: &toml::de::Error,
) -> ManifestError {
    let line = error
        .span()
        .and_then(|span| normalized.as_bytes().get(..span.start))
        .map(|prefix| prefix.iter().filter(|byte| **byte == b'\n').count() + 1);
    manifest_error(path, line, MANIFEST_TOML_SYNTAX_ERROR)
}

/// 将言序允许的中文裸键补成标准 TOML 引号键。
///
/// TOML 裸键仅接受 ASCII，而言序清单允许惯用的`[包]`、`名 =`。这里仅
/// 为键补引号，字符串值、注释与行数保持不变。已经使用单引号或双引号的
/// 标准 TOML 键也保持不变，包管理器和编辑器可直接复用此兼容规则。
pub fn normalize_manifest_toml(text: &str) -> String {
    text.lines()
        .map(|line| {
            let indentation = &line[..line.len() - line.trim_start().len()];
            let trimmed = line.trim_start();
            if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.starts_with("[[") {
                let section = &trimmed[1..trimmed.len() - 1];
                if !section.starts_with(['\'', '"']) && !section.is_ascii() {
                    let section = section
                        .split('.')
                        .map(|component| {
                            if component.is_ascii() {
                                component.to_owned()
                            } else {
                                format!("\"{component}\"")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(".");
                    return format!("{indentation}[{section}]");
                }
            }
            let mut normalized = line.to_owned();
            if let Some(equal) = trimmed.find('=') {
                let key = trimmed[..equal].trim();
                if !key.starts_with(['\'', '"']) && !key.is_ascii() {
                    let absolute = indentation.len();
                    normalized.replace_range(
                        absolute..absolute + trimmed[..equal].trim_end().len(),
                        &format!("\"{key}\""),
                    );
                }
            }
            normalized = normalize_inline_source_keys(&normalized);
            normalized
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_inline_source_keys(line: &str) -> String {
    let mut normalized = line.to_owned();
    for key in ["包", "路径", "版", "修订", "源"] {
        for separator in ['{', ','] {
            for spacing in ["", " "] {
                for equals in ["=", " ="] {
                    let bare = format!("{separator}{spacing}{key}{equals}");
                    let quoted = format!("{separator}{spacing}\"{key}\"{equals}");
                    normalized = normalized.replace(&bare, &quoted);
                }
            }
        }
    }
    normalized
}

fn parse_dependency(
    value: &toml::Value,
    manifest_path: &Path,
    name: &str,
) -> Result<Dependency, ManifestError> {
    if let Some(path) = value.as_str() {
        validate_local_source_path_text(path)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
        let dependency = Dependency::Path {
            path: manifest_relative_path(path, manifest_path, &format!("依赖“{name}”路径"))?,
            requirement: None,
        };
        validate_dependency_source_security(&dependency)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
        return Ok(dependency);
    }
    let table = value.as_table().ok_or_else(|| {
        manifest_error(
            manifest_path,
            None,
            format!("依赖“{name}”须为路径字符串或来源表"),
        )
    })?;
    let requirement = string_alias(table, &["版", "version"])
        .map(VersionReq::parse)
        .transpose()
        .map_err(|error| {
            manifest_error(
                manifest_path,
                None,
                format!("依赖“{name}”版本要求无效：{error}"),
            )
        })?;
    if let Some(path) = string_alias(table, &["路径", "path"]) {
        validate_local_source_path_text(path)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
        let dependency = Dependency::Path {
            path: manifest_relative_path(path, manifest_path, &format!("依赖“{name}”路径"))?,
            requirement,
        };
        validate_dependency_source_security(&dependency)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
        return Ok(dependency);
    }
    if let Some(url) = string_alias(table, &["git", "Git"]) {
        let dependency = Dependency::Git {
            url: url.into(),
            revision: string_alias(table, &["修订", "rev", "revision"])
                .unwrap_or("HEAD")
                .into(),
            requirement,
        };
        validate_dependency_source_security(&dependency)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
        return Ok(dependency);
    }
    let requirement = requirement.ok_or_else(|| {
        manifest_error(manifest_path, None, format!("索引依赖“{name}”必须给出“版”"))
    })?;
    let dependency = Dependency::Registry {
        requirement,
        registry: string_alias(table, &["源", "registry"])
            .unwrap_or(DEFAULT_REGISTRY)
            .into(),
    };
    validate_dependency_source_security(&dependency)
        .map_err(|message| manifest_error(manifest_path, None, message))?;
    Ok(dependency)
}

fn dependency_package_name(
    value: &toml::Value,
    alias: &str,
    manifest_path: &Path,
) -> Result<String, ManifestError> {
    let package = value
        .as_table()
        .and_then(|table| string_alias(table, &["包", "package"]))
        .unwrap_or(alias);
    validate_package_name(package)
        .map_err(|message| manifest_error(manifest_path, None, message))?;
    Ok(package.to_owned())
}

fn parse_native_package(
    document: &toml::Value,
    manifest_path: &Path,
) -> Result<Option<NativePackage>, ManifestError> {
    let Some(table) = table_alias(document, &["原生", "native"]) else {
        return Ok(None);
    };
    let abi_version = integer_alias(table, &["ABI", "abi"]).unwrap_or(1);
    if !matches!(abi_version, 1 | 2) {
        return Err(manifest_error(
            manifest_path,
            None,
            format!(
                "不支持原生扩展 ABI {abi_version}，言序 {} 支持 ABI 1、2",
                env!("CARGO_PKG_VERSION")
            ),
        ));
    }
    let mut artifacts = BTreeMap::new();
    for (os, architectures) in table {
        if matches!(os.as_str(), "ABI" | "abi") {
            continue;
        }
        let Some(architectures) = architectures.as_table() else {
            continue;
        };
        for (architecture, artifact) in architectures {
            let Some(artifact) = artifact.as_table() else {
                continue;
            };
            let target = native_target(os, architecture);
            let path = string_alias(artifact, &["文件", "file", "path"]).ok_or_else(|| {
                manifest_error(
                    manifest_path,
                    None,
                    format!("原生制品 {os}.{architecture} 缺少文件路径"),
                )
            })?;
            let checksum = string_alias(artifact, &["校验和", "checksum"]).ok_or_else(|| {
                manifest_error(
                    manifest_path,
                    None,
                    format!("原生制品 {os}.{architecture} 缺少 SHA-256 校验和"),
                )
            })?;
            let relative = manifest_relative_path(
                path,
                manifest_path,
                &format!("原生制品 {os}.{architecture}"),
            )?;
            validate_relative_path(&relative, "原生制品")?;
            if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(manifest_error(
                    manifest_path,
                    None,
                    format!("原生制品 {os}.{architecture} 的校验和须为 64 位十六进制 SHA-256"),
                ));
            }
            let package_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            let full_path = resolve_existing_package_path(
                package_root,
                &relative,
                PackagePathPurpose::ManifestReference,
            )
            .map_err(|error| package_path_manifest_error(manifest_path, error))?;
            let metadata = fs::symlink_metadata(&full_path).map_err(|error| {
                manifest_error(&full_path, None, format!("不能检查原生制品：{error}"))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(manifest_error(
                    &full_path,
                    None,
                    "原生制品必须是普通文件，不得为符号链接或特殊文件",
                ));
            }
            if metadata.len() > NATIVE_ARTIFACT_MAX_BYTES {
                return Err(manifest_error(
                    &full_path,
                    None,
                    format!("原生制品不得超过 {NATIVE_ARTIFACT_MAX_BYTES} 字节"),
                ));
            }
            let declared_size = integer_alias(artifact, &["大小", "size"])
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(metadata.len());
            if declared_size != metadata.len() {
                return Err(manifest_error(
                    &full_path,
                    None,
                    format!(
                        "原生制品声明大小 {declared_size} 与实际 {} 不符",
                        metadata.len()
                    ),
                ));
            }
            artifacts.insert(
                target.clone(),
                NativeArtifact {
                    abi: abi_version as u32,
                    target,
                    path: path.to_owned(),
                    checksum: checksum.to_ascii_lowercase(),
                    size: metadata.len(),
                },
            );
        }
    }
    if artifacts.is_empty() {
        return Err(manifest_error(
            manifest_path,
            None,
            "【原生】声明 ABI 后至少须提供一个平台制品",
        ));
    }
    if artifacts.len() > NATIVE_ARTIFACT_MAX_COUNT {
        return Err(manifest_error(
            manifest_path,
            None,
            format!("原生制品不得超过 {NATIVE_ARTIFACT_MAX_COUNT} 个"),
        ));
    }
    let total_size = artifacts
        .values()
        .try_fold(0_u64, |total, artifact| total.checked_add(artifact.size));
    if total_size.is_none_or(|total| total > NATIVE_ARTIFACT_MAX_TOTAL_BYTES) {
        return Err(manifest_error(
            manifest_path,
            None,
            format!("原生制品总大小不得超过 {NATIVE_ARTIFACT_MAX_TOTAL_BYTES} 字节"),
        ));
    }
    Ok(Some(NativePackage {
        abi_version: abi_version as u32,
        artifacts,
    }))
}

fn parse_application_config(
    document: &toml::Value,
    manifest_path: &Path,
    root: &Path,
) -> Result<Option<ApplicationConfig>, ManifestError> {
    let Some(table) = table_alias(document, &["应用", "application"]) else {
        return Ok(None);
    };
    let kind = match string_alias(table, &["类型", "type", "kind"])
        .ok_or_else(|| manifest_error(manifest_path, None, "【应用】缺少字符串“类型”"))?
    {
        "图形" | "gui" | "graphical" => ApplicationKind::Graphical,
        "命令行" | "cli" | "console" => ApplicationKind::CommandLine,
        other => {
            return Err(manifest_error(
                manifest_path,
                None,
                format!("应用类型只可为“图形”或“命令行”，不可为“{other}”"),
            ));
        }
    };
    let name = string_alias(table, &["名称", "名", "name"])
        .filter(|name| !name.trim().is_empty() && name.chars().count() <= 128)
        .ok_or_else(|| manifest_error(manifest_path, None, "应用名称须为 1–128 个字符"))?
        .to_owned();
    let identifier = string_alias(table, &["标识", "identifier", "bundle_identifier"])
        .ok_or_else(|| manifest_error(manifest_path, None, "【应用】缺少字符串“标识”"))?;
    validate_application_identifier(identifier)
        .map_err(|message| manifest_error(manifest_path, None, message))?;
    let version = string_alias(table, &["版本", "版", "version"])
        .ok_or_else(|| manifest_error(manifest_path, None, "【应用】缺少字符串“版本”"))?;
    let version = Version::parse(version).map_err(|error| {
        manifest_error(
            manifest_path,
            None,
            format!("应用版本须为语义化版本：{error}"),
        )
    })?;
    let icon = string_alias(table, &["图标", "icon"])
        .map(|raw| {
            let icon = manifest_relative_path(raw, manifest_path, "应用图标")?;
            validate_relative_path(&icon, "应用图标")?;
            let full_path =
                resolve_existing_package_path(root, &icon, PackagePathPurpose::ManifestReference)
                    .map_err(|error| package_path_manifest_error(manifest_path, error))?;
            let metadata = fs::symlink_metadata(&full_path).map_err(|error| {
                manifest_error(&full_path, None, format!("不能检查应用图标：{error}"))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(manifest_error(
                    &full_path,
                    None,
                    "应用图标必须是包内普通文件，不得为符号链接或特殊文件",
                ));
            }
            Ok(icon)
        })
        .transpose()?;
    let company = string_alias(table, &["公司", "company"])
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let minimum_system_version = string_alias(table, &["最低系统版本", "minimum_system_version"])
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let window = table
        .iter()
        .find_map(|(name, value)| {
            matches!(name.as_str(), "窗口" | "window")
                .then(|| value.as_table())
                .flatten()
        })
        .map(|window| parse_window_config(window, manifest_path))
        .transpose()?
        .unwrap_or_default();
    Ok(Some(ApplicationConfig {
        kind,
        name,
        identifier: identifier.to_owned(),
        version,
        icon,
        company,
        minimum_system_version,
        window,
    }))
}

fn parse_window_config(
    table: &toml::map::Map<String, toml::Value>,
    manifest_path: &Path,
) -> Result<WindowConfig, ManifestError> {
    let defaults = WindowConfig::default();
    let width = window_dimension(table, &["宽", "width"], defaults.width, manifest_path)?;
    let height = window_dimension(table, &["高", "height"], defaults.height, manifest_path)?;
    let minimum_width = window_dimension(
        table,
        &["最小宽", "minimum_width", "min_width"],
        defaults.minimum_width,
        manifest_path,
    )?;
    let minimum_height = window_dimension(
        table,
        &["最小高", "minimum_height", "min_height"],
        defaults.minimum_height,
        manifest_path,
    )?;
    let maximum_width = optional_window_dimension(
        table,
        &["最大宽", "maximum_width", "max_width"],
        manifest_path,
    )?;
    let maximum_height = optional_window_dimension(
        table,
        &["最大高", "maximum_height", "max_height"],
        manifest_path,
    )?;
    if minimum_width > width || minimum_height > height {
        return Err(manifest_error(
            manifest_path,
            None,
            "窗口最小尺寸不得大于默认尺寸",
        ));
    }
    if maximum_width.is_some_and(|maximum| maximum < width)
        || maximum_height.is_some_and(|maximum| maximum < height)
    {
        return Err(manifest_error(
            manifest_path,
            None,
            "窗口最大尺寸不得小于默认尺寸",
        ));
    }
    Ok(WindowConfig {
        width,
        height,
        minimum_width,
        minimum_height,
        maximum_width,
        maximum_height,
        resizable: bool_alias(table, &["可缩放", "resizable"]).unwrap_or(true),
        high_dpi: bool_alias(table, &["高分屏", "high_dpi"]).unwrap_or(true),
    })
}

fn window_dimension(
    table: &toml::map::Map<String, toml::Value>,
    names: &[&str],
    default: u32,
    manifest_path: &Path,
) -> Result<u32, ManifestError> {
    optional_window_dimension(table, names, manifest_path).map(|value| value.unwrap_or(default))
}

fn optional_window_dimension(
    table: &toml::map::Map<String, toml::Value>,
    names: &[&str],
    manifest_path: &Path,
) -> Result<Option<u32>, ManifestError> {
    let Some((name, value)) = names
        .iter()
        .find_map(|name| table.get(*name).map(|value| (*name, value)))
    else {
        return Ok(None);
    };
    let value = value
        .as_integer()
        .and_then(|value| u32::try_from(value).ok());
    match value {
        Some(value @ 1..=16_384) => Ok(Some(value)),
        _ => Err(manifest_error(
            manifest_path,
            None,
            format!("窗口尺寸“{name}”须为 1–16384 的整数"),
        )),
    }
}

fn validate_application_identifier(identifier: &str) -> Result<(), String> {
    if identifier.len() > 255 || !identifier.is_ascii() {
        return Err("应用标识须为不超过 255 字节的 ASCII 反向域名".into());
    }
    let labels = identifier.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(
            "应用标识须为反向域名（例如 dev.yanxu.myapp），标签仅含字母、数字和连字符".into(),
        );
    }
    Ok(())
}

fn native_target(os: &str, architecture: &str) -> String {
    let normalized_architecture = architecture.to_ascii_lowercase();
    let architecture = match normalized_architecture.as_str() {
        "x64" | "amd64" | "x86_64" => "x86_64",
        "arm64" | "aarch64" => "aarch64",
        other => other,
    };
    match os.to_ascii_lowercase().as_str() {
        "windows" | "窗口" => format!("{architecture}-pc-windows-msvc"),
        "linux" => format!("{architecture}-unknown-linux-gnu"),
        "macos" | "darwin" => format!("{architecture}-apple-darwin"),
        other => format!("{architecture}-{other}"),
    }
}

fn manifest_relative_path(
    raw: &str,
    manifest_path: &Path,
    kind: &str,
) -> Result<PathBuf, ManifestError> {
    if raw.contains('\\') {
        return Err(package_path_manifest_error(
            manifest_path,
            PackagePathError {
                code: PACKAGE_PATH_NON_PORTABLE_CODE,
                message: format!("{kind}路径“{raw}”包含反斜杠目录分隔符。"),
                path: PathBuf::from(raw),
                component: None,
                suggestion: "请在包清单路径中统一使用正斜杠。".into(),
            },
        ));
    }
    Ok(PathBuf::from(raw))
}

fn validate_relative_path(path: &Path, kind: &str) -> Result<(), ManifestError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}路径须为包内非空相对路径"),
        ));
    }
    Ok(())
}

pub fn current_target() -> String {
    let architecture = std::env::consts::ARCH;
    if cfg!(target_os = "windows") {
        format!(
            "{architecture}-pc-windows-{}",
            std::env::consts::DLL_SUFFIX.trim_start_matches('.')
        )
        .replace("-dll", "-msvc")
    } else if cfg!(target_os = "macos") {
        format!("{architecture}-apple-darwin")
    } else if cfg!(target_os = "linux") {
        let environment = if cfg!(target_env = "musl") {
            "musl"
        } else {
            "gnu"
        };
        format!("{architecture}-unknown-linux-{environment}")
    } else {
        format!("{architecture}-{}", std::env::consts::OS)
    }
}

fn package_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

struct GraphBuilder<'a> {
    offline: bool,
    existing: Option<&'a LockFile>,
    packages: BTreeMap<String, ResolvedDependency>,
    visiting: Vec<String>,
    target: String,
    native_allowed: bool,
}

impl GraphBuilder<'_> {
    fn resolve_table(
        &mut self,
        manifest: &Manifest,
        dependencies: &BTreeMap<String, Dependency>,
        packages: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, ManifestError> {
        let mut edges = BTreeMap::new();
        for (alias, dependency) in dependencies {
            let package_name = packages.get(alias).map_or(alias.as_str(), String::as_str);
            let locked = self.locked_candidate(package_name, dependency);
            let mut resolved = resolve_one(
                manifest,
                alias,
                package_name,
                dependency,
                locked.as_ref(),
                self.offline,
            )?;
            let id = package_identity(&resolved.locked);
            edges.insert(alias.clone(), id.clone());
            if self.packages.contains_key(&id) {
                continue;
            }
            if let Some(position) = self.visiting.iter().position(|visiting| visiting == &id) {
                let mut cycle = self.visiting[position..].to_vec();
                cycle.push(id);
                return Err(manifest_error(
                    &manifest.path,
                    None,
                    format!("依赖图存在循环：{}", cycle.join(" → ")),
                ));
            }
            self.visiting.push(id.clone());
            let dependency_manifest = load(resolved.root.join(MANIFEST_NAME))?;
            if let Some(requirement) = &dependency_manifest.minimum_yanxu {
                let runtime = Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version");
                if !requirement.matches(&runtime) {
                    return Err(manifest_error(
                        &dependency_manifest.path,
                        None,
                        format!(
                            "依赖“{}”要求言序 {requirement}，当前包核心为 {runtime}",
                            dependency_manifest.name
                        ),
                    ));
                }
            }
            let dependency_edges = self.resolve_table(
                &dependency_manifest,
                &dependency_manifest.dependencies,
                &dependency_manifest.dependency_packages,
            )?;
            let native = selected_native_artifact(&dependency_manifest, &self.target)?;
            if native.is_some() && !self.native_allowed {
                return Err(manifest_error(
                    &manifest.path,
                    None,
                    format!(
                        "依赖“{}”包含原生扩展；顶层【权限】必须显式设置 原生扩展 = true，图形界面权限不能代替原生加载授权",
                        dependency_manifest.name
                    ),
                ));
            }
            resolved.locked.id = id.clone();
            resolved.locked.dependencies = dependency_edges;
            resolved.locked.exports = dependency_manifest
                .exports
                .iter()
                .map(|(name, path)| (name.clone(), path.to_string_lossy().into_owned()))
                .collect();
            resolved.locked.target = self.target.clone();
            resolved.locked.native = native;
            resolved.locked.minimum_yanxu = dependency_manifest
                .minimum_yanxu
                .as_ref()
                .map(ToString::to_string);
            let default_export = resolved
                .locked
                .exports
                .get("默认")
                .expect("manifest always has default export");
            resolved.entry = resolve_existing_package_path(
                &resolved.root,
                Path::new(default_export),
                PackagePathPurpose::ModuleSource,
            )
            .map_err(|error| package_path_manifest_error(&dependency_manifest.path, error))?;
            self.visiting.pop();
            self.packages.insert(id, resolved);
        }
        Ok(edges)
    }

    fn locked_candidate(
        &self,
        package_name: &str,
        dependency: &Dependency,
    ) -> Option<LockedPackage> {
        self.existing?.packages.iter().find_map(|locked| {
            (locked.name == package_name
                && dependency_source_matches(dependency, &locked.source)
                && dependency_requirement(dependency).is_none_or(|requirement| {
                    Version::parse(&locked.version)
                        .is_ok_and(|version| requirement.matches(&version))
                }))
            .then(|| locked.clone())
        })
    }
}

fn dependency_source_matches(dependency: &Dependency, source: &str) -> bool {
    match dependency {
        Dependency::Path { path, .. } => source == format!("path:{}", path.display()),
        Dependency::Git { url, .. } => source == format!("git:{url}"),
        Dependency::Registry { registry, .. } => source == format!("registry:{registry}"),
    }
}

fn locked_source_is_machine_local(source: &str) -> bool {
    if source.starts_with("path:") {
        return true;
    }
    if let Some(url) = source.strip_prefix("git:") {
        let scp_remote = url
            .split_once(':')
            .is_some_and(|(authority, path)| authority.contains('@') && !path.is_empty());
        return url.starts_with("file://")
            || Path::new(url).is_absolute()
            || Path::new(url).exists()
            || (!url.contains("://") && !scp_remote);
    }
    if let Some(registry) = source.strip_prefix("registry:") {
        return !registry.starts_with("https://") || local_registry_path(registry).is_some();
    }
    false
}

fn dependency_requirement(dependency: &Dependency) -> Option<&VersionReq> {
    match dependency {
        Dependency::Path { requirement, .. } | Dependency::Git { requirement, .. } => {
            requirement.as_ref()
        }
        Dependency::Registry { requirement, .. } => Some(requirement),
    }
}

fn package_identity(locked: &LockedPackage) -> String {
    format!(
        "{}@{}#{}-{}",
        locked.name,
        locked.version,
        short_hash(&locked.source)[..12].to_owned(),
        locked.checksum[..16].to_owned()
    )
}

fn selected_native_artifact(
    manifest: &Manifest,
    target: &str,
) -> Result<Option<NativeArtifact>, ManifestError> {
    let Some(native) = &manifest.native else {
        return Ok(None);
    };
    let artifact = native.artifacts.get(target).ok_or_else(|| {
        manifest_error(
            &manifest.path,
            None,
            format!(
                "原生包“{}”没有目标 {target} 的制品；可用目标：{}",
                manifest.name,
                native
                    .artifacts
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        )
    })?;
    let path = resolve_existing_package_path(
        &manifest.root,
        Path::new(&artifact.path),
        PackagePathPurpose::ManifestReference,
    )
    .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| manifest_error(&path, None, format!("不能检查原生制品：{error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(manifest_error(
            &path,
            None,
            "原生制品必须是普通文件，不得为符号链接或特殊文件",
        ));
    }
    if metadata.len() != artifact.size || metadata.len() > NATIVE_ARTIFACT_MAX_BYTES {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "原生制品大小不符或超限：锁定 {}，实际 {}",
                artifact.size,
                metadata.len()
            ),
        ));
    }
    let actual = file_checksum(&path)?;
    if actual != artifact.checksum {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "原生制品校验和不符：锁定 {}，实际 {actual}",
                artifact.checksum
            ),
        ));
    }
    Ok(Some(artifact.clone()))
}

fn resolve_one(
    manifest: &Manifest,
    alias: &str,
    package_name: &str,
    dependency: &Dependency,
    locked: Option<&LockedPackage>,
    offline: bool,
) -> Result<ResolvedDependency, ManifestError> {
    validate_dependency_source_security(dependency)
        .map_err(|message| manifest_error(&manifest.path, None, message))?;
    if let Some(locked) = locked
        && let Some(root) = find_vendored_package(&manifest.root, locked)?
    {
        let requirement = dependency_requirement(dependency);
        let mut resolved = lock_local(
            package_name,
            &root,
            &locked.source,
            locked.revision.clone(),
            requirement,
        )?;
        verify_locked(alias, &root, &mut resolved, Some(locked))?;
        return Ok(resolved);
    }
    match dependency {
        Dependency::Path { path, requirement } => {
            let root = canonical_dependency_root(&manifest.root.join(path))?;
            let mut resolved = lock_local(
                package_name,
                &root,
                &format!("path:{}", path.display()),
                None,
                requirement.as_ref(),
            )?;
            verify_locked(alias, &root, &mut resolved, locked)?;
            Ok(resolved)
        }
        Dependency::Git {
            url,
            revision,
            requirement,
        } => {
            let exact_revision = locked.and_then(|locked| locked.revision.as_deref());
            let (root, revision) = resolve_git(url, exact_revision.unwrap_or(revision), offline)?;
            let mut resolved = lock_local(
                package_name,
                &root,
                &format!("git:{url}"),
                Some(revision),
                requirement.as_ref(),
            )?;
            verify_locked(alias, &root, &mut resolved, locked)?;
            Ok(resolved)
        }
        Dependency::Registry {
            requirement,
            registry,
        } => {
            let exact = locked
                .map(|locked| Version::parse(&locked.version))
                .transpose()
                .map_err(|error| {
                    manifest_error(&manifest.path, None, format!("锁定版本无效：{error}"))
                })?;
            let mut resolved = resolve_registry(
                package_name,
                requirement,
                registry,
                exact,
                locked.map(|locked| locked.checksum.as_str()),
                offline,
            )?;
            let resolved_root = resolved.root.clone();
            verify_locked(alias, &resolved_root, &mut resolved, locked)?;
            Ok(resolved)
        }
    }
}

fn verify_locked(
    name: &str,
    root: &Path,
    resolved: &mut ResolvedDependency,
    locked: Option<&LockedPackage>,
) -> Result<(), ManifestError> {
    if let Some(locked) = locked {
        let checksum_matches = if locked.checksum == resolved.locked.checksum {
            true
        } else {
            tree_checksum_matches(root, &locked.checksum)?
        };
        if locked.name != resolved.locked.name
            || locked.version != resolved.locked.version
            || locked.source != resolved.locked.source
            || locked.revision != resolved.locked.revision
            || !checksum_matches
            || locked.entry != resolved.locked.entry
        {
            return Err(manifest_error(
                root,
                None,
                format!(
                    "依赖“{name}”与 {LOCK_NAME} 不符（版本、修订或内容校验已改变）；请显式更新锁文件"
                ),
            ));
        }
        resolved.locked.checksum.clone_from(&locked.checksum);
    }
    Ok(())
}

fn lock_local(
    expected_name: &str,
    root: &Path,
    source: &str,
    revision: Option<String>,
    requirement: Option<&VersionReq>,
) -> Result<ResolvedDependency, ManifestError> {
    let root = fs::canonicalize(root)
        .map_err(|error| manifest_error(root, None, format!("不能规范化依赖包根目录：{error}")))?;
    if !root.is_dir() {
        return Err(manifest_error(&root, None, "依赖包根路径不是目录"));
    }
    let dependency_manifest = load(root.join(MANIFEST_NAME))?;
    validate_package_root(&dependency_manifest)?;
    if dependency_manifest.name != expected_name {
        return Err(manifest_error(
            &dependency_manifest.path,
            None,
            format!(
                "依赖名为“{expected_name}”，其清单却声明“{}”",
                dependency_manifest.name
            ),
        ));
    }
    if let Some(requirement) = requirement
        && !requirement.matches(&dependency_manifest.version)
    {
        return Err(manifest_error(
            &dependency_manifest.path,
            None,
            format!(
                "依赖“{expected_name}”版本 {} 不满足 {requirement}",
                dependency_manifest.version
            ),
        ));
    }
    let checksum = tree_checksum(&root)?;
    let entry = resolve_existing_package_path(
        &root,
        &dependency_manifest.entry,
        PackagePathPurpose::ModuleSource,
    )
    .map_err(|error| package_path_manifest_error(&dependency_manifest.path, error))?;
    Ok(ResolvedDependency {
        locked: LockedPackage {
            id: String::new(),
            name: expected_name.into(),
            version: dependency_manifest.version.to_string(),
            source: source.into(),
            revision,
            checksum,
            entry: dependency_manifest.entry.to_string_lossy().into_owned(),
            dependencies: BTreeMap::new(),
            exports: BTreeMap::new(),
            target: String::new(),
            native: None,
            minimum_yanxu: None,
        },
        entry,
        root,
    })
}

fn resolve_git(
    url: &str,
    revision: &str,
    offline: bool,
) -> Result<(PathBuf, String), ManifestError> {
    validate_source_url_security(url)
        .map_err(|message| manifest_error("Git 来源", None, message))?;
    if !secure_git_source(url) {
        return Err(manifest_error(
            "Git 来源",
            None,
            "远程 Git 依赖须使用 HTTPS 或 SSH",
        ));
    }
    validate_git_revision_security(revision)
        .map_err(|message| manifest_error("Git 来源", None, message))?;
    let cache = cache_root().join("git").join(short_hash(url));
    if !cache.join(".git").is_dir() {
        if offline {
            let url = safe_git_source_value_for_display(url);
            let revision = safe_git_revision_for_display(revision);
            return Err(manifest_error(
                &cache,
                None,
                format!("离线模式下未缓存 Git 依赖 {url}@{revision}"),
            ));
        }
        if cache.exists() {
            fs::remove_dir_all(&cache).map_err(|error| {
                manifest_error(&cache, None, format!("不能清理损坏缓存：{error}"))
            })?;
        }
        fs::create_dir_all(cache.parent().expect("git cache parent"))
            .map_err(|error| manifest_error(&cache, None, format!("不能创建 Git 缓存：{error}")))?;
        run_command(
            Command::new("git")
                .arg("clone")
                .arg("--quiet")
                .arg("--")
                .arg(url)
                .arg(&cache),
            &cache,
            "克隆 Git 依赖",
        )?;
    }
    let exact_revision =
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit());
    let exact_cached = exact_revision
        && Command::new("git")
            .arg("-C")
            .arg(&cache)
            .arg("cat-file")
            .arg("-e")
            .arg(format!("{revision}^{{commit}}"))
            .status()
            .is_ok_and(|status| status.success());
    let checkout_revision = if !offline && (!exact_revision || !exact_cached) {
        run_command(
            Command::new("git")
                .arg("-C")
                .arg(&cache)
                .arg("fetch")
                .arg("--quiet")
                .arg("--force")
                .arg("origin")
                .arg("--")
                .arg(revision),
            &cache,
            "更新 Git 依赖",
        )?;
        "FETCH_HEAD"
    } else {
        revision
    };
    run_command(
        Command::new("git")
            .arg("-C")
            .arg(&cache)
            .arg("checkout")
            .arg("--quiet")
            .arg("--force")
            .arg("--detach")
            .arg(checkout_revision),
        &cache,
        "检出 Git 修订",
    )?;
    let output = Command::new("git")
        .arg("-C")
        .arg(&cache)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|error| manifest_error(&cache, None, format!("不能读取 Git 修订：{error}")))?;
    if !output.status.success() {
        return Err(manifest_error(&cache, None, "不能读取 Git 精确修订"));
    }
    Ok((cache, String::from_utf8_lossy(&output.stdout).trim().into()))
}

const SOURCE_SECURITY_ERROR: &str = "依赖来源不得包含内嵌凭据、不安全用户信息、片段或敏感查询参数；请改用凭据管理器、SSH 密钥管理器或外部认证配置";
const GIT_REVISION_ERROR: &str = "Git 修订名称不合法";
const SOURCE_VALUE_MAX_BYTES: usize = 16 * 1024;
const SOURCE_QUERY_MAX_BYTES: usize = 4 * 1024;
const SOURCE_QUERY_MAX_FIELDS: usize = 128;
const SOURCE_PERCENT_DECODE_ROUNDS: usize = 3;
const SSH_USERNAME_MAX_BYTES: usize = 128;
const SSH_HOST_MAX_BYTES: usize = 255;
const GIT_REVISION_MAX_BYTES: usize = 1_024;
const HIDDEN_SOURCE_VALUE: &str = "<已隐藏的不安全来源>";

fn source_text_is_bounded(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= SOURCE_VALUE_MAX_BYTES
        && !source.chars().any(char::is_control)
}

fn sensitive_query_key(key: &str) -> bool {
    let compact = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "signature",
        "apikey",
        "accesskey",
        "privatekey",
        "authorization",
        "oauth",
        "bearer",
        "sessionkey",
        "sessionid",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
        || key
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                matches!(
                    segment.to_ascii_lowercase().as_str(),
                    "auth" | "authorization" | "oauth" | "key" | "sig" | "code"
                )
            })
}

fn inspect_query_layer(query: &str) -> Result<(), &'static str> {
    if query.len() > SOURCE_QUERY_MAX_BYTES
        || query.contains('#')
        || query.chars().any(char::is_control)
    {
        return Err(SOURCE_SECURITY_ERROR);
    }
    let mut fields = 0usize;
    for field in query.split(['&', ';', '?']) {
        fields = fields.checked_add(1).ok_or(SOURCE_SECURITY_ERROR)?;
        if fields > SOURCE_QUERY_MAX_FIELDS {
            return Err(SOURCE_SECURITY_ERROR);
        }
        let key = field.split_once('=').map_or(field, |(key, _)| key);
        if !key.is_ascii() {
            return Err(SOURCE_SECURITY_ERROR);
        }
        let normalized = key.nfkc().collect::<String>();
        if !normalized.is_ascii() || sensitive_query_key(&normalized) {
            return Err(SOURCE_SECURITY_ERROR);
        }
    }
    Ok(())
}

fn percent_decode_source_layer(value: &str) -> Result<String, &'static str> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = bytes
            .get(index + 1)
            .copied()
            .and_then(hex)
            .ok_or(SOURCE_SECURITY_ERROR)?;
        let low = bytes
            .get(index + 2)
            .copied()
            .and_then(hex)
            .ok_or(SOURCE_SECURITY_ERROR)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| SOURCE_SECURITY_ERROR)
}

fn percent_decode_source_shape_layer(value: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| {
                Some((
                    bytes.get(index + 1).copied().and_then(hex)?,
                    bytes.get(index + 2).copied().and_then(hex)?,
                ))
            })
            .flatten()
            .map(|(high, low)| (high << 4) | low)
            .filter(u8::is_ascii);
        if let Some(byte) = escaped {
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).expect("ASCII percent decoding preserves UTF-8")
}

fn validate_source_query_security(source: &str) -> Result<(), &'static str> {
    let Some((_, query)) = source.split_once('?') else {
        return Ok(());
    };
    if query.len() > SOURCE_QUERY_MAX_BYTES {
        return Err(SOURCE_SECURITY_ERROR);
    }
    let mut layer = query.to_owned();
    for depth in 0..=SOURCE_PERCENT_DECODE_ROUNDS {
        inspect_query_layer(&layer)?;
        let decoded = percent_decode_source_layer(&layer)?;
        if decoded == layer {
            return Ok(());
        }
        if depth == SOURCE_PERCENT_DECODE_ROUNDS {
            return Err(SOURCE_SECURITY_ERROR);
        }
        layer = decoded;
    }
    Err(SOURCE_SECURITY_ERROR)
}

fn validate_source_text(source: &str) -> Result<(), &'static str> {
    if !source_text_is_bounded(source) {
        return Err(SOURCE_SECURITY_ERROR);
    }
    validate_source_query_security(source)
}

fn valid_ssh_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= SSH_USERNAME_MAX_BYTES
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_url_source(source: &str) -> Result<url::Url, &'static str> {
    validate_source_text(source)?;
    let parsed = url::Url::parse(source).map_err(|_| SOURCE_SECURITY_ERROR)?;
    if parsed.fragment().is_some() {
        return Err(SOURCE_SECURITY_ERROR);
    }
    let authority = source
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
        .ok_or(SOURCE_SECURITY_ERROR)?;
    let at_count = authority.bytes().filter(|byte| *byte == b'@').count();
    let has_user_information =
        at_count != 0 || !parsed.username().is_empty() || parsed.password().is_some();
    if has_user_information {
        let ssh_scheme = matches!(parsed.scheme(), "ssh" | "git+ssh");
        if !ssh_scheme
            || at_count != 1
            || parsed.password().is_some()
            || !valid_ssh_username(parsed.username())
        {
            return Err(SOURCE_SECURITY_ERROR);
        }
    }
    Ok(parsed)
}

fn parse_scp_like_git_source(source: &str) -> Result<Option<(&str, &str, &str)>, &'static str> {
    if !source.contains('@') {
        return Ok(None);
    }
    if source.bytes().filter(|byte| *byte == b'@').count() != 1 {
        return Err(SOURCE_SECURITY_ERROR);
    }
    let (username, remainder) = source.split_once('@').ok_or(SOURCE_SECURITY_ERROR)?;
    let Some((host, path)) = remainder.split_once(':') else {
        if username.contains(':') {
            return Err(SOURCE_SECURITY_ERROR);
        }
        return Ok(None);
    };
    if !valid_ssh_username(username)
        || host.is_empty()
        || host.len() > SSH_HOST_MAX_BYTES
        || path.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || path.contains('#')
    {
        return Err(SOURCE_SECURITY_ERROR);
    }
    Ok(Some((username, host, path)))
}

fn looks_like_uri_scheme(source: &str) -> bool {
    let Some((scheme, _)) = source.split_once(':') else {
        return false;
    };
    if scheme.len() == 1 && scheme.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

#[doc(hidden)]
pub fn validate_source_url_security(source: &str) -> Result<(), &'static str> {
    validate_source_text(source)?;
    if source.contains("://") {
        validate_url_source(source)?;
    } else if parse_scp_like_git_source(source)?.is_some() {
        validate_source_query_security(source)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_local_source_path_text(source: &str) -> Result<(), &'static str> {
    validate_source_text(source)?;
    let mut layer = source.to_owned();
    for depth in 0..=SOURCE_PERCENT_DECODE_ROUNDS {
        validate_source_query_security(&layer)?;
        if layer.contains("://")
            || looks_like_uri_scheme(&layer)
            || parse_scp_like_git_source(&layer)?.is_some()
        {
            return Err(SOURCE_SECURITY_ERROR);
        }
        let decoded = percent_decode_source_shape_layer(&layer);
        if decoded == layer {
            return Ok(());
        }
        if depth == SOURCE_PERCENT_DECODE_ROUNDS {
            return Err(SOURCE_SECURITY_ERROR);
        }
        layer = decoded;
    }
    Err(SOURCE_SECURITY_ERROR)
}

#[doc(hidden)]
pub fn validate_git_source_security(source: &str) -> Result<(), &'static str> {
    validate_source_text(source)?;
    if source.contains("://") {
        let parsed = validate_url_source(source)?;
        if !matches!(parsed.scheme(), "file" | "https" | "ssh" | "git+ssh")
            || (parsed.scheme() != "file" && parsed.host_str().is_none())
        {
            return Err(SOURCE_SECURITY_ERROR);
        }
        return Ok(());
    }
    if source.contains('@') {
        return parse_scp_like_git_source(source)
            .and_then(|source| source.map(|_| ()).ok_or(SOURCE_SECURITY_ERROR));
    }
    validate_local_source_path_text(source)
}

#[doc(hidden)]
pub fn validate_registry_source_security(source: &str) -> Result<(), &'static str> {
    validate_source_text(source)?;
    if source.contains("://") {
        let parsed = validate_url_source(source)?;
        if (parsed.scheme() == "https" && parsed.host_str().is_some()) || parsed.scheme() == "file"
        {
            return Ok(());
        }
        return Err(SOURCE_SECURITY_ERROR);
    }
    validate_local_source_path_text(source)
}

#[doc(hidden)]
pub fn validate_artifact_source_security(source: &str) -> Result<(), &'static str> {
    validate_registry_source_security(source)
}

#[doc(hidden)]
pub fn validate_advisory_source_security(source: &str) -> Result<(), &'static str> {
    let parsed = validate_url_source(source)?;
    if parsed.scheme() == "https" && parsed.host_str().is_some() {
        Ok(())
    } else {
        Err(SOURCE_SECURITY_ERROR)
    }
}

fn validate_git_revision_security(revision: &str) -> Result<(), &'static str> {
    if revision.is_empty()
        || revision.len() > GIT_REVISION_MAX_BYTES
        || revision.starts_with('-')
        || revision.contains('#')
        || revision.chars().any(char::is_control)
    {
        return Err(GIT_REVISION_ERROR);
    }
    validate_local_source_path_text(revision).map_err(|_| GIT_REVISION_ERROR)
}

#[doc(hidden)]
pub fn secure_https_source(source: &str) -> bool {
    validate_url_source(source)
        .is_ok_and(|parsed| parsed.scheme() == "https" && parsed.host_str().is_some())
}

#[doc(hidden)]
pub fn validate_dependency_source_security(dependency: &Dependency) -> Result<(), &'static str> {
    match dependency {
        Dependency::Path { path, .. } => path
            .to_str()
            .ok_or(SOURCE_SECURITY_ERROR)
            .and_then(validate_local_source_path_text),
        Dependency::Git { url, revision, .. } => validate_git_source_security(url)
            .and_then(|()| validate_git_revision_security(revision)),
        Dependency::Registry { registry, .. } => validate_registry_source_security(registry),
    }
}

fn validate_locked_dependency_source(source: &str) -> Result<(), &'static str> {
    let (kind, value) = source.split_once(':').ok_or(SOURCE_SECURITY_ERROR)?;
    if value.is_empty() {
        return Err(SOURCE_SECURITY_ERROR);
    }
    match kind {
        "path" => validate_local_source_path_text(value),
        "git" => validate_git_source_security(value),
        "registry" => validate_registry_source_security(value),
        _ => Err(SOURCE_SECURITY_ERROR),
    }
}

fn validate_lock_source_security(path: &Path, lock: &LockFile) -> Result<(), ManifestError> {
    if lock.packages.iter().any(|package| {
        validate_locked_dependency_source(&package.source).is_err()
            || package
                .revision
                .as_deref()
                .is_some_and(|revision| validate_git_revision_security(revision).is_err())
    }) {
        return Err(manifest_error(path, None, SOURCE_SECURITY_ERROR));
    }
    Ok(())
}

#[doc(hidden)]
pub fn safe_source_value_for_display(source: &str) -> String {
    if validate_git_source_security(source).is_ok()
        || validate_registry_source_security(source).is_ok()
        || validate_advisory_source_security(source).is_ok()
        || validate_local_source_path_text(source).is_ok()
    {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

#[doc(hidden)]
pub fn safe_local_source_path_for_display(path: &Path) -> String {
    path.to_str()
        .filter(|source| validate_local_source_path_text(source).is_ok())
        .map(str::to_owned)
        .unwrap_or_else(|| HIDDEN_SOURCE_VALUE.into())
}

#[doc(hidden)]
pub fn safe_git_source_value_for_display(source: &str) -> String {
    if validate_git_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

#[doc(hidden)]
pub fn safe_registry_source_value_for_display(source: &str) -> String {
    if validate_registry_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

#[doc(hidden)]
pub fn safe_artifact_source_value_for_display(source: &str) -> String {
    if validate_artifact_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

#[doc(hidden)]
pub fn safe_advisory_source_value_for_display(source: &str) -> String {
    if validate_advisory_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

#[doc(hidden)]
pub fn safe_git_revision_for_display(revision: &str) -> String {
    if validate_git_revision_security(revision).is_ok() {
        revision.to_owned()
    } else {
        "<已隐藏的不安全修订>".into()
    }
}

#[doc(hidden)]
pub fn safe_dependency_source_for_display(source: &str) -> String {
    if validate_locked_dependency_source(source).is_ok() {
        source.to_owned()
    } else {
        match source.split_once(':').map(|(kind, _)| kind) {
            Some("path") => format!("path:{HIDDEN_SOURCE_VALUE}"),
            Some("git") => format!("git:{HIDDEN_SOURCE_VALUE}"),
            Some("registry") => format!("registry:{HIDDEN_SOURCE_VALUE}"),
            _ => HIDDEN_SOURCE_VALUE.into(),
        }
    }
}

fn secure_git_source(url: &str) -> bool {
    if validate_git_source_security(url).is_err() || url.starts_with('-') {
        return false;
    }
    if url.contains("://") {
        return url::Url::parse(url).is_ok_and(|parsed| {
            matches!(parsed.scheme(), "file" | "https" | "ssh" | "git+ssh")
                && (parsed.scheme() == "file" || parsed.host_str().is_some())
        });
    }
    Path::new(url).exists() || parse_scp_like_git_source(url).is_ok_and(|source| source.is_some())
}

fn resolve_registry(
    name: &str,
    requirement: &VersionReq,
    registry: &str,
    locked: Option<Version>,
    locked_checksum: Option<&str>,
    offline: bool,
) -> Result<ResolvedDependency, ManifestError> {
    validate_source_url_security(registry)
        .map_err(|message| manifest_error("索引来源", None, message))?;
    let source = format!("registry:{registry}");
    if let Some(registry_path) = local_registry_path(registry) {
        let package_root = registry_path.join(name);
        let version = select_registry_version(&package_root, requirement, locked.as_ref())?;
        let root = package_root.join(version.to_string());
        let resolved = lock_local(name, &root, &source, None, Some(requirement))?;
        if resolved.locked.version != version.to_string() {
            return Err(manifest_error(
                &root,
                None,
                "索引目录版本与包清单版本不一致",
            ));
        }
        return Ok(resolved);
    }
    if !secure_https_source(registry) {
        return Err(manifest_error("索引来源", None, "远程包索引须使用 HTTPS"));
    }
    if offline && locked.is_none() {
        return Err(manifest_error(
            "索引来源",
            None,
            format!("离线模式须由锁文件固定索引依赖“{name}”"),
        ));
    }
    let registry_cache = cache_root().join("registry").join(short_hash(registry));
    if let Some(version) = &locked {
        let expected_checksum = locked_checksum.ok_or_else(|| {
            manifest_error(
                &registry_cache,
                None,
                format!("锁定索引依赖“{name}”缺少内容 SHA-256"),
            )
        })?;
        if !valid_sha256(expected_checksum) {
            return Err(manifest_error(
                &registry_cache,
                None,
                format!("锁定索引依赖“{name}”的内容 SHA-256 无效"),
            ));
        }
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry,
            name,
            version,
            requirement,
        };
        let _cache_lock = acquire_registry_package_lock(&key)?;
        let lookup = find_cached_registry_package_locked(&key, expected_checksum, true)?;
        if let Some(resolved) = lookup.resolved {
            return Ok(resolved);
        }
        if offline {
            if let Some(error) = lookup.invalid {
                let message = if error.code() == "PACKAGE000" {
                    format!(
                        "离线索引缓存损坏或与锁文件校验和不一致：{}；请联网重新安装",
                        error.message
                    )
                } else {
                    format!(
                        "[{}] 离线索引缓存损坏或与锁文件校验和不一致：{}；请联网重新安装",
                        error.code(),
                        error.diagnostic_message()
                    )
                };
                return Err(manifest_error(error.path, None, message));
            }
            return Err(manifest_error(
                &registry_cache,
                None,
                format!("离线模式下未缓存索引依赖“{name}”"),
            ));
        }
    }
    if offline {
        return Err(manifest_error(
            &registry_cache,
            None,
            format!("离线模式下未缓存索引依赖“{name}”"),
        ));
    }
    fs::create_dir_all(&registry_cache).map_err(|error| {
        manifest_error(&registry_cache, None, format!("不能创建索引缓存：{error}"))
    })?;
    let (index, index_path) = download_registry_index(&registry_cache, registry, name)?;
    let (version, release) =
        select_remote_registry_release(index.versions, requirement, locked.as_ref()).ok_or_else(
            || {
                manifest_error(
                    &index_path,
                    None,
                    format!("远程索引中没有满足 {requirement} 的“{name}”版本"),
                )
            },
        )?;
    if !valid_sha256(&release.checksum) {
        return Err(manifest_error(
            &index_path,
            None,
            format!("索引版本 {version} 缺少合法的制品 SHA-256"),
        ));
    }
    if !secure_https_source(&release.url) {
        return Err(manifest_error(
            &index_path,
            None,
            format!("索引版本 {version} 的制品地址须使用 HTTPS"),
        ));
    }
    let key = RegistryPackageKey {
        registry_cache: &registry_cache,
        registry,
        name,
        version: &version,
        requirement,
    };
    let staged = stage_registry_release(&key, &release, locked_checksum)?;
    publish_registry_snapshot(&key, staged)
}

const REGISTRY_SNAPSHOT_LAYOUT: &str = "tree-v1";

struct RegistryPackageKey<'a> {
    registry_cache: &'a Path,
    registry: &'a str,
    name: &'a str,
    version: &'a Version,
    requirement: &'a VersionReq,
}

struct RegistryCacheLookup {
    resolved: Option<ResolvedDependency>,
    invalid: Option<ManifestError>,
}

#[derive(Debug)]
struct RegistryTemporaryDirectory {
    path: PathBuf,
    retained: bool,
}

impl RegistryTemporaryDirectory {
    fn create(parent: &Path, purpose: &str) -> Result<Self, ManifestError> {
        fs::create_dir_all(parent).map_err(|error| {
            manifest_error(parent, None, format!("不能创建索引临时目录：{error}"))
        })?;
        for _ in 0..1_024 {
            let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".{purpose}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        retained: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(manifest_error(
                        &path,
                        None,
                        format!("不能创建唯一索引临时目录：{error}"),
                    ));
                }
            }
        }
        Err(manifest_error(parent, None, "不能分配唯一索引临时目录"))
    }

    fn create_within(boundary: &Path, parent: &Path, purpose: &str) -> Result<Self, ManifestError> {
        let temporary = Self::create(parent, purpose)?;
        let canonical_boundary = fs::canonicalize(boundary).map_err(|error| {
            manifest_error(boundary, None, format!("不能定位索引缓存根目录：{error}"))
        })?;
        let canonical_temporary = fs::canonicalize(temporary.path()).map_err(|error| {
            manifest_error(
                temporary.path(),
                None,
                format!("不能定位索引临时目录：{error}"),
            )
        })?;
        if !canonical_temporary.starts_with(canonical_boundary) {
            return Err(manifest_error(
                temporary.path(),
                None,
                "索引临时目录越出缓存根目录",
            ));
        }
        Ok(temporary)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(mut self, destination: &Path) -> Result<(), ManifestError> {
        rename_registry_directory(&self.path, destination).map_err(|error| {
            manifest_error(destination, None, format!("不能原子发布索引缓存：{error}"))
        })?;
        self.retained = true;
        Ok(())
    }
}

impl Drop for RegistryTemporaryDirectory {
    fn drop(&mut self) {
        if !self.retained {
            fs::remove_dir_all(&self.path).ok();
        }
    }
}

#[cfg(not(windows))]
fn rename_registry_directory(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn rename_registry_directory(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an interior NUL",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }

    let source = wide(source)?;
    let destination = wide(destination)?;
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug)]
struct StagedRegistryPackage {
    _temporary: RegistryTemporaryDirectory,
    root: PathBuf,
    tree_checksum: String,
    artifact_checksum: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryInstallCheckpoint {
    BeforeCopyEntry,
    CandidateCopied,
    BeforePublish,
}

fn download_registry_index(
    registry_cache: &Path,
    registry: &str,
    name: &str,
) -> Result<(RegistryIndex, PathBuf), ManifestError> {
    let temporary = RegistryTemporaryDirectory::create_within(
        registry_cache,
        &registry_cache.join(".staging"),
        "index-download",
    )?;
    let downloaded = temporary.path().join("index.json");
    download(
        &format!("{}/{name}/index.json", registry.trim_end_matches('/')),
        &downloaded,
    )?;
    let index = read_registry_index(&downloaded)?;
    let bytes = fs::read(&downloaded).map_err(|error| {
        manifest_error(&downloaded, None, format!("不能读取索引下载结果：{error}"))
    })?;
    let cached = registry_cache.join(format!("{}-index.json", short_hash(name)));
    crate::storage::atomic_write(&cached, &bytes).map_err(|error| {
        manifest_error(&cached, None, format!("不能原子保存索引下载结果：{error}"))
    })?;
    Ok((index, cached))
}

fn stage_registry_release(
    key: &RegistryPackageKey<'_>,
    release: &RegistryRelease,
    expected_tree_checksum: Option<&str>,
) -> Result<StagedRegistryPackage, ManifestError> {
    let temporary = RegistryTemporaryDirectory::create_within(
        key.registry_cache,
        &key.registry_cache.join(".staging"),
        "package-download",
    )?;
    let archive = temporary.path().join("package.tar.gz");
    download(&release.url, &archive)?;
    prepare_staged_registry_package(
        key,
        temporary,
        &archive,
        &release.checksum,
        expected_tree_checksum,
    )
}

fn prepare_staged_registry_package(
    key: &RegistryPackageKey<'_>,
    temporary: RegistryTemporaryDirectory,
    archive: &Path,
    expected_artifact_checksum: &str,
    expected_tree_checksum: Option<&str>,
) -> Result<StagedRegistryPackage, ManifestError> {
    prepare_staged_registry_package_with_hook(
        key,
        temporary,
        archive,
        expected_artifact_checksum,
        expected_tree_checksum,
        |_| Ok(()),
    )
}

fn prepare_staged_registry_package_with_hook(
    key: &RegistryPackageKey<'_>,
    temporary: RegistryTemporaryDirectory,
    archive: &Path,
    expected_artifact_checksum: &str,
    expected_tree_checksum: Option<&str>,
    after_archive_snapshot: impl FnOnce(&Path) -> Result<(), ManifestError>,
) -> Result<StagedRegistryPackage, ManifestError> {
    if !valid_sha256(expected_artifact_checksum) {
        return Err(manifest_error(archive, None, "索引制品 SHA-256 无效"));
    }
    let archive_bytes = read_registry_archive_snapshot(archive)?;
    let actual_checksum = format!("{:x}", Sha256::digest(&archive_bytes));
    if !actual_checksum.eq_ignore_ascii_case(expected_artifact_checksum) {
        return Err(manifest_error(
            archive,
            None,
            format!("索引制品校验不符：应为 {expected_artifact_checksum}，实为 {actual_checksum}"),
        ));
    }
    after_archive_snapshot(archive)?;
    let unpacked = temporary.path().join("unpacked");
    fs::create_dir(&unpacked).map_err(|error| {
        manifest_error(&unpacked, None, format!("不能创建制品展开目录：{error}"))
    })?;
    extract_archive_bytes_safely(&archive_bytes, archive, &unpacked)?;
    let root = find_manifest_root(&unpacked)?;
    let resolved = validate_registry_root(key, &root, expected_tree_checksum)?;
    Ok(StagedRegistryPackage {
        _temporary: temporary,
        root,
        tree_checksum: resolved.locked.checksum,
        artifact_checksum: expected_artifact_checksum.to_ascii_lowercase(),
    })
}

fn read_registry_archive_snapshot(archive: &Path) -> Result<Vec<u8>, ManifestError> {
    let metadata = fs::symlink_metadata(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能检查索引制品：{error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(manifest_error(
            archive,
            None,
            "索引制品必须是普通文件，不得为符号链接或特殊文件",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能打开索引制品：{error}")))?;
    let opened = file.metadata().map_err(|error| {
        manifest_error(archive, None, format!("不能检查已打开的索引制品：{error}"))
    })?;
    if !opened.is_file() || opened.len() > ARCHIVE_MAX_COMPRESSED_BYTES {
        return Err(manifest_error(
            archive,
            None,
            format!(
                "索引制品压缩后为 {} 字节，超过 {} 字节上限或不是普通文件",
                opened.len(),
                ARCHIVE_MAX_COMPRESSED_BYTES
            ),
        ));
    }
    let capacity = usize::try_from(opened.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(ARCHIVE_MAX_COMPRESSED_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| manifest_error(archive, None, format!("不能读取索引制品：{error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > ARCHIVE_MAX_COMPRESSED_BYTES {
        return Err(manifest_error(
            archive,
            None,
            format!("索引制品压缩后超过 {ARCHIVE_MAX_COMPRESSED_BYTES} 字节上限"),
        ));
    }
    Ok(bytes)
}

fn acquire_registry_package_lock(
    key: &RegistryPackageKey<'_>,
) -> Result<crate::storage::ProjectLock, ManifestError> {
    let identity = format!("{}\0{}", key.name, key.version);
    #[cfg(any(windows, target_os = "macos"))]
    let identity = identity.to_ascii_lowercase();
    let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
    let lock_root = key.registry_cache.join(".locks").join(digest);
    let lock = crate::storage::ProjectLock::acquire(&lock_root).map_err(|error| {
        manifest_error(&lock_root, None, format!("不能取得索引版本缓存锁：{error}"))
    })?;
    let canonical_cache = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    let canonical_lock = fs::canonicalize(&lock_root).map_err(|error| {
        manifest_error(&lock_root, None, format!("不能定位索引版本缓存锁：{error}"))
    })?;
    if !canonical_lock.starts_with(canonical_cache) {
        return Err(manifest_error(
            &lock_root,
            None,
            "索引版本缓存锁越出缓存根目录",
        ));
    }
    Ok(lock)
}

fn registry_snapshot_checksum_root(key: &RegistryPackageKey<'_>, checksum: &str) -> PathBuf {
    key.registry_cache
        .join(key.name)
        .join(".snapshots")
        .join(REGISTRY_SNAPSHOT_LAYOUT)
        .join(key.version.to_string())
        .join(checksum.to_ascii_lowercase())
}

fn create_registry_snapshot_checksum_root(
    key: &RegistryPackageKey<'_>,
    checksum: &str,
) -> Result<PathBuf, ManifestError> {
    let mut directory = key.registry_cache.to_path_buf();
    for component in [
        key.name.to_owned(),
        ".snapshots".to_owned(),
        REGISTRY_SNAPSHOT_LAYOUT.to_owned(),
        key.version.to_string(),
        checksum.to_ascii_lowercase(),
    ] {
        directory.push(component);
        let created = match fs::create_dir(&directory) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(manifest_error(
                    &directory,
                    None,
                    format!("不能创建索引快照目录：{error}"),
                ));
            }
        };
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            manifest_error(&directory, None, format!("不能检查索引快照目录：{error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(manifest_error(
                &directory,
                None,
                "索引快照目录必须是普通目录",
            ));
        }
        if created {
            sync_registry_directory_parent(&directory)?;
        }
    }
    let canonical_cache = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    let canonical_directory = fs::canonicalize(&directory).map_err(|error| {
        manifest_error(&directory, None, format!("不能定位索引快照目录：{error}"))
    })?;
    if !canonical_directory.starts_with(canonical_cache) {
        return Err(manifest_error(
            &directory,
            None,
            "索引快照目录越出缓存根目录",
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn sync_registry_directory_parent(path: &Path) -> Result<(), ManifestError> {
    let parent = path
        .parent()
        .ok_or_else(|| manifest_error(path, None, "索引快照目录没有可同步的父目录"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| manifest_error(parent, None, format!("不能同步索引快照父目录：{error}")))
}

#[cfg(not(unix))]
fn sync_registry_directory_parent(_path: &Path) -> Result<(), ManifestError> {
    Ok(())
}

fn registry_legacy_root(key: &RegistryPackageKey<'_>) -> PathBuf {
    key.registry_cache
        .join(key.name)
        .join(key.version.to_string())
}

fn registry_generation_destination(
    checksum_root: &Path,
    artifact_checksum: &str,
) -> Result<PathBuf, ManifestError> {
    let primary = checksum_root.join(artifact_checksum);
    match fs::symlink_metadata(&primary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(primary),
        Ok(_) => {}
        Err(error) => {
            return Err(manifest_error(
                &primary,
                None,
                format!("不能检查索引快照发布位置：{error}"),
            ));
        }
    }
    for _ in 0..1_024 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let repair = checksum_root.join(format!(
            "{artifact_checksum}-repair-{}-{sequence}",
            std::process::id()
        ));
        match fs::symlink_metadata(&repair) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(repair),
            Ok(_) => continue,
            Err(error) => {
                return Err(manifest_error(
                    &repair,
                    None,
                    format!("不能检查索引快照修复位置：{error}"),
                ));
            }
        }
    }
    Err(manifest_error(
        checksum_root,
        None,
        "不能分配唯一索引快照发布位置",
    ))
}

fn validate_registry_root(
    key: &RegistryPackageKey<'_>,
    root: &Path,
    expected_tree_checksum: Option<&str>,
) -> Result<ResolvedDependency, ManifestError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| manifest_error(root, None, format!("不能检查索引包缓存：{error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(manifest_error(root, None, "索引包缓存根必须是普通目录"));
    }
    if let Some(expected) = expected_tree_checksum
        && !valid_sha256(expected)
    {
        return Err(manifest_error(root, None, "索引包内容 SHA-256 无效"));
    }
    validate_published_package_tree(root)?;
    let source = format!("registry:{}", key.registry);
    let mut resolved = lock_local(key.name, root, &source, None, Some(key.requirement))?;
    if resolved.locked.version != key.version.to_string() {
        return Err(manifest_error(
            &resolved.root,
            None,
            format!(
                "索引选择版本 {}，包清单却声明 {}",
                key.version, resolved.locked.version
            ),
        ));
    }
    if let Some(expected) = expected_tree_checksum {
        if resolved.locked.checksum != expected && !tree_checksum_matches(&resolved.root, expected)?
        {
            return Err(manifest_error(
                &resolved.root,
                None,
                format!(
                    "索引包内容校验不符：应为 {expected}，实为 {}",
                    resolved.locked.checksum
                ),
            ));
        }
        resolved.locked.checksum = expected.to_owned();
    }
    let canonical_cache = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    if !resolved.root.starts_with(&canonical_cache) {
        return Err(manifest_error(
            &resolved.root,
            None,
            "索引包缓存越出缓存根目录",
        ));
    }
    Ok(resolved)
}

fn validate_published_package_tree(root: &Path) -> Result<(), ManifestError> {
    let mut directories = vec![root.to_path_buf()];
    let mut paths = PortablePackagePaths::default();
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            manifest_error(&directory, None, format!("不能遍历发布包内容：{error}"))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                manifest_error(&directory, None, format!("不能读取发布包目录项：{error}"))
            })?;
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("walk under published root");
            match package_path_decision(relative, PackagePathPurpose::YxpEntry)
                .map_err(|error| package_path_manifest_error(&path, error))?
            {
                PackagePathDecision::Include => {}
                PackagePathDecision::Exclude(_) => {
                    let error =
                        package_path_decision(relative, PackagePathPurpose::ManifestReference)
                            .expect_err(
                                "excluded package path must be rejected as a manifest reference",
                            );
                    return Err(package_path_manifest_error(&path, error));
                }
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                manifest_error(&path, None, format!("不能检查发布包内容：{error}"))
            })?;
            if metadata.is_dir() {
                paths
                    .insert_directory(relative)
                    .map_err(|error| package_path_manifest_error(&path, error))?;
            } else {
                paths
                    .insert(relative)
                    .map_err(|error| package_path_manifest_error(&path, error))?;
            }
            if metadata.file_type().is_symlink() {
                return Err(manifest_error(&path, None, "发布包不得包含符号链接"));
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if !metadata.is_file() {
                return Err(manifest_error(&path, None, "发布包不得包含特殊文件"));
            }
        }
    }
    Ok(())
}

fn find_cached_registry_package_locked(
    key: &RegistryPackageKey<'_>,
    expected_tree_checksum: &str,
    include_legacy: bool,
) -> Result<RegistryCacheLookup, ManifestError> {
    if !valid_sha256(expected_tree_checksum) {
        return Err(manifest_error(
            key.registry_cache,
            None,
            "索引包内容 SHA-256 无效",
        ));
    }
    let checksum_root = registry_snapshot_checksum_root(key, expected_tree_checksum);
    let mut invalid = None;
    match fs::symlink_metadata(&checksum_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            invalid = Some(manifest_error(&checksum_root, None, "索引快照目录类型无效"));
        }
        Ok(_) => {
            let mut generations = fs::read_dir(&checksum_root)
                .map_err(|error| {
                    manifest_error(
                        &checksum_root,
                        None,
                        format!("不能读取索引快照目录：{error}"),
                    )
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    manifest_error(&checksum_root, None, format!("不能读取索引快照项：{error}"))
                })?;
            generations.sort_by_key(std::fs::DirEntry::file_name);
            for generation in generations {
                if generation.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }
                let path = generation.path();
                match generation.file_type() {
                    Ok(file_type) if file_type.is_dir() && !file_type.is_symlink() => {
                        match validate_registry_root(key, &path, Some(expected_tree_checksum)) {
                            Ok(resolved) => {
                                return Ok(RegistryCacheLookup {
                                    resolved: Some(resolved),
                                    invalid,
                                });
                            }
                            Err(error) => {
                                invalid.get_or_insert(error);
                            }
                        }
                    }
                    Ok(_) => {
                        invalid.get_or_insert_with(|| {
                            manifest_error(&path, None, "索引快照项类型无效")
                        });
                    }
                    Err(error) => {
                        invalid.get_or_insert_with(|| {
                            manifest_error(&path, None, format!("不能检查索引快照项：{error}"))
                        });
                    }
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(manifest_error(
                &checksum_root,
                None,
                format!("不能检查索引快照目录：{error}"),
            ));
        }
    }
    if include_legacy {
        let legacy = registry_legacy_root(key);
        match fs::symlink_metadata(&legacy) {
            Ok(_) => match validate_registry_root(key, &legacy, Some(expected_tree_checksum)) {
                Ok(resolved) => {
                    return Ok(RegistryCacheLookup {
                        resolved: Some(resolved),
                        invalid,
                    });
                }
                Err(error) => {
                    invalid.get_or_insert(error);
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                invalid.get_or_insert_with(|| {
                    manifest_error(&legacy, None, format!("不能检查旧索引缓存：{error}"))
                });
            }
        }
    }
    Ok(RegistryCacheLookup {
        resolved: None,
        invalid,
    })
}

fn publish_registry_snapshot(
    key: &RegistryPackageKey<'_>,
    staged: StagedRegistryPackage,
) -> Result<ResolvedDependency, ManifestError> {
    publish_registry_snapshot_with_checkpoint(key, staged, |_, _| Ok(()))
}

fn publish_registry_snapshot_with_checkpoint(
    key: &RegistryPackageKey<'_>,
    staged: StagedRegistryPackage,
    mut checkpoint: impl FnMut(RegistryInstallCheckpoint, &Path) -> Result<(), ManifestError>,
) -> Result<ResolvedDependency, ManifestError> {
    let staged_resolved = validate_registry_root(key, &staged.root, Some(&staged.tree_checksum))?;
    if staged_resolved.locked.checksum != staged.tree_checksum {
        return Err(manifest_error(
            &staged.root,
            None,
            "索引暂存内容在发布前发生变化",
        ));
    }
    let _cache_lock = acquire_registry_package_lock(key)?;
    let lookup = find_cached_registry_package_locked(key, &staged.tree_checksum, false)?;
    if let Some(resolved) = lookup.resolved {
        return Ok(resolved);
    }

    let checksum_root = create_registry_snapshot_checksum_root(key, &staged.tree_checksum)?;

    let candidate =
        RegistryTemporaryDirectory::create_within(key.registry_cache, &checksum_root, "candidate")?;
    copy_registry_tree_with_checkpoint(&staged.root, candidate.path(), &mut checkpoint)?;
    checkpoint(RegistryInstallCheckpoint::CandidateCopied, candidate.path())?;
    validate_registry_root(key, candidate.path(), Some(&staged.tree_checksum))?;

    let generation = registry_generation_destination(&checksum_root, &staged.artifact_checksum)?;
    checkpoint(RegistryInstallCheckpoint::BeforePublish, &generation)?;
    candidate.publish(&generation)?;
    #[cfg(unix)]
    fs::File::open(&checksum_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            manifest_error(
                &checksum_root,
                None,
                format!("不能同步索引快照目录：{error}"),
            )
        })?;
    validate_registry_root(key, &generation, Some(&staged.tree_checksum))
}

#[doc(hidden)]
pub fn registry_release_metadata(
    registry: &str,
    name: &str,
    version: &Version,
    offline: bool,
) -> Result<Option<RegistryReleaseMetadata>, ManifestError> {
    validate_source_url_security(registry)
        .map_err(|message| manifest_error("索引来源", None, message))?;
    let index_path = if let Some(registry_path) = local_registry_path(registry) {
        registry_path.join(name).join("index.json")
    } else {
        if !secure_https_source(registry) {
            return Err(manifest_error("索引来源", None, "远程包索引须使用 HTTPS"));
        }
        let registry_cache = cache_root().join("registry").join(short_hash(registry));
        if !offline {
            fs::create_dir_all(&registry_cache).map_err(|error| {
                manifest_error(&registry_cache, None, format!("不能创建索引缓存：{error}"))
            })?;
        }
        let index_path = registry_cache.join(format!("{}-index.json", short_hash(name)));
        if !offline {
            download(
                &format!("{}/{name}/index.json", registry.trim_end_matches('/')),
                &index_path,
            )?;
        }
        index_path
    };
    if !index_path.is_file() {
        return Ok(None);
    }
    let index = read_registry_index(&index_path)?;
    Ok(index
        .versions
        .into_iter()
        .find(|release| release.version == version.to_string())
        .map(|release| RegistryReleaseMetadata {
            url: release.url,
            checksum: release.checksum,
            yanked: release.yanked,
            vulnerabilities: release.vulnerabilities,
        }))
}

fn local_registry_path(registry: &str) -> Option<PathBuf> {
    registry
        .strip_prefix("file://")
        .map(PathBuf::from)
        .or_else(|| {
            let path = PathBuf::from(registry);
            path.is_dir().then_some(path)
        })
}

fn read_registry_index(path: &Path) -> Result<RegistryIndex, ManifestError> {
    let index_text = fs::read_to_string(path)
        .map_err(|error| manifest_error(path, None, format!("不能读取索引元数据：{error}")))?;
    reject_duplicate_registry_json_keys(path, index_text.as_bytes())?;
    let index: RegistryIndex = serde_json::from_str(&index_text)
        .map_err(|error| manifest_error(path, None, format!("索引元数据无效：{error}")))?;
    validate_registry_index(path, &index)?;
    Ok(index)
}

fn reject_duplicate_registry_json_keys(path: &Path, payload: &[u8]) -> Result<(), ManifestError> {
    use serde::de::{MapAccess, SeqAccess, Visitor};

    struct UniqueJson;
    struct UniqueVisitor;

    impl<'de> Deserialize<'de> for UniqueJson {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(UniqueVisitor)
        }
    }

    impl<'de> Visitor<'de> for UniqueVisitor {
        type Value = UniqueJson;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("无重复对象键的 JSON")
        }

        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(UniqueJson)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            while sequence.next_element::<UniqueJson>()?.is_some() {}
            Ok(UniqueJson)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key.clone()) {
                    return Err(serde::de::Error::custom(format!("JSON 对象键重复：{key}")));
                }
                map.next_value::<UniqueJson>()?;
            }
            Ok(UniqueJson)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    UniqueJson::deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|error| manifest_error(path, None, format!("索引元数据无效：{error}")))
}

fn validate_registry_index(path: &Path, index: &RegistryIndex) -> Result<(), ManifestError> {
    if index.versions.len() > REGISTRY_INDEX_MAX_VERSIONS {
        return Err(manifest_error(
            path,
            None,
            format!(
                "索引版本数量 {} 超过上限 {REGISTRY_INDEX_MAX_VERSIONS}",
                index.versions.len()
            ),
        ));
    }
    let mut versions = BTreeSet::new();
    for release in &index.versions {
        Version::parse(&release.version).map_err(|error| {
            manifest_error(
                path,
                None,
                format!("索引版本“{}”无效：{error}", release.version),
            )
        })?;
        if !versions.insert(release.version.as_str()) {
            return Err(manifest_error(
                path,
                None,
                format!("索引版本重复：{}", release.version),
            ));
        }
        if release.url.is_empty()
            || release.checksum.is_empty()
            || release.version.len() > 128
            || release.url.len() > REGISTRY_RELEASE_URL_MAX_BYTES
            || release.checksum.len() > 128
            || release
                .version
                .chars()
                .chain(release.url.chars())
                .chain(release.checksum.chars())
                .any(char::is_control)
        {
            return Err(manifest_error(
                path,
                None,
                "索引版本字段为空、过长或包含控制字符",
            ));
        }
        if validate_artifact_source_security(&release.url).is_err() {
            return Err(manifest_error(path, None, SOURCE_SECURITY_ERROR));
        }
        let Some(vulnerabilities) = &release.vulnerabilities else {
            continue;
        };
        if vulnerabilities.len() > REGISTRY_VULNERABILITY_MAX_COUNT {
            return Err(manifest_error(
                path,
                None,
                format!(
                    "版本 {} 的漏洞数量超过上限 {REGISTRY_VULNERABILITY_MAX_COUNT}",
                    release.version
                ),
            ));
        }
        for vulnerability in vulnerabilities {
            let reference = vulnerability.url.as_deref().unwrap_or("");
            if vulnerability.id.len() > REGISTRY_VULNERABILITY_ID_MAX_BYTES
                || vulnerability.severity.len() > 32
                || vulnerability.summary.len() > REGISTRY_VULNERABILITY_SUMMARY_MAX_BYTES
                || reference.len() > REGISTRY_RELEASE_URL_MAX_BYTES
                || vulnerability
                    .id
                    .chars()
                    .chain(vulnerability.severity.chars())
                    .chain(vulnerability.summary.chars())
                    .chain(reference.chars())
                    .any(char::is_control)
            {
                return Err(manifest_error(
                    path,
                    None,
                    format!("版本 {} 的漏洞元数据过长或包含控制字符", release.version),
                ));
            }
            if !reference.is_empty() && validate_advisory_source_security(reference).is_err() {
                return Err(manifest_error(path, None, SOURCE_SECURITY_ERROR));
            }
        }
    }
    Ok(())
}

fn select_remote_registry_release(
    releases: Vec<RegistryRelease>,
    requirement: &VersionReq,
    locked: Option<&Version>,
) -> Option<(Version, RegistryRelease)> {
    let mut candidates = releases
        .into_iter()
        .filter_map(|release| {
            let version = Version::parse(&release.version).ok()?;
            (requirement.matches(&version)
                && locked.is_none_or(|locked| locked == &version)
                && (locked.is_some() || release.yanked != Some(true)))
            .then_some((version, release))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn select_registry_version(
    package_root: &Path,
    requirement: &VersionReq,
    locked: Option<&Version>,
) -> Result<Version, ManifestError> {
    let index_path = package_root.join("index.json");
    if index_path.is_file() {
        let index = read_registry_index(&index_path)?;
        return select_remote_registry_release(
            index
                .versions
                .into_iter()
                .filter(|release| package_root.join(&release.version).is_dir())
                .collect(),
            requirement,
            locked,
        )
        .map(|(version, _)| version)
        .ok_or_else(|| {
            manifest_error(
                package_root,
                None,
                format!("索引中没有满足 {requirement} 的未撤回版本"),
            )
        });
    }
    if let Some(locked) = locked {
        if requirement.matches(locked) && package_root.join(locked.to_string()).is_dir() {
            return Ok(locked.clone());
        }
        return Err(manifest_error(
            package_root,
            None,
            format!("锁定版本 {locked} 不在索引中或不满足 {requirement}"),
        ));
    }
    let mut versions = fs::read_dir(package_root)
        .map_err(|error| manifest_error(package_root, None, format!("不能读取包索引：{error}")))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| Version::parse(&entry.file_name().to_string_lossy()).ok())
        .filter(|version| requirement.matches(version))
        .collect::<Vec<_>>();
    versions.sort();
    versions.pop().ok_or_else(|| {
        manifest_error(
            package_root,
            None,
            format!("索引中没有满足 {requirement} 的版本"),
        )
    })
}

fn write_lock(path: &Path, lock: &LockFile) -> Result<(), ManifestError> {
    validate_lock_source_security(path, lock)?;
    let text = toml::to_string_pretty(lock)
        .map_err(|error| manifest_error(path, None, format!("不能生成锁文件：{error}")))?;
    atomic_write(path, text.as_bytes(), "锁文件")
}

fn canonical_dependency_root(path: &Path) -> Result<PathBuf, ManifestError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| manifest_error(path, None, format!("不能定位路径依赖：{error}")))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        canonical
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| manifest_error(&canonical, None, "依赖文卷没有父目录"))
    }
}

struct LimitedHashWriter<W> {
    inner: W,
    limit: u64,
    remaining: u64,
    written: u64,
    digest: Sha256,
}

impl<W> LimitedHashWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            remaining: limit,
            written: 0,
            digest: Sha256::new(),
        }
    }

    fn finish(self) -> (u64, String) {
        (self.written, format!("{:x}", self.digest.finalize()))
    }
}

impl<W: Write> Write for LimitedHashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if requested > self.remaining {
            return Err(io::Error::other(format!(
                "打包制品压缩后超过 {} 字节上限",
                self.limit
            )));
        }
        let written = self.inner.write(bytes)?;
        self.digest.update(&bytes[..written]);
        let written = written as u64;
        self.written = self.written.saturating_add(written);
        self.remaining = self.remaining.saturating_sub(written);
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// 将包源码与锁文件制成确定性 gzip/tar 归档。
pub fn pack_package(
    manifest: &Manifest,
    output: impl AsRef<Path>,
) -> Result<PackageArtifact, ManifestError> {
    pack_package_with_limits(manifest, output.as_ref(), ARCHIVE_LIMITS)
}

fn pack_package_with_limits(
    manifest: &Manifest,
    output: &Path,
    limits: ArchiveLimits,
) -> Result<PackageArtifact, ManifestError> {
    pack_package_with_limits_and_hook(manifest, output, limits, |_| Ok(()))
}

fn pack_package_with_limits_and_hook(
    manifest: &Manifest,
    output: &Path,
    limits: ArchiveLimits,
    before_archive: impl FnOnce(&Manifest) -> Result<(), ManifestError>,
) -> Result<PackageArtifact, ManifestError> {
    let _project_lock = acquire_project_lock(&manifest.root)?;
    let mut trusted_root = TrustedPackageRoots::default();
    trusted_root
        .insert(&manifest.root)
        .map_err(|error| package_path_manifest_error(&manifest.root, error))?;
    let expected_root = trusted_root
        .exact_root_identity(&manifest.root)
        .ok_or_else(|| manifest_error(&manifest.root, None, "不能绑定调用方包根目录"))?
        .to_path_buf();
    let declared_manifest = expected_root.join(MANIFEST_NAME);
    let caller_manifest = fs::canonicalize(&manifest.path).map_err(|error| {
        manifest_error(
            &manifest.path,
            None,
            format!("不能定位调用方包清单：{error}"),
        )
    })?;
    let canonical_manifest = fs::canonicalize(&declared_manifest).map_err(|error| {
        manifest_error(
            &declared_manifest,
            None,
            format!("不能定位规范包清单：{error}"),
        )
    })?;
    if caller_manifest != canonical_manifest {
        return Err(manifest_error(
            &manifest.path,
            None,
            format!("打包只能使用包根目录中的规范清单 {MANIFEST_NAME}"),
        ));
    }
    let manifest_file = trusted_root
        .resolve_existing_file(&declared_manifest, PackagePathPurpose::ManifestReference)
        .map_err(|error| package_path_manifest_error(&declared_manifest, error))?
        .ok_or_else(|| manifest_error(&declared_manifest, None, "规范包清单不属于可信包根"))?;
    let manifest_bytes =
        read_resolved_regular_file_snapshot(manifest_file, limits.file_bytes, "规范包清单")?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).map_err(|error| {
        manifest_error(
            &declared_manifest,
            None,
            format!("规范包清单不是 UTF-8：{error}"),
        )
    })?;
    let current_manifest = parse(
        manifest_text,
        declared_manifest.clone(),
        expected_root.clone(),
    )?;
    let current_root = trusted_root
        .exact_root_identity(&current_manifest.root)
        .ok_or_else(|| manifest_error(&current_manifest.root, None, "锁内包根目录身份改变"))?
        .to_path_buf();
    if current_root != expected_root {
        return Err(manifest_error(
            &current_manifest.path,
            None,
            "锁内重新读取的清单不属于调用方包根目录",
        ));
    }
    let manifest = &current_manifest;
    let in_tree_output = validate_pack_output(&manifest.root, output, limits)?;
    validate_pack_output_conflicts(manifest, in_tree_output.as_deref())?;
    validate_package_manifest_paths(manifest)?;
    let manifest_checksum = format!("{:x}", Sha256::digest(&manifest_bytes));
    let graph =
        resolve_graph_mode_locked_with_checksum(manifest, false, true, true, manifest_checksum)?;
    if let Some(dependency) = graph
        .packages
        .values()
        .find(|dependency| locked_source_is_machine_local(&dependency.locked.source))
    {
        return Err(manifest_error(
            &manifest.path,
            None,
            format!(
                "YXP 不能发布仅本机可用的依赖“{}”（{}）；请先改用可移植的 HTTPS/SSH Git 或远程索引来源",
                dependency.locked.name,
                safe_dependency_source_for_display(&dependency.locked.source)
            ),
        ));
    }
    cache_graph(manifest, graph);
    before_archive(manifest)?;
    let snapshot = capture_package_tree_in(
        &trusted_root,
        &manifest.root,
        PackagePathPurpose::YxpEntry,
        PackageTreeCaptureLimits::archive(limits),
        in_tree_output.as_deref(),
    )?;
    let files = snapshot.paths();
    if files.len() > limits.entries {
        return Err(manifest_error(
            output,
            None,
            format!("打包条目不得超过 {}", limits.entries),
        ));
    }
    let manifest_count = files
        .iter()
        .filter(|relative| {
            relative
                .file_name()
                .is_some_and(|name| name == MANIFEST_NAME)
        })
        .count();
    if manifest_count != 1
        || !files
            .iter()
            .any(|relative| relative == Path::new(MANIFEST_NAME))
    {
        return Err(manifest_error(
            output,
            None,
            format!("打包内容应恰含根目录一个 {MANIFEST_NAME}，实有 {manifest_count} 个"),
        ));
    }
    if snapshot.get(Path::new(MANIFEST_NAME)) != Some(manifest_bytes.as_slice()) {
        return Err(manifest_error(
            &declared_manifest,
            None,
            "规范包清单在锁内读取后发生变化",
        ));
    }
    validate_package_manifest_contents_structure(manifest, &files)?;
    let mut pending = crate::storage::AtomicFile::create(output)
        .map_err(|error| manifest_error(output, None, format!("不能创建归档：{error}")))?;
    let limited = LimitedHashWriter::new(pending.file_mut(), limits.compressed_bytes);
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(limited, flate2::Compression::best());
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    let mut expanded_bytes = 0_u64;
    for relative in &files {
        let path = manifest.root.join(relative);
        let archive_path = validated_yxp_archive_path(relative, &path, limits.path_bytes)?;
        let bytes = snapshot
            .get(relative)
            .expect("captured package path has bytes");
        let length = bytes.len() as u64;
        validate_packaged_bytes(manifest, relative, bytes)?;
        expanded_bytes = expanded_bytes
            .checked_add(length)
            .filter(|total| *total <= limits.expanded_bytes)
            .ok_or_else(|| {
                manifest_error(
                    output,
                    None,
                    format!("打包内容不得超过 {} 字节", limits.expanded_bytes),
                )
            })?;
        let mut header = tar::Header::new_gnu();
        header.set_size(length);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, archive_path, bytes)
            .map_err(|error| manifest_error(&path, None, format!("不能写入归档：{error}")))?;
    }
    let encoder = archive
        .into_inner()
        .map_err(|error| manifest_error(output, None, format!("不能结束 tar：{error}")))?;
    let limited = encoder
        .finish()
        .map_err(|error| manifest_error(output, None, format!("不能结束 gzip：{error}")))?;
    let (compressed_bytes, checksum) = limited.finish();
    pending
        .commit()
        .map_err(|error| manifest_error(output, None, format!("不能安装归档：{error}")))?;
    Ok(PackageArtifact {
        path: output.to_path_buf(),
        checksum,
        bytes: compressed_bytes,
        entries: files.len(),
    })
}

fn validate_package_manifest_paths(manifest: &Manifest) -> Result<(), ManifestError> {
    validate_package_manifest_path(manifest, "入口", &manifest.entry)?;
    for (name, path) in &manifest.exports {
        validate_package_manifest_path(manifest, &format!("导出“{name}”"), path)?;
    }
    for path in &manifest.resources {
        if path != Path::new(".") {
            validate_package_manifest_path(manifest, "资源", path)?;
        }
    }
    for path in &manifest.workspace_members {
        validate_package_manifest_path(manifest, "工作区成员", path)?;
    }
    if let Some(icon) = manifest
        .application
        .as_ref()
        .and_then(|application| application.icon.as_ref())
    {
        validate_package_manifest_path(manifest, "应用图标", icon)?;
    }
    if let Some(native) = &manifest.native {
        for (target, artifact) in &native.artifacts {
            validate_package_manifest_path(
                manifest,
                &format!("原生制品 {target}"),
                Path::new(&artifact.path),
            )?;
        }
    }
    Ok(())
}

fn validate_package_root(manifest: &Manifest) -> Result<(), ManifestError> {
    validate_package_manifest_paths(manifest)?;
    let mut files = Vec::new();
    collect_files(&manifest.root, &manifest.root, &mut files)?;
    sort_portable_paths(&mut files)?;
    validate_package_manifest_contents(manifest, &files)
}

fn validate_package_manifest_contents(
    manifest: &Manifest,
    files: &[PathBuf],
) -> Result<(), ManifestError> {
    validate_package_manifest_contents_structure(manifest, files)?;
    validate_native_artifacts_on_disk(manifest)
}

fn validate_package_manifest_contents_structure(
    manifest: &Manifest,
    files: &[PathBuf],
) -> Result<(), ManifestError> {
    validate_package_file(manifest, files, "入口", &manifest.entry)?;
    for (name, path) in &manifest.exports {
        validate_package_file(manifest, files, &format!("导出“{name}”"), path)?;
    }
    if let Some(icon) = manifest
        .application
        .as_ref()
        .and_then(|application| application.icon.as_ref())
    {
        validate_package_file(manifest, files, "应用图标", icon)?;
    }
    if let Some(native) = &manifest.native {
        for (target, artifact) in &native.artifacts {
            validate_package_file(
                manifest,
                files,
                &format!("原生制品 {target}"),
                Path::new(&artifact.path),
            )?;
        }
    }
    for resource in &manifest.resources {
        let normalized = normalize_pack_relative_path(resource).ok_or_else(|| {
            manifest_error(
                &manifest.path,
                None,
                format!("资源“{}”不是规范的包内路径", resource.display()),
            )
        })?;
        let full_path = if normalized.as_os_str().is_empty() {
            fs::canonicalize(&manifest.root).map_err(|error| {
                manifest_error(
                    &manifest.root,
                    None,
                    format!("不能定位包资源根目录：{error}"),
                )
            })?
        } else {
            resolve_existing_package_path(
                &manifest.root,
                &normalized,
                PackagePathPurpose::ManifestReference,
            )
            .map_err(|error| package_path_manifest_error(&manifest.path, error))?
        };
        let metadata = fs::symlink_metadata(&full_path).map_err(|error| {
            manifest_error(&full_path, None, format!("不能检查包资源目录：{error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(manifest_error(&full_path, None, "包资源必须是包内普通目录"));
        }
        let contains_resource = if normalized.as_os_str().is_empty() {
            !files.is_empty()
        } else {
            let prefix = format!(
                "{}/",
                portable_package_path(&normalized)
                    .map_err(|error| package_path_manifest_error(&manifest.path, error))?
            );
            files
                .iter()
                .any(|file| portable_package_path(file).is_ok_and(|file| file.starts_with(&prefix)))
        };
        if !contains_resource {
            return Err(manifest_error(
                &full_path,
                None,
                "包资源目录为空或其内容全部被排除，无法形成自包含内容",
            ));
        }
    }
    Ok(())
}

fn validate_native_artifacts_on_disk(manifest: &Manifest) -> Result<(), ManifestError> {
    let Some(native) = &manifest.native else {
        return Ok(());
    };
    for (target, artifact) in &native.artifacts {
        let path = resolve_existing_package_path(
            &manifest.root,
            Path::new(&artifact.path),
            PackagePathPurpose::ManifestReference,
        )
        .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
        let (actual_size, actual_checksum) =
            hash_regular_file_limited(&path, NATIVE_ARTIFACT_MAX_BYTES, "原生制品")?;
        if actual_size != artifact.size || actual_checksum != artifact.checksum {
            return Err(native_artifact_mismatch(
                &path,
                target,
                artifact,
                actual_size,
                &actual_checksum,
            ));
        }
    }
    Ok(())
}

fn native_artifact_mismatch(
    path: &Path,
    target: &str,
    artifact: &NativeArtifact,
    actual_size: u64,
    actual_checksum: &str,
) -> ManifestError {
    manifest_error(
        path,
        None,
        format!(
            "原生制品 {target} 的大小或 SHA-256 与清单不符：声明 {} 字节/{}，实际 {actual_size} 字节/{actual_checksum}",
            artifact.size, artifact.checksum
        ),
    )
}

fn hash_regular_file_limited(
    path: &Path,
    max_bytes: u64,
    kind: &str,
) -> Result<(u64, String), ManifestError> {
    let file = open_regular_file_for_snapshot(path)
        .map_err(|error| manifest_error(path, None, format!("不能打开{kind}：{error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能检查{kind}：{error}")))?;
    if !metadata.is_file() {
        return Err(manifest_error(path, None, format!("{kind}必须是普通文件")));
    }
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| manifest_error(path, None, format!("不能读取{kind}：{error}")))?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        if size > max_bytes {
            return Err(manifest_error(
                path,
                None,
                format!("{kind}不得超过 {max_bytes} 字节"),
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

/// 从解析阶段持有的普通文件句柄读取有界快照。
#[doc(hidden)]
pub fn read_resolved_regular_file_snapshot(
    resolved: ResolvedPackageFile,
    max_bytes: u64,
    kind: &str,
) -> Result<Vec<u8>, ManifestError> {
    let path = resolved.path().to_path_buf();
    read_opened_regular_file_snapshot(resolved.into_file(), &path, max_bytes, kind)
}

/// 只消费安全解析令牌中已经打开的模块句柄。
#[doc(hidden)]
pub fn read_resolved_module_source_snapshot(
    resolved: ResolvedPackageFile,
) -> Result<String, ManifestError> {
    let path = resolved.path().to_path_buf();
    let bytes =
        read_resolved_regular_file_snapshot(resolved, u64::MAX.saturating_sub(1), "模块源码")?;
    String::from_utf8(bytes)
        .map_err(|error| manifest_error(&path, None, format!("模块源码不是 UTF-8：{error}")))
}

fn read_opened_regular_file_snapshot(
    mut file: fs::File,
    path: &Path,
    max_bytes: u64,
    kind: &str,
) -> Result<Vec<u8>, ManifestError> {
    let before = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能检查已打开的{kind}：{error}")))?;
    if !before.is_file() {
        return Err(manifest_error(path, None, format!("{kind}必须是普通文件")));
    }
    if before.len() > max_bytes {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}不得超过 {max_bytes} 字节"),
        ));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| manifest_error(path, None, format!("{kind}大小无法由当前平台安全分配")))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        manifest_error(path, None, format!("不能为{kind}快照分配内存：{error}"))
    })?;
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| manifest_error(path, None, format!("不能读取{kind}：{error}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}不得超过 {max_bytes} 字节"),
        ));
    }
    let after = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能复验已打开的{kind}：{error}")))?;
    if !after.is_file()
        || before.len() != bytes.len() as u64
        || after.len() != bytes.len() as u64
        || metadata_modified_changed(&before, &after)
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在读取期间发生变化"),
        ));
    }
    Ok(bytes)
}

#[cfg(not(target_os = "wasi"))]
fn open_regular_file_for_snapshot(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !is_regular_file_metadata(&file.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "文件必须是普通文件，不得为符号链接、重解析点或特殊文件",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "wasi")]
fn open_regular_file_for_snapshot(path: &Path) -> io::Result<fs::File> {
    use rustix::fs::{AtFlags, Mode, OFlags, fstat, openat, readlinkat, statat};

    let before =
        statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let before_identity = wasi_regular_file_identity(&before)?;
    match readlinkat(rustix::fs::CWD, path, Vec::new()) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "文件不得为符号链接",
            ));
        }
        Err(error) if error == rustix::io::Errno::INVAL => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    let descriptor = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let opened = fstat(&descriptor).map_err(io::Error::from)?;
    let opened_identity = wasi_regular_file_identity(&opened)?;
    let after =
        statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    let after_identity = wasi_regular_file_identity(&after)?;
    if before_identity != opened_identity || opened_identity != after_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "文件在打开期间被替换或 WASI 宿主没有保持描述符绑定",
        ));
    }
    Ok(descriptor.into())
}

#[cfg(target_os = "wasi")]
fn wasi_regular_file_identity(metadata: &rustix::fs::Stat) -> io::Result<(u64, u64)> {
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "文件必须是普通文件，不得为符号链接或特殊文件",
        ));
    }
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WASI 宿主未提供非零文件设备号与索引号",
        ));
    }
    Ok((metadata.st_dev, metadata.st_ino))
}

#[cfg(windows)]
fn windows_file_identity(file: &fs::File) -> io::Result<(u64, [u8; 16])> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = MaybeUninit::<FILE_ID_INFO>::zeroed();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

#[cfg(all(unix, not(target_os = "wasi")))]
fn same_opened_file_identity(left: &fs::File, right: &fs::File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_opened_file_identity(left: &fs::File, right: &fs::File) -> io::Result<bool> {
    Ok(windows_file_identity(left)? == windows_file_identity(right)?)
}

#[cfg(target_os = "wasi")]
fn same_opened_file_identity(left: &fs::File, right: &fs::File) -> io::Result<bool> {
    let left = rustix::fs::fstat(left).map_err(io::Error::from)?;
    let right = rustix::fs::fstat(right).map_err(io::Error::from)?;
    Ok(wasi_regular_file_identity(&left)? == wasi_regular_file_identity(&right)?)
}

#[cfg(not(any(unix, windows, target_os = "wasi")))]
fn same_opened_file_identity(left: &fs::File, right: &fs::File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.created().ok() == right.created().ok())
}

fn is_regular_file_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && !standard_metadata_is_reparse(metadata)
}

#[cfg(windows)]
fn standard_metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn standard_metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn metadata_modified_changed(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    matches!((left.modified(), right.modified()), (Ok(left), Ok(right)) if left != right)
}

fn validate_packaged_bytes(
    manifest: &Manifest,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), ManifestError> {
    if relative == Path::new(MANIFEST_NAME) {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            manifest_error(
                &manifest.path,
                None,
                format!("归档中的规范包清单不是 UTF-8：{error}"),
            )
        })?;
        let archived = parse(text, manifest.path.clone(), manifest.root.clone())?;
        if &archived != manifest {
            return Err(manifest_error(
                &manifest.path,
                None,
                "规范包清单在锁内读取后发生变化，已取消打包",
            ));
        }
    }
    if let Some((target, artifact)) = manifest.native.as_ref().and_then(|native| {
        native.artifacts.iter().find(|(_, artifact)| {
            normalize_pack_relative_path(Path::new(&artifact.path)).is_some_and(|artifact_path| {
                portable_package_path(&artifact_path).is_ok_and(|artifact_path| {
                    portable_package_path(relative).is_ok_and(|relative| artifact_path == relative)
                })
            })
        })
    }) {
        let actual_size = bytes.len() as u64;
        let actual_checksum = format!("{:x}", Sha256::digest(bytes));
        if actual_size != artifact.size || actual_checksum != artifact.checksum {
            return Err(native_artifact_mismatch(
                &manifest.root.join(&artifact.path),
                target,
                artifact,
                actual_size,
                &actual_checksum,
            ));
        }
    }
    Ok(())
}

fn validated_yxp_archive_path(
    relative: &Path,
    source: &Path,
    max_bytes: usize,
) -> Result<PathBuf, ManifestError> {
    let portable_relative = portable_package_path(relative)
        .map_err(|error| package_path_manifest_error(source, error))?;
    let archive_path = Path::new("package").join(portable_relative);
    validate_archive_relative_path(&archive_path, max_bytes)
        .map_err(|message| manifest_error(source, None, message))?;
    Ok(archive_path)
}

fn validate_package_file(
    manifest: &Manifest,
    files: &[PathBuf],
    kind: &str,
    path: &Path,
) -> Result<(), ManifestError> {
    let normalized = normalize_pack_relative_path(path).ok_or_else(|| {
        manifest_error(
            &manifest.path,
            None,
            format!("{kind}“{}”不是规范的包内路径", path.display()),
        )
    })?;
    let expected = portable_package_path(&normalized)
        .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
    let found = files
        .iter()
        .any(|file| portable_package_path(file).is_ok_and(|candidate| candidate == expected));
    if !found {
        return Err(manifest_error(
            &manifest.path,
            None,
            format!(
                "{kind}“{}”不存在、不是普通文件或未进入包内容",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn normalize_pack_relative_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => normalized.push(component),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn validate_package_manifest_path(
    manifest: &Manifest,
    kind: &str,
    path: &Path,
) -> Result<(), ManifestError> {
    match package_path_decision(path, PackagePathPurpose::ManifestReference) {
        Ok(PackagePathDecision::Include) => Ok(()),
        Ok(PackagePathDecision::Exclude(_)) => {
            unreachable!("manifest references reject reserved paths")
        }
        Err(mut error) => {
            error.message = format!("{kind}无效：{}", error.message);
            Err(package_path_manifest_error(&manifest.path, error))
        }
    }
}

fn validate_pack_output(
    root: &Path,
    output: &Path,
    limits: ArchiveLimits,
) -> Result<Option<PathBuf>, ManifestError> {
    if output.as_os_str().is_empty() {
        return Err(manifest_error(output, None, "打包输出路径不得为空"));
    }
    let output_absolute = absolute_normalized(output)?;
    let output_exists = match fs::symlink_metadata(&output_absolute) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
        Ok(_) => {
            return Err(manifest_error(
                output,
                None,
                "打包输出已存在时必须是普通文件，不得为目录、符号链接或特殊文件",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(manifest_error(
                output,
                None,
                format!("不能检查打包输出类型：{error}"),
            ));
        }
    };

    let canonical_root = fs::canonicalize(root).map_err(|error| {
        manifest_error(
            root,
            None,
            format!("不能定位包根目录以校验打包输出：{error}"),
        )
    })?;
    let resolved_output = match fs::canonicalize(&output_absolute) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            resolve_output_parent(&output_absolute, output)?
        }
        Err(error) => {
            return Err(manifest_error(
                output,
                None,
                format!("不能定位打包输出：{error}"),
            ));
        }
    };
    validate_pack_output_location(
        &canonical_root,
        &resolved_output,
        output,
        output_exists,
        limits,
    )
}

fn validate_pack_output_location(
    root: &Path,
    output: &Path,
    display: &Path,
    output_exists: bool,
    limits: ArchiveLimits,
) -> Result<Option<PathBuf>, ManifestError> {
    let Ok(relative) = output.strip_prefix(root) else {
        return Ok(None);
    };
    if relative.as_os_str().is_empty() {
        return Err(manifest_error(display, None, "打包输出不能覆盖包根目录"));
    }
    let output_decision = package_path_decision(relative, PackagePathPurpose::YxpEntry)
        .map_err(|error| package_path_manifest_error(display, error))?;
    let generated_output = matches!(
        output_decision,
        PackagePathDecision::Exclude(PackagePathReason::ReservedComponent { ref component })
            if matches!(component.as_str(), ".yanxu" | "target" | "build" | "vendor")
    );
    if output_exists && !generated_output {
        validate_existing_package_archive(output, limits).map_err(|error| {
            let message = if error.code() == "PACKAGE000" {
                format!("源树内既有输出不是可安全替换的 YXP：{}", error.message)
            } else {
                format!(
                    "[{}] 源树内既有输出不是可安全替换的 YXP：{}",
                    error.code(),
                    error.diagnostic_message()
                )
            };
            manifest_error(display, error.line, message)
        })?;
    }
    Ok(Some(relative.to_path_buf()))
}

fn validate_pack_output_conflicts(
    manifest: &Manifest,
    relative: Option<&Path>,
) -> Result<(), ManifestError> {
    let Some(relative) = relative else {
        return Ok(());
    };
    let output_identity = portable_pack_path_identity(relative)
        .map_err(|error| package_path_manifest_error(relative, error))?;
    let mut protected = vec![
        ("包清单".to_owned(), PathBuf::from(MANIFEST_NAME)),
        ("锁文件".to_owned(), PathBuf::from(LOCK_NAME)),
        ("入口".to_owned(), manifest.entry.clone()),
    ];
    protected.extend(
        manifest
            .exports
            .iter()
            .map(|(name, path)| (format!("导出“{name}”"), path.clone())),
    );
    if let Some(icon) = manifest
        .application
        .as_ref()
        .and_then(|application| application.icon.as_ref())
    {
        protected.push(("应用图标".into(), icon.clone()));
    }
    if let Some(native) = &manifest.native {
        protected.extend(native.artifacts.iter().map(|(target, artifact)| {
            (format!("原生制品 {target}"), PathBuf::from(&artifact.path))
        }));
    }
    for (kind, path) in protected {
        let protected_identity = portable_pack_path_identity(&path)
            .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
        if protected_identity == output_identity {
            return Err(manifest_error(
                &manifest.path,
                None,
                format!("打包输出会覆盖{kind}“{}”", path.display()),
            ));
        }
    }
    for (kind, paths) in [
        ("资源目录", &manifest.resources),
        ("工作区成员", &manifest.workspace_members),
    ] {
        for path in paths {
            let protected_identity = portable_pack_path_identity(path)
                .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
            if output_identity.starts_with(&protected_identity) {
                return Err(manifest_error(
                    &manifest.path,
                    None,
                    format!("打包输出位于{kind}“{}”内", path.display()),
                ));
            }
        }
    }
    Ok(())
}

fn portable_pack_path_identity(path: &Path) -> Result<Vec<String>, PackagePathError> {
    if path
        .components()
        .all(|component| component == Component::CurDir)
    {
        return Ok(Vec::new());
    }
    portable_package_path(path).map(|path| path.split('/').map(portable_case_fold).collect())
}

fn absolute_normalized(path: &Path) -> Result<PathBuf, ManifestError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| manifest_error(path, None, format!("不能定位当前目录：{error}")))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    let mut normal_depth = 0_usize;
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normal_depth > 0 {
                    normalized.pop();
                    normal_depth -= 1;
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                normalized.push(component.as_os_str());
                normal_depth = 0;
            }
            Component::Normal(_) => {
                normalized.push(component.as_os_str());
                normal_depth += 1;
            }
        }
    }
    Ok(normalized)
}

fn resolve_output_parent(absolute: &Path, display: &Path) -> Result<PathBuf, ManifestError> {
    let file_name = absolute
        .file_name()
        .ok_or_else(|| manifest_error(display, None, "打包输出必须包含普通文件名"))?;
    let mut cursor = absolute
        .parent()
        .ok_or_else(|| manifest_error(display, None, "打包输出缺少父目录"))?;
    let mut missing = Vec::new();
    let mut resolved = loop {
        match fs::canonicalize(cursor) {
            Ok(resolved) => break resolved,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = cursor.file_name().ok_or_else(|| {
                    manifest_error(display, None, format!("不能定位打包输出父目录：{error}"))
                })?;
                missing.push(component.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    manifest_error(display, None, format!("不能定位打包输出父目录：{error}"))
                })?;
            }
            Err(error) => {
                return Err(manifest_error(
                    display,
                    None,
                    format!("不能定位打包输出父目录：{error}"),
                ));
            }
        }
    };
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    resolved.push(file_name);
    Ok(resolved)
}

#[derive(Debug, Clone)]
struct PackageTreeEntry {
    relative: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PackageTreeSnapshot {
    root: PathBuf,
    files: Vec<PackageTreeEntry>,
}

impl PackageTreeSnapshot {
    fn paths(&self) -> Vec<PathBuf> {
        self.files
            .iter()
            .map(|entry| entry.relative.clone())
            .collect()
    }

    fn get(&self, relative: &Path) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|entry| entry.relative == relative)
            .map(|entry| entry.bytes.as_slice())
    }
}

#[derive(Debug, Clone, Copy)]
struct PackageTreeCaptureLimits {
    file_bytes: u64,
    total_bytes: u64,
    files: usize,
    directories: usize,
    scanned_entries: usize,
    depth: usize,
    path_bytes: Option<usize>,
}

impl PackageTreeCaptureLimits {
    fn dependency() -> Self {
        Self {
            file_bytes: PACKAGE_TREE_MAX_FILE_BYTES,
            total_bytes: PACKAGE_TREE_MAX_BYTES,
            files: PACKAGE_TREE_MAX_ENTRIES,
            directories: PACKAGE_TREE_MAX_ENTRIES.saturating_add(1),
            scanned_entries: PACKAGE_TREE_MAX_ENTRIES.saturating_mul(2),
            depth: PACKAGE_TREE_MAX_DEPTH,
            path_bytes: None,
        }
    }

    fn archive(limits: ArchiveLimits) -> Self {
        Self {
            file_bytes: limits.file_bytes,
            total_bytes: limits.expanded_bytes,
            files: limits.entries,
            directories: limits.entries.saturating_add(1),
            scanned_entries: limits.entries.saturating_mul(4).saturating_add(1_024),
            depth: PACKAGE_TREE_MAX_DEPTH,
            path_bytes: Some(limits.path_bytes),
        }
    }
}

fn capture_package_tree(
    root: &Path,
    purpose: PackagePathPurpose,
    limits: PackageTreeCaptureLimits,
    excluded: Option<&Path>,
) -> Result<PackageTreeSnapshot, ManifestError> {
    let mut roots = TrustedPackageRoots::default();
    roots
        .insert(root)
        .map_err(|error| package_path_manifest_error(root, error))?;
    capture_package_tree_in(&roots, root, purpose, limits, excluded)
}

fn capture_package_tree_in(
    roots: &TrustedPackageRoots,
    root: &Path,
    purpose: PackagePathPurpose,
    limits: PackageTreeCaptureLimits,
    excluded: Option<&Path>,
) -> Result<PackageTreeSnapshot, ManifestError> {
    let canonical_root = roots
        .exact_root_identity(root)
        .ok_or_else(|| manifest_error(root, None, "包根不属于已打开的可信根集合"))?
        .to_path_buf();
    let mut snapshot = PackageTreeSnapshot {
        root: canonical_root.clone(),
        files: Vec::new(),
    };
    let mut portable_paths = PortablePackagePaths::default();
    let mut total_bytes = 0_u64;
    let mut directory_count = 1_usize;
    let mut scanned_entries = 0_usize;

    #[cfg(not(target_os = "wasi"))]
    {
        let directory = roots
            .clone_exact_root_directory(root)
            .map_err(|error| manifest_error(root, None, format!("不能复制包根句柄：{error}")))?
            .ok_or_else(|| manifest_error(root, None, "包根目录句柄不存在"))?;
        capture_package_directory_capability(
            &directory,
            &canonical_root,
            Path::new(""),
            0,
            purpose,
            limits,
            excluded,
            &mut portable_paths,
            &mut total_bytes,
            &mut directory_count,
            &mut scanned_entries,
            &mut snapshot.files,
        )?;
    }
    #[cfg(target_os = "wasi")]
    {
        let directory = roots
            .clone_exact_root_directory(root)
            .map_err(|error| manifest_error(root, None, format!("不能复制包根句柄：{error}")))?
            .ok_or_else(|| manifest_error(root, None, "包根目录句柄不存在"))?;
        capture_package_directory_wasi(
            &directory,
            &canonical_root,
            Path::new(""),
            0,
            purpose,
            limits,
            excluded,
            &mut portable_paths,
            &mut total_bytes,
            &mut directory_count,
            &mut scanned_entries,
            &mut snapshot.files,
        )?;
    }

    snapshot.files.sort_by(|left, right| {
        let left = portable_package_path(&left.relative).unwrap_or_default();
        let right = portable_package_path(&right.relative).unwrap_or_default();
        left.cmp(&right)
    });
    Ok(snapshot)
}

#[cfg(not(target_os = "wasi"))]
struct CapabilityDirectoryFrame {
    directory: cap_std::fs::Dir,
    relative: PathBuf,
    depth: usize,
    entries: std::vec::IntoIter<PathBuf>,
}

#[cfg(not(target_os = "wasi"))]
fn capability_directory_frame(
    directory: cap_std::fs::Dir,
    canonical_root: &Path,
    relative: PathBuf,
    depth: usize,
    scan_limit: usize,
    scanned_entries: &mut usize,
) -> Result<CapabilityDirectoryFrame, ManifestError> {
    let display_directory = canonical_root.join(&relative);
    let read_dir = directory.entries().map_err(|error| {
        manifest_error(
            &display_directory,
            None,
            format!("不能从稳定目录句柄遍历包：{error}"),
        )
    })?;
    let mut entries = Vec::new();
    for entry in read_dir {
        *scanned_entries = scanned_entries.saturating_add(1);
        if *scanned_entries > scan_limit {
            return Err(manifest_error(
                &display_directory,
                None,
                format!("包目录项不得超过 {scan_limit} 个"),
            ));
        }
        let entry = entry.map_err(|error| {
            manifest_error(
                &display_directory,
                None,
                format!("不能读取包目录项：{error}"),
            )
        })?;
        entries.push(PathBuf::from(entry.file_name()));
    }
    entries.sort();
    Ok(CapabilityDirectoryFrame {
        directory,
        relative,
        depth,
        entries: entries.into_iter(),
    })
}

#[cfg(not(target_os = "wasi"))]
#[allow(clippy::too_many_arguments)]
fn capture_package_directory_capability(
    directory: &cap_std::fs::Dir,
    canonical_root: &Path,
    relative_directory: &Path,
    depth: usize,
    purpose: PackagePathPurpose,
    limits: PackageTreeCaptureLimits,
    excluded: Option<&Path>,
    portable_paths: &mut PortablePackagePaths,
    total_bytes: &mut u64,
    directory_count: &mut usize,
    scanned_entries: &mut usize,
    files: &mut Vec<PackageTreeEntry>,
) -> Result<(), ManifestError> {
    let scan_limit = limits.scanned_entries;
    let root = directory.try_clone().map_err(|error| {
        manifest_error(canonical_root, None, format!("不能复制包目录句柄：{error}"))
    })?;
    let mut pending = vec![capability_directory_frame(
        root,
        canonical_root,
        relative_directory.to_path_buf(),
        depth,
        scan_limit,
        scanned_entries,
    )?];

    loop {
        let (name, relative_directory, depth) = loop {
            let Some(frame) = pending.last_mut() else {
                return Ok(());
            };
            if let Some(name) = frame.entries.next() {
                break (name, frame.relative.clone(), frame.depth);
            }
            pending.pop();
        };
        let directory = &pending
            .last()
            .expect("an entry always belongs to the current directory frame")
            .directory;
        let relative = relative_directory.join(&name);
        let display = canonical_root.join(&relative);
        match package_path_decision(&relative, purpose)
            .map_err(|error| package_path_manifest_error(&display, error))?
        {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => continue,
        }
        let metadata = directory.symlink_metadata(&name).map_err(|error| {
            manifest_error(&display, None, format!("不能检查包目录项：{error}"))
        })?;
        let file_type = metadata.file_type();
        if metadata.is_dir() {
            portable_paths
                .insert_directory(&relative)
                .map_err(|error| package_path_manifest_error(&display, error))?;
        } else {
            portable_paths
                .insert(&relative)
                .map_err(|error| package_path_manifest_error(&display, error))?;
        }
        if excluded.is_some_and(|excluded| excluded == relative) {
            continue;
        }
        if file_type.is_symlink() {
            return Err(manifest_error(&display, None, "包不得包含符号链接"));
        }
        if file_type.is_dir() {
            *directory_count = directory_count.saturating_add(1);
            if *directory_count > limits.directories {
                let kind = if purpose == PackagePathPurpose::YxpEntry {
                    "打包目录"
                } else {
                    "包目录"
                };
                return Err(manifest_error(
                    &display,
                    None,
                    format!("{kind}不得超过 {} 个", limits.directories),
                ));
            }
            let child_depth = depth.saturating_add(1);
            if child_depth > limits.depth {
                let kind = if purpose == PackagePathPurpose::YxpEntry {
                    "打包目录深度"
                } else {
                    "包目录深度"
                };
                return Err(manifest_error(
                    &display,
                    None,
                    format!("{kind}不得超过 {} 层", limits.depth),
                ));
            }
            let child = directory.open_dir_nofollow(&name).map_err(|error| {
                manifest_error(&display, None, format!("不能安全打开包目录：{error}"))
            })?;
            let metadata = child.dir_metadata().map_err(|error| {
                manifest_error(&display, None, format!("不能检查已打开的包目录：{error}"))
            })?;
            if !metadata.is_dir() || cap_metadata_is_reparse(&metadata) {
                return Err(manifest_error(
                    &display,
                    None,
                    "包目录必须是真实目录，不得为重解析点或特殊文件",
                ));
            }
            let child = capability_directory_frame(
                child,
                canonical_root,
                relative,
                child_depth,
                scan_limit,
                scanned_entries,
            )?;
            pending.push(child);
            continue;
        }
        if !file_type.is_file() {
            return Err(manifest_error(&display, None, "包不得包含特殊文件"));
        }
        if files.len() >= limits.files {
            let kind = if purpose == PackagePathPurpose::YxpEntry {
                "打包条目"
            } else {
                "包文件"
            };
            return Err(manifest_error(
                &display,
                None,
                format!("{kind}不得超过 {} 个", limits.files),
            ));
        }
        if let Some(path_bytes) = limits.path_bytes {
            validated_yxp_archive_path(&relative, &display, path_bytes)?;
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = directory.open_with(&name, &options).map_err(|error| {
            manifest_error(&display, None, format!("不能安全打开包文件：{error}"))
        })?;
        let metadata = file.metadata().map_err(|error| {
            manifest_error(&display, None, format!("不能检查已打开的包文件：{error}"))
        })?;
        if !metadata.is_file() || cap_metadata_is_reparse(&metadata) {
            return Err(manifest_error(
                &display,
                None,
                "包文件必须是普通文件，不得为重解析点或特殊文件",
            ));
        }
        let bytes = read_opened_regular_file_snapshot(
            file.into_std(),
            &display,
            limits.file_bytes,
            "包内容",
        )?;
        *total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= limits.total_bytes)
            .ok_or_else(|| {
                let kind = if purpose == PackagePathPurpose::YxpEntry {
                    "打包内容"
                } else {
                    "包内容"
                };
                manifest_error(
                    &display,
                    None,
                    format!("{kind}不得超过 {} 字节", limits.total_bytes),
                )
            })?;
        files.push(PackageTreeEntry { relative, bytes });
    }
}

#[cfg(windows)]
fn cap_metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(not(windows), not(target_os = "wasi")))]
fn cap_metadata_is_reparse(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

#[cfg(target_os = "wasi")]
struct WasiDirectoryFrame {
    directory: WasiPackageDirectory,
    relative: PathBuf,
    depth: usize,
    entries: std::vec::IntoIter<WasiPackageDirectoryEntry>,
}

#[cfg(target_os = "wasi")]
fn wasi_directory_frame(
    directory: WasiPackageDirectory,
    canonical_root: &Path,
    relative: PathBuf,
    depth: usize,
    scan_limit: usize,
    scanned_entries: &mut usize,
) -> Result<WasiDirectoryFrame, ManifestError> {
    let display_directory = canonical_root.join(&relative);
    let entries = directory
        .entries(scan_limit.saturating_add(1))
        .map_err(|error| {
            if error.to_string().starts_with("包目录项不得超过 ") {
                manifest_error(
                    &display_directory,
                    None,
                    format!("包目录项不得超过 {scan_limit} 个"),
                )
            } else {
                manifest_error(
                    &display_directory,
                    None,
                    format!("不能从稳定目录句柄遍历包：{error}"),
                )
            }
        })?;
    *scanned_entries = scanned_entries.saturating_add(entries.len());
    if *scanned_entries > scan_limit {
        return Err(manifest_error(
            &display_directory,
            None,
            format!("包目录项不得超过 {scan_limit} 个"),
        ));
    }
    Ok(WasiDirectoryFrame {
        directory,
        relative,
        depth,
        entries: entries.into_iter(),
    })
}

#[cfg(target_os = "wasi")]
#[allow(clippy::too_many_arguments)]
fn capture_package_directory_wasi(
    directory: &WasiPackageDirectory,
    canonical_root: &Path,
    relative_directory: &Path,
    depth: usize,
    purpose: PackagePathPurpose,
    limits: PackageTreeCaptureLimits,
    excluded: Option<&Path>,
    portable_paths: &mut PortablePackagePaths,
    total_bytes: &mut u64,
    directory_count: &mut usize,
    scanned_entries: &mut usize,
    files: &mut Vec<PackageTreeEntry>,
) -> Result<(), ManifestError> {
    let scan_limit = limits.scanned_entries;
    let root = directory.try_clone().map_err(|error| {
        manifest_error(canonical_root, None, format!("不能复制包目录句柄：{error}"))
    })?;
    let mut pending = vec![wasi_directory_frame(
        root,
        canonical_root,
        relative_directory.to_path_buf(),
        depth,
        scan_limit,
        scanned_entries,
    )?];

    loop {
        let (entry, relative_directory, depth) = loop {
            let Some(frame) = pending.last_mut() else {
                return Ok(());
            };
            if let Some(entry) = frame.entries.next() {
                break (entry, frame.relative.clone(), frame.depth);
            }
            pending.pop();
        };
        let directory = &pending
            .last()
            .expect("an entry always belongs to the current directory frame")
            .directory;
        let relative = relative_directory.join(entry.name());
        let display = canonical_root.join(&relative);
        match package_path_decision(&relative, purpose)
            .map_err(|error| package_path_manifest_error(&display, error))?
        {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => continue,
        }
        match directory.open_entry_nofollow(&entry).map_err(|error| {
            manifest_error(
                &display,
                None,
                format!("不能从稳定目录句柄安全打开包目录项：{error}"),
            )
        })? {
            WasiPackageEntry::Directory(child) => {
                portable_paths
                    .insert_directory(&relative)
                    .map_err(|error| package_path_manifest_error(&display, error))?;
                if excluded.is_some_and(|excluded| excluded == relative) {
                    continue;
                }
                *directory_count = directory_count.saturating_add(1);
                if *directory_count > limits.directories {
                    let kind = if purpose == PackagePathPurpose::YxpEntry {
                        "打包目录"
                    } else {
                        "包目录"
                    };
                    return Err(manifest_error(
                        &display,
                        None,
                        format!("{kind}不得超过 {} 个", limits.directories),
                    ));
                }
                let child_depth = depth.saturating_add(1);
                if child_depth > limits.depth {
                    let kind = if purpose == PackagePathPurpose::YxpEntry {
                        "打包目录深度"
                    } else {
                        "包目录深度"
                    };
                    return Err(manifest_error(
                        &display,
                        None,
                        format!("{kind}不得超过 {} 层", limits.depth),
                    ));
                }
                pending.push(wasi_directory_frame(
                    child,
                    canonical_root,
                    relative,
                    child_depth,
                    scan_limit,
                    scanned_entries,
                )?);
            }
            WasiPackageEntry::File(file) => {
                portable_paths
                    .insert(&relative)
                    .map_err(|error| package_path_manifest_error(&display, error))?;
                if excluded.is_some_and(|excluded| excluded == relative) {
                    continue;
                }
                if files.len() >= limits.files {
                    let kind = if purpose == PackagePathPurpose::YxpEntry {
                        "打包条目"
                    } else {
                        "包文件"
                    };
                    return Err(manifest_error(
                        &display,
                        None,
                        format!("{kind}不得超过 {} 个", limits.files),
                    ));
                }
                if let Some(path_bytes) = limits.path_bytes {
                    validated_yxp_archive_path(&relative, &display, path_bytes)?;
                }
                let bytes =
                    read_opened_regular_file_snapshot(file, &display, limits.file_bytes, "包内容")?;
                *total_bytes = total_bytes
                    .checked_add(bytes.len() as u64)
                    .filter(|total| *total <= limits.total_bytes)
                    .ok_or_else(|| {
                        let kind = if purpose == PackagePathPurpose::YxpEntry {
                            "打包内容"
                        } else {
                            "包内容"
                        };
                        manifest_error(
                            &display,
                            None,
                            format!("{kind}不得超过 {} 字节", limits.total_bytes),
                        )
                    })?;
                files.push(PackageTreeEntry { relative, bytes });
            }
        }
    }
}

/// 把完整锁定图复制到项目内目录；解析器会自动优先使用祖先目录中的辖制清单。
pub fn vendor_dependencies(
    graph: &ResolutionGraph,
    destination: impl AsRef<Path>,
) -> Result<VendorManifest, ManifestError> {
    let destination = destination.as_ref();
    if destination.exists() {
        fs::remove_dir_all(destination).map_err(|error| {
            manifest_error(destination, None, format!("不能清理旧辖制目录：{error}"))
        })?;
    }
    fs::create_dir_all(destination)
        .map_err(|error| manifest_error(destination, None, format!("不能创建辖制目录：{error}")))?;
    let mut packages = BTreeMap::new();
    for (id, dependency) in &graph.packages {
        let directory = format!("{}-{}", dependency.locked.name, &short_hash(id)[..12]);
        let target = destination.join(&directory);
        copy_package_tree(&dependency.root, &target)?;
        let checksum = tree_checksum(&target)?;
        if checksum != dependency.locked.checksum {
            return Err(manifest_error(
                &target,
                None,
                format!(
                    "辖制包校验不符：锁定 {}，复制后 {checksum}",
                    dependency.locked.checksum
                ),
            ));
        }
        packages.insert(
            id.clone(),
            VendorPackage {
                path: directory,
                checksum,
                source: dependency.locked.source.clone(),
                revision: dependency.locked.revision.clone(),
            },
        );
    }
    let vendor = VendorManifest {
        format_version: 1,
        target: graph.target.clone(),
        packages,
    };
    let manifest_path = destination.join("言序-vendor.json");
    let document = serde_json::to_vec_pretty(&vendor).map_err(|error| {
        manifest_error(&manifest_path, None, format!("不能生成辖制清单：{error}"))
    })?;
    atomic_write(&manifest_path, &document, "辖制清单")?;
    Ok(vendor)
}

fn find_vendored_package(
    start: &Path,
    locked: &LockedPackage,
) -> Result<Option<PathBuf>, ManifestError> {
    for ancestor in start.ancestors() {
        for vendor_root in [ancestor.join("vendor"), ancestor.to_path_buf()] {
            let manifest_path = vendor_root.join("言序-vendor.json");
            if !manifest_path.is_file() {
                continue;
            }
            let bytes = fs::read(&manifest_path).map_err(|error| {
                manifest_error(&manifest_path, None, format!("不能读取辖制清单：{error}"))
            })?;
            let vendor: VendorManifest = serde_json::from_slice(&bytes).map_err(|error| {
                manifest_error(&manifest_path, None, format!("辖制清单无效：{error}"))
            })?;
            if vendor.format_version != 1 || vendor.target != current_target() {
                return Err(manifest_error(
                    &manifest_path,
                    None,
                    "辖制清单格式或目标平台与当前运行时不兼容",
                ));
            }
            let Some(package) = vendor.packages.get(&locked.id) else {
                continue;
            };
            if package.checksum != locked.checksum
                || package.source != locked.source
                || package.revision != locked.revision
            {
                return Err(manifest_error(
                    &manifest_path,
                    None,
                    "辖制包身份与锁文件不符",
                ));
            }
            let root = vendor_root.join(&package.path);
            let canonical_vendor = fs::canonicalize(&vendor_root).map_err(|error| {
                manifest_error(&vendor_root, None, format!("不能定位辖制目录：{error}"))
            })?;
            let canonical = fs::canonicalize(&root)
                .map_err(|error| manifest_error(&root, None, format!("不能定位辖制包：{error}")))?;
            if !canonical.starts_with(&canonical_vendor)
                || !tree_checksum_matches(&canonical, &locked.checksum)?
            {
                return Err(manifest_error(&root, None, "辖制包越界或内容校验不符"));
            }
            return Ok(Some(canonical));
        }
    }
    Ok(None)
}

fn copy_package_tree(source: &Path, destination: &Path) -> Result<(), ManifestError> {
    let mut files = Vec::new();
    collect_files(source, source, &mut files)?;
    files.sort();
    for relative in files {
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                manifest_error(parent, None, format!("不能创建辖制目录：{error}"))
            })?;
        }
        fs::copy(source.join(&relative), &target)
            .map_err(|error| manifest_error(&target, None, format!("不能复制辖制包：{error}")))?;
    }
    Ok(())
}

pub fn validate_package_name(name: &str) -> Result<(), String> {
    let normalized = name.nfc().collect::<String>();
    if normalized != name {
        return Err(format!(
            "[{PACKAGE_PATH_NON_PORTABLE_CODE}] 包名“{name}”必须使用 Unicode NFC 规范拼写；请改用“{normalized}”。"
        ));
    }
    if name.is_empty()
        || name.starts_with(['.', '-'])
        || name
            .chars()
            .any(|character| !(character.is_alphanumeric() || matches!(character, '_' | '-' | '.')))
    {
        Err(format!("包名“{name}”不规范；仅可用文字、数字、_、-、."))
    } else {
        crate::path_policy::validate_portable_component(Path::new(name), name)
            .map_err(|error| error.to_string())?;
        let _ = portable_package_path(Path::new(name)).map_err(|error| error.to_string())?;
        Ok(())
    }
}

pub fn validate_entry(entry: &Path) -> Result<(), String> {
    if entry.is_absolute()
        || entry
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        || entry.extension().and_then(|extension| extension.to_str()) != Some("yx")
    {
        Err(format!("入口“{}”须为包内相对 .yx 文卷", entry.display()))
    } else {
        Ok(())
    }
}

fn tree_checksum(root: &Path) -> Result<String, ManifestError> {
    let snapshot = capture_package_tree(
        root,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )?;
    portable_tree_snapshot_checksum(&snapshot)
}

fn portable_tree_snapshot_checksum(
    snapshot: &PackageTreeSnapshot,
) -> Result<String, ManifestError> {
    let mut digest = Sha256::new();
    for entry in &snapshot.files {
        let portable = portable_package_path(&entry.relative).map_err(|error| {
            package_path_manifest_error(snapshot.root.join(&entry.relative), error)
        })?;
        digest.update(portable.as_bytes());
        digest.update([0]);
        digest.update((entry.bytes.len() as u64).to_le_bytes());
        digest.update(&entry.bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn tree_checksum_matches(root: &Path, expected: &str) -> Result<bool, ManifestError> {
    let snapshot = capture_package_tree(
        root,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )?;
    tree_snapshot_checksum_matches(&snapshot, expected)
}

fn tree_snapshot_checksum_matches(
    snapshot: &PackageTreeSnapshot,
    expected: &str,
) -> Result<bool, ManifestError> {
    if portable_tree_snapshot_checksum(snapshot)? == expected {
        return Ok(true);
    }
    for separator in ["/", "\\"] {
        if legacy_tree_snapshot_checksum(snapshot, separator) == expected {
            return Ok(true);
        }
        if legacy_normalized_tree_snapshot_checksum(snapshot, separator, false) == expected
            || legacy_normalized_tree_snapshot_checksum(snapshot, separator, true) == expected
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn legacy_tree_snapshot_checksum(snapshot: &PackageTreeSnapshot, separator: &str) -> String {
    let mut files = snapshot.files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    let mut digest = Sha256::new();
    for entry in files {
        let legacy = entry
            .relative
            .iter()
            .map(|component| component.to_string_lossy())
            .collect::<Vec<_>>()
            .join(separator);
        digest.update(legacy.as_bytes());
        digest.update([0]);
        digest.update((entry.bytes.len() as u64).to_le_bytes());
        digest.update(&entry.bytes);
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
fn legacy_tree_checksum(root: &Path, separator: &str) -> Result<String, ManifestError> {
    let snapshot = capture_package_tree(
        root,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )?;
    Ok(legacy_tree_snapshot_checksum(&snapshot, separator))
}

fn legacy_normalized_tree_snapshot_checksum(
    snapshot: &PackageTreeSnapshot,
    separator: &str,
    decomposed: bool,
) -> String {
    let mut keyed = snapshot
        .files
        .iter()
        .map(|entry| {
            let path = entry
                .relative
                .iter()
                .map(|component| component.to_string_lossy())
                .collect::<Vec<_>>()
                .join(separator);
            let key = if decomposed {
                path.nfd().collect::<String>()
            } else {
                path.nfc().collect::<String>()
            };
            (key, entry)
        })
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    for (key, entry) in keyed {
        digest.update(key.as_bytes());
        digest.update([0]);
        digest.update((entry.bytes.len() as u64).to_le_bytes());
        digest.update(&entry.bytes);
    }
    format!("{:x}", digest.finalize())
}

fn sort_portable_paths(paths: &mut Vec<PathBuf>) -> Result<(), ManifestError> {
    let mut keyed = Vec::with_capacity(paths.len());
    for path in std::mem::take(paths) {
        let key = portable_package_path(&path)
            .map_err(|error| package_path_manifest_error(&path, error))?;
        keyed.push((key, path));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    paths.extend(keyed.into_iter().map(|(_, path)| path));
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ManifestError> {
    let mut portable_paths = PortablePackagePaths::default();
    collect_files_with_paths(root, directory, files, &mut portable_paths)
}

fn collect_files_with_paths(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    portable_paths: &mut PortablePackagePaths,
) -> Result<(), ManifestError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能遍历依赖：{error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| manifest_error(directory, None, format!("不能读取目录项：{error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).expect("walk remains under root");
        match package_path_decision(relative, PackagePathPurpose::TreeChecksum)
            .map_err(|error| package_path_manifest_error(&path, error))?
        {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => continue,
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| manifest_error(&path, None, error.to_string()))?;
        if metadata.is_dir() {
            portable_paths
                .insert_directory(relative)
                .map_err(|error| package_path_manifest_error(&path, error))?;
        } else {
            portable_paths
                .insert(relative)
                .map_err(|error| package_path_manifest_error(&path, error))?;
        }
        if metadata.file_type().is_symlink() {
            return Err(manifest_error(&path, None, "依赖包不得包含符号链接"));
        }
        if metadata.is_dir() {
            collect_files_with_paths(root, &path, files, portable_paths)?;
        } else if metadata.is_file() {
            files.push(relative.into());
        } else {
            return Err(manifest_error(&path, None, "依赖包不得包含特殊文件"));
        }
    }
    Ok(())
}

fn file_checksum(path: &Path) -> Result<String, ManifestError> {
    let bytes = fs::read(path)
        .map_err(|error| manifest_error(path, None, format!("不能校验清单：{error}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn short_hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))[..24].into()
}

fn cache_root() -> PathBuf {
    if let Some(root) = std::env::var_os("YANXU_CACHE") {
        return PathBuf::from(root);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".yanxu")
        .join("缓存")
}

fn download(url: &str, destination: &Path) -> Result<(), ManifestError> {
    validate_artifact_source_security(url)
        .map_err(|message| manifest_error(destination, None, message))?;
    if !secure_https_source(url) {
        return Err(manifest_error(
            destination,
            None,
            "远程下载来源须使用 HTTPS",
        ));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| manifest_error(destination, None, format!("不能创建下载目录：{error}")))?;
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "registry-download".into());
    let temporary = parent.join(format!(
        ".{file_name}.download-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        run_command(
            Command::new("curl")
                .arg("--proto")
                .arg("=https")
                .arg("--proto-redir")
                .arg("=https")
                .arg("--tlsv1.2")
                .arg("--fail")
                .arg("--silent")
                .arg("--show-error")
                .arg("--location")
                .arg("--max-time")
                .arg("30")
                .arg("--max-filesize")
                .arg(ARCHIVE_MAX_COMPRESSED_BYTES.to_string())
                .arg("--output")
                .arg(&temporary)
                .arg(url),
            destination,
            "下载索引资源",
        )?;
        let bytes = fs::read(&temporary).map_err(|error| {
            manifest_error(destination, None, format!("不能读取下载结果：{error}"))
        })?;
        crate::storage::atomic_write(destination, &bytes).map_err(|error| {
            manifest_error(destination, None, format!("不能原子保存下载结果：{error}"))
        })
    })();
    fs::remove_file(temporary).ok();
    result
}

fn copy_registry_tree_with_checkpoint(
    source: &Path,
    destination: &Path,
    checkpoint: &mut impl FnMut(RegistryInstallCheckpoint, &Path) -> Result<(), ManifestError>,
) -> Result<(), ManifestError> {
    fs::create_dir_all(destination)
        .map_err(|error| manifest_error(destination, None, format!("不能创建缓存目录：{error}")))?;
    for entry in fs::read_dir(source)
        .map_err(|error| manifest_error(source, None, format!("不能读取展开制品：{error}")))?
    {
        let entry = entry
            .map_err(|error| manifest_error(source, None, format!("不能读取制品项：{error}")))?;
        let destination = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            manifest_error(entry.path(), None, format!("不能检查制品项类型：{error}"))
        })?;
        checkpoint(RegistryInstallCheckpoint::BeforeCopyEntry, &entry.path())?;
        if file_type.is_dir() {
            copy_registry_tree_with_checkpoint(&entry.path(), &destination, checkpoint)?;
        } else if file_type.is_file() {
            let mut source = OpenOptions::new()
                .read(true)
                .open(entry.path())
                .map_err(|error| {
                    manifest_error(entry.path(), None, format!("不能读取制品缓存源：{error}"))
                })?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|error| {
                    manifest_error(&destination, None, format!("不能创建制品缓存：{error}"))
                })?;
            io::copy(&mut source, &mut output).map_err(|error| {
                manifest_error(&destination, None, format!("不能写入制品缓存：{error}"))
            })?;
            output.sync_all().map_err(|error| {
                manifest_error(&destination, None, format!("不能同步制品缓存：{error}"))
            })?;
        } else {
            return Err(manifest_error(entry.path(), None, "制品含特殊文件"));
        }
    }
    #[cfg(unix)]
    fs::File::open(destination)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            manifest_error(destination, None, format!("不能同步制品缓存目录：{error}"))
        })?;
    Ok(())
}

fn run_command(command: &mut Command, path: &Path, action: &str) -> Result<(), ManifestError> {
    let output = command
        .output()
        .map_err(|_| manifest_error(path, None, format!("{action}失败：不能启动外部命令")))?;
    if output.status.success() {
        Ok(())
    } else if let Some(code) = output.status.code() {
        Err(manifest_error(
            path,
            None,
            format!("{action}失败（退出码 {code}）"),
        ))
    } else {
        Err(manifest_error(
            path,
            None,
            format!("{action}失败（进程异常终止）"),
        ))
    }
}

fn table_alias<'a>(
    value: &'a toml::Value,
    names: &[&str],
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    names.iter().find_map(|name| value.get(*name)?.as_table())
}

fn string_alias<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    names: &[&str],
) -> Option<&'a str> {
    names.iter().find_map(|name| table.get(*name)?.as_str())
}

fn array_alias<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    names: &[&str],
) -> Option<Vec<&'a str>> {
    names.iter().find_map(|name| {
        table.get(*name)?.as_array().map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
        })
    })
}

fn bool_alias(table: &toml::map::Map<String, toml::Value>, names: &[&str]) -> Option<bool> {
    names.iter().find_map(|name| table.get(*name)?.as_bool())
}

fn integer_alias(table: &toml::map::Map<String, toml::Value>, names: &[&str]) -> Option<i64> {
    names
        .iter()
        .find_map(|name| table.get(*name).and_then(toml::Value::as_integer))
}

fn manifest_error(
    path: impl AsRef<Path>,
    line: Option<usize>,
    message: impl Into<String>,
) -> ManifestError {
    ManifestError {
        message: message.into(),
        path: path.as_ref().to_path_buf(),
        line,
    }
}

fn package_path_manifest_error(
    path: impl AsRef<Path>,
    error: crate::path_policy::PackagePathError,
) -> ManifestError {
    ManifestError {
        message: format!("[{}] {}", error.code, error.diagnostic_message()),
        path: path.as_ref().to_path_buf(),
        line: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        #[cfg(not(target_os = "wasi"))]
        let base = std::env::temp_dir();
        #[cfg(target_os = "wasi")]
        let base = PathBuf::from("/tmp");
        base.join(format!("yanxu-{name}-{unique}"))
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn lock_with_source(source: impl Into<String>) -> LockFile {
        LockFile {
            lock_version: LOCK_FORMAT_VERSION,
            manifest_checksum: "0".repeat(64),
            target: current_target(),
            generator: package_core_version(),
            root_dependencies: BTreeMap::from([("fixture".into(), "fixture@1.0.0".into())]),
            root_dev_dependencies: BTreeMap::new(),
            packages: vec![LockedPackage {
                id: "fixture@1.0.0".into(),
                name: "fixture".into(),
                version: "1.0.0".into(),
                source: source.into(),
                revision: Some("0".repeat(40)),
                checksum: "0".repeat(64),
                entry: "main.yx".into(),
                dependencies: BTreeMap::new(),
                exports: BTreeMap::new(),
                target: current_target(),
                native: None,
                minimum_yanxu: None,
            }],
        }
    }

    fn write_native_package(root: &Path, name: &str) {
        let bytes = b"native permission fixture";
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("backend.bin"), bytes).unwrap();
        fs::write(root.join("主.yx"), "公 定 ABI：数 为 2；\n").unwrap();
        let checksum = format!("{:x}", Sha256::digest(bytes));
        let target = current_target();
        let architecture = std::env::consts::ARCH;
        let os = if target == format!("{architecture}-pc-windows-msvc") {
            "windows"
        } else if target == format!("{architecture}-apple-darwin") {
            "macos"
        } else if target == format!("{architecture}-unknown-linux-gnu") {
            "linux"
        } else {
            target
                .strip_prefix(&format!("{architecture}-"))
                .expect("current target starts with the architecture")
        };
        write(
            &root.join(MANIFEST_NAME),
            &format!(
                "[包]\n格式=2\n名称={name:?}\n版本='1.0.0'\n入口='主.yx'\n[导出]\n默认='主.yx'\n[原生]\nABI=2\n[原生.{os}.{architecture}]\n文件='backend.bin'\n校验和='{checksum}'\n大小={}\n",
                bytes.len()
            ),
        );
        assert_eq!(
            load(root.join(MANIFEST_NAME))
                .unwrap()
                .native
                .unwrap()
                .artifacts
                .keys()
                .next()
                .unwrap(),
            &target
        );
    }

    #[test]
    fn format_diagnostics_report_the_running_package_version() {
        let unsupported_build = parse(
            "[包]\n格式=2\n名称='示例'\n版本='1.0.0'\n入口='主.yx'\n[构建]\n目标='原生'\n",
            PathBuf::from(MANIFEST_NAME),
            PathBuf::from("."),
        )
        .unwrap_err();
        assert!(
            unsupported_build
                .message
                .contains(&format!("言序 {}", env!("CARGO_PKG_VERSION")))
        );

        let unsupported_abi = parse(
            "[包]\n格式=2\n名称='示例'\n版本='1.0.0'\n入口='主.yx'\n[原生]\nABI=3\n",
            PathBuf::from(MANIFEST_NAME),
            PathBuf::from("."),
        )
        .unwrap_err();
        assert!(
            unsupported_abi
                .message
                .contains(&format!("言序 {}", env!("CARGO_PKG_VERSION")))
        );
    }

    #[test]
    fn malformed_manifest_toml_diagnostics_never_echo_sensitive_source_lines() {
        let package = "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\n";
        let cases = [
            (
                "userinfo",
                "userinfo-value-must-not-appear",
                format!(
                    "{package}fixture = {{ git = https://user:userinfo-value-must-not-appear@example.invalid/package.git }}\n"
                ),
            ),
            (
                "query",
                "query-value-must-not-appear",
                format!(
                    "{package}fixture = {{ git = \"https://example.invalid/package.git?access_token=query-value-must-not-appear\" invalid = true }}\n"
                ),
            ),
            (
                "fragment",
                "fragment-value-must-not-appear",
                format!(
                    "{package}fixture = {{ git = \"https://example.invalid/package.git#fragment-value-must-not-appear\", revision = }}\n"
                ),
            ),
        ];

        for (name, marker, contents) in cases {
            let root = temp(&format!("malformed-sensitive-{name}"));
            let manifest_path = root.join(MANIFEST_NAME);
            write(&manifest_path, &contents);
            let error = load(&manifest_path).unwrap_err();
            assert_eq!(error.message, MANIFEST_TOML_SYNTAX_ERROR);
            assert!(error.line.is_some());
            let diagnostic = error.to_string();
            assert!(!diagnostic.contains(marker), "{diagnostic}");
            assert!(!diagnostic.contains("https://"), "{diagnostic}");
            assert!(!diagnostic.contains("access_token"), "{diagnostic}");
            assert!(!diagnostic.contains("fragment-value"), "{diagnostic}");
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn discovers_relative_projects_with_absolute_manifest_identity() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let relative_root = PathBuf::from(format!(".yanxu-relative-discovery-{unique}"));
        write(
            &relative_root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='相对工程'\n版本='1.0.0'\n入口='src/主.yx'\n",
        );
        write(&relative_root.join("src/主.yx"), "言「相对工程」；\n");

        let manifest = discover(relative_root.join("src/主.yx")).unwrap().unwrap();
        assert!(manifest.root.is_absolute());
        assert!(manifest.path.is_absolute());
        assert_eq!(
            manifest.root,
            std::env::current_dir().unwrap().join(&relative_root)
        );
        fs::remove_dir_all(relative_root).unwrap();
    }

    #[test]
    fn discovers_the_deepest_unicode_equivalent_nested_project() {
        let root = temp("unicode-nested-discovery");
        let nested = root.join("packages/é");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='外层'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言「外层」；\n");
        write(
            &nested.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='内层'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&nested.join("主.yx"), "言「内层」；\n");

        let manifest = discover(root.join("packages/e\u{301}")).unwrap().unwrap();
        assert_eq!(manifest.name, "内层");
        assert_eq!(
            fs::canonicalize(&manifest.root).unwrap(),
            fs::canonicalize(&nested).unwrap()
        );
        let case_error = discover(root.join("packages/É")).unwrap_err();
        assert_eq!(case_error.code(), PACKAGE_PATH_NON_PORTABLE_CODE);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn import_resolution_uses_the_discovered_unicode_equivalent_nested_root() {
        let root = temp("unicode-nested-import");
        let nested = root.join("packages/é");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='外层'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言「外层」；\n");
        write(
            &nested.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='内层'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&nested.join("主.yx"), "言「内层」；\n");

        let requested = root.join("packages/e\u{301}/主.yx");
        let mut roots = TrustedPackageRoots::default();
        let (resolved, authority) = roots
            .resolve_import_file(requested.parent().unwrap(), &requested, false)
            .unwrap();
        assert!(authority.is_verified());
        assert_eq!(
            read_resolved_module_source_snapshot(resolved.open().unwrap()).unwrap(),
            "言「内层」；\n"
        );

        fs::remove_dir_all(root).unwrap();
    }

    fn write_archive(path: &Path, files: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, *contents).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }

    fn staged_registry_fixture(
        key: &RegistryPackageKey<'_>,
        declared_name: &str,
        declared_version: &str,
        entry: &str,
        include_entry: bool,
    ) -> Result<StagedRegistryPackage, ManifestError> {
        staged_registry_fixture_with_expected(
            key,
            declared_name,
            declared_version,
            entry,
            include_entry,
            None,
        )
    }

    fn staged_registry_fixture_with_expected(
        key: &RegistryPackageKey<'_>,
        declared_name: &str,
        declared_version: &str,
        entry: &str,
        include_entry: bool,
        expected_tree_checksum: Option<&str>,
    ) -> Result<StagedRegistryPackage, ManifestError> {
        let temporary = RegistryTemporaryDirectory::create_within(
            key.registry_cache,
            &key.registry_cache.join(".staging"),
            "fixture-package",
        )?;
        let archive = temporary.path().join("package.tar.gz");
        let manifest = format!(
            "[包]\n格式=2\n名称='{declared_name}'\n版本='{declared_version}'\n入口='{entry}'\n"
        );
        if include_entry {
            write_archive(
                &archive,
                &[
                    ("package/言序.toml", manifest.as_bytes()),
                    ("package/主.yx", "公 定 值 为 1；\n".as_bytes()),
                ],
            );
        } else {
            write_archive(&archive, &[("package/言序.toml", manifest.as_bytes())]);
        }
        let artifact_checksum = file_checksum(&archive)?;
        prepare_staged_registry_package(
            key,
            temporary,
            &archive,
            &artifact_checksum,
            expected_tree_checksum,
        )
    }

    fn write_special_archive(path: &Path, entry_type: tar::EntryType) {
        let file = fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_mode(0o644);
        if matches!(entry_type, tar::EntryType::Symlink | tar::EntryType::Link) {
            header.set_link_name("target").unwrap();
        }
        header.set_cksum();
        archive
            .append_data(&mut header, "package/special", io::empty())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn safely_extracts_regular_registry_archives() {
        let root = temp("safe-archive");
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("package.tar.gz");
        let destination = root.join("unpacked");
        write_archive(
            &archive,
            &[
                (
                    "package/言序.toml",
                    b"[package]\nname='safe'\nversion='1.0.0'\nentry='main.yx'\n",
                ),
                ("package/main.yx", "言「善哉」；\n".as_bytes()),
            ],
        );
        extract_archive_safely(&archive, &destination).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("package/main.yx")).unwrap(),
            "言「善哉」；\n"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_archive_links_devices_fifos_and_unsafe_paths() {
        let root = temp("special-archive");
        fs::create_dir_all(&root).unwrap();
        for (index, entry_type) in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ]
        .into_iter()
        .enumerate()
        {
            let archive = root.join(format!("special-{index}.tar.gz"));
            write_special_archive(&archive, entry_type);
            let error =
                extract_archive_safely(&archive, &root.join(format!("out-{index}"))).unwrap_err();
            assert!(error.message.contains("特殊条目"));
        }
        assert!(validate_archive_relative_path(Path::new("../escape"), 512).is_err());
        assert!(validate_archive_relative_path(Path::new("/absolute"), 512).is_err());
        assert!(validate_archive_relative_path(Path::new("safe/file"), 4).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_archive_resource_bombs_before_expansion() {
        let root = temp("archive-limits");
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("limits.tar.gz");
        write_archive(&archive, &[("one", b"1234"), ("two", b"5678")]);

        let mut limits = ARCHIVE_LIMITS;
        limits.compressed_bytes = 1;
        assert!(extract_archive_with_limits(&archive, &root.join("compressed"), limits).is_err());

        let mut limits = ARCHIVE_LIMITS;
        limits.file_bytes = 3;
        assert!(extract_archive_with_limits(&archive, &root.join("single"), limits).is_err());

        let mut limits = ARCHIVE_LIMITS;
        limits.expanded_bytes = 7;
        assert!(extract_archive_with_limits(&archive, &root.join("expanded"), limits).is_err());

        let mut limits = ARCHIVE_LIMITS;
        limits.entries = 1;
        assert!(extract_archive_with_limits(&archive, &root.join("entries"), limits).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn core_edits_format_two_dependencies_and_restores_valid_manifests() {
        let root = temp("edit-dependency");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/主.yx"), "言「善哉」；\n").unwrap();
        fs::write(root.join(MANIFEST_NAME), manifest_template("工程").unwrap()).unwrap();
        let dependency = Dependency::Path {
            path: PathBuf::from("../实际包"),
            requirement: Some(VersionReq::parse("^1.2").unwrap()),
        };
        let manifest = edit_dependency(
            root.join(MANIFEST_NAME),
            "别名",
            Some("实际包"),
            Some(&dependency),
            true,
        )
        .unwrap();
        assert_eq!(manifest.format_version, 2);
        assert_eq!(manifest.dev_dependency_packages["别名"], "实际包");
        assert!(matches!(
            &manifest.dev_dependencies["别名"],
            Dependency::Path { requirement: Some(requirement), .. } if requirement.to_string() == "^1.2"
        ));
        let manifest = edit_dependency(root.join(MANIFEST_NAME), "别名", None, None, true).unwrap();
        assert!(manifest.dev_dependencies.is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_manifest_edits_are_serialized_and_leave_no_partial_files() {
        let root = temp("concurrent-edit");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/主.yx"), "言「善哉」；\n").unwrap();
        let manifest_path = root.join(MANIFEST_NAME);
        fs::write(&manifest_path, manifest_template("并发工程").unwrap()).unwrap();
        let threads = (0..8)
            .map(|index| {
                let manifest_path = manifest_path.clone();
                std::thread::spawn(move || {
                    edit_dependency(
                        manifest_path,
                        &format!("依赖{index}"),
                        None,
                        Some(&Dependency::Path {
                            path: PathBuf::from(format!("../dependency-{index}")),
                            requirement: None,
                        }),
                        false,
                    )
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let manifest = load(&manifest_path).unwrap();
        assert_eq!(manifest.dependencies.len(), 8);
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_install_update_and_build_leave_complete_artifacts() {
        let root = temp("concurrent-package-operations");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='并发应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/application.yxp");
        let threads = (0..6)
            .map(|index| {
                let manifest = manifest.clone();
                let output = output.clone();
                std::thread::spawn(move || match index % 3 {
                    0 => ensure_lock_with_dev(&manifest, false).map(|_| ()),
                    1 => update_lock(&manifest, false).map(|_| ()),
                    _ => pack_package(&manifest, output).map(|_| ()),
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let lock = read_lock(root.join(LOCK_NAME)).unwrap();
        assert_eq!(lock.generator, env!("CARGO_PKG_VERSION"));
        assert!(output.is_file());
        let unpacked = root.join("unpacked");
        extract_archive_safely(&output, &unpacked).unwrap();
        assert!(unpacked.join("package/主.yx").is_file());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn locked_build_cache_uses_one_key_for_relative_and_canonical_roots() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let relative = PathBuf::from(format!(".yanxu-relative-cache-{unique}"));
        write(
            &relative.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='相对缓存'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&relative.join("主.yx"), "言 1；\n");
        let manifest = load(relative.join(MANIFEST_NAME)).unwrap();
        let canonical = fs::canonicalize(&relative).unwrap();
        with_locked_resolution(&manifest, false, |graph| {
            let cached = graph_cache()
                .lock()
                .expect("graph cache poisoned")
                .get(&canonical)
                .cloned();
            assert_eq!(cached, Some(graph));
            Ok::<_, ManifestError>(())
        })
        .unwrap();
        fs::remove_dir_all(relative).ok();
    }

    #[test]
    fn failed_lock_update_preserves_the_last_complete_lockfile() {
        let root = temp("atomic-lock-update");
        let dependency = root.join("dependency");
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值 为 1；\n");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='dependency'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let lock_path = root.join(LOCK_NAME);
        let complete = fs::read(&lock_path).unwrap();
        fs::remove_dir_all(dependency).unwrap();
        assert!(update_lock(&manifest, true).is_err());
        assert_eq!(fs::read(lock_path).unwrap(), complete);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn offline_registry_resolution_never_attempts_an_uncached_download() {
        let root = temp("offline-registry");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='离线应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n远程={版='^1',源='https://127.0.0.1:1/never'}\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let error = ensure_lock(&manifest, true).unwrap_err();
        assert!(error.message.contains("离线模式"));
        assert!(!root.join(LOCK_NAME).exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn offline_registry_cache_revalidates_legacy_content_without_deleting_it() {
        let root = temp("offline-registry-cache-validation");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let legacy = registry_cache.join("缓存包/1.0.0");
        write(
            &legacy.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缓存包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&legacy.join("主.yx"), "公 定 值 为 1；\n");
        let checksum = tree_checksum(&legacy).unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "缓存包",
            version: &version,
            requirement: &requirement,
        };
        let _cache_lock = acquire_registry_package_lock(&key).unwrap();
        let valid = find_cached_registry_package_locked(&key, &checksum, true).unwrap();
        assert_eq!(
            valid.resolved.unwrap().root,
            fs::canonicalize(&legacy).unwrap()
        );

        fs::remove_file(legacy.join("主.yx")).unwrap();
        let invalid = find_cached_registry_package_locked(&key, &checksum, true).unwrap();
        assert!(invalid.resolved.is_none());
        assert!(invalid.invalid.is_some());
        assert!(legacy.is_dir());
        assert!(legacy.join(MANIFEST_NAME).is_file());
        drop(_cache_lock);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn registry_staging_rejects_wrong_identity_and_incomplete_content() {
        let root = temp("registry-staging-identity");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "正确包",
            version: &version,
            requirement: &requirement,
        };
        let legacy = registry_legacy_root(&key);
        write(
            &legacy.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='正确包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&legacy.join("主.yx"), "旧缓存内容\n");
        let previous = fs::read(legacy.join("主.yx")).unwrap();
        let cases = [
            ("错误包", "1.0.0", "主.yx", true, "依赖名"),
            ("正确包", "1.1.0", "主.yx", true, "索引选择版本"),
            ("正确包", "1.0.0", "主.yx", false, "未进入包内容"),
        ];
        for (name, declared_version, entry, include_entry, expected) in cases {
            let error = staged_registry_fixture(&key, name, declared_version, entry, include_entry)
                .unwrap_err();
            assert!(
                error.message.contains(expected),
                "{name}@{declared_version}: {error}"
            );
            assert_eq!(fs::read(legacy.join("主.yx")).unwrap(), previous);
        }
        let legacy_checksum = tree_checksum(&legacy).unwrap();
        let checksum_error = staged_registry_fixture_with_expected(
            &key,
            "正确包",
            "1.0.0",
            "主.yx",
            true,
            Some(&legacy_checksum),
        )
        .unwrap_err();
        assert!(checksum_error.message.contains("内容校验不符"));
        assert_eq!(fs::read(legacy.join("主.yx")).unwrap(), previous);
        let staging = registry_cache.join(".staging");
        assert!(
            !staging.exists()
                || fs::read_dir(staging)
                    .unwrap()
                    .all(|entry| !entry.unwrap().path().is_dir())
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn registry_staging_extracts_the_exact_hashed_archive_bytes() {
        let root = temp("registry-staging-hash-binding");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "绑定包",
            version: &version,
            requirement: &requirement,
        };
        let temporary = RegistryTemporaryDirectory::create_within(
            &registry_cache,
            &registry_cache.join(".staging"),
            "archive-binding",
        )
        .unwrap();
        let archive = temporary.path().join("package.tar.gz");
        let original_manifest = "[包]\n格式=2\n名称='绑定包'\n版本='1.0.0'\n入口='主.yx'\n";
        write_archive(
            &archive,
            &[
                ("package/言序.toml", original_manifest.as_bytes()),
                ("package/主.yx", "原始已校验内容\n".as_bytes()),
            ],
        );
        let expected_artifact_checksum = file_checksum(&archive).unwrap();

        let replacement = root.join("replacement.tar.gz");
        write_archive(
            &replacement,
            &[
                ("package/言序.toml", original_manifest.as_bytes()),
                ("package/主.yx", "摘要后替换内容\n".as_bytes()),
            ],
        );
        let replacement_bytes = fs::read(replacement).unwrap();
        let staged = prepare_staged_registry_package_with_hook(
            &key,
            temporary,
            &archive,
            &expected_artifact_checksum,
            None,
            |path| {
                crate::storage::atomic_write(path, &replacement_bytes).map_err(|error| {
                    manifest_error(path, None, format!("不能模拟替换索引制品：{error}"))
                })
            },
        )
        .unwrap();
        assert_eq!(
            fs::read(staged.root.join("主.yx")).unwrap(),
            "原始已校验内容\n".as_bytes()
        );
        assert_eq!(staged.artifact_checksum, expected_artifact_checksum);
        drop(staged);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn registry_publish_failures_preserve_legacy_cache_and_hide_candidates() {
        let root = temp("registry-copy-transaction");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let legacy = registry_cache.join("缓存包/1.0.0");
        write(
            &legacy.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缓存包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&legacy.join("主.yx"), "旧缓存内容\n");
        let previous = fs::read(legacy.join("主.yx")).unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "缓存包",
            version: &version,
            requirement: &requirement,
        };
        for failure in [
            RegistryInstallCheckpoint::BeforeCopyEntry,
            RegistryInstallCheckpoint::BeforePublish,
        ] {
            let staged = staged_registry_fixture(&key, "缓存包", "1.0.0", "主.yx", true).unwrap();
            let checksum_root = registry_snapshot_checksum_root(&key, &staged.tree_checksum);
            let error = publish_registry_snapshot_with_checkpoint(&key, staged, |point, path| {
                if point == failure {
                    Err(manifest_error(path, None, "模拟索引缓存发布失败"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(error.message.contains("模拟索引缓存发布失败"));
            assert_eq!(fs::read(legacy.join("主.yx")).unwrap(), previous);
            assert!(
                !checksum_root.exists()
                    || fs::read_dir(checksum_root).unwrap().all(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with('.'))
            );
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_registry_publishers_share_one_complete_snapshot() {
        use std::sync::{Arc, Barrier};

        let root = temp("concurrent-registry-publish");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "并发包",
            version: &version,
            requirement: &requirement,
        };
        let first = staged_registry_fixture(&key, "并发包", "1.0.0", "主.yx", true).unwrap();
        let second = staged_registry_fixture(&key, "并发包", "1.0.0", "主.yx", true).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for staged in [first, second] {
            let registry_cache = registry_cache.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let version = Version::new(1, 0, 0);
                let requirement = VersionReq::parse("^1").unwrap();
                let key = RegistryPackageKey {
                    registry_cache: &registry_cache,
                    registry: "https://packages.example.invalid/v1",
                    name: "并发包",
                    version: &version,
                    requirement: &requirement,
                };
                barrier.wait();
                publish_registry_snapshot(&key, staged)
            }));
        }
        let first = threads.remove(0).join().unwrap().unwrap();
        let second = threads.remove(0).join().unwrap().unwrap();
        assert_eq!(first.root, second.root);
        assert_eq!(first.locked.checksum, second.locked.checksum);

        let checksum_root = registry_snapshot_checksum_root(&key, &first.locked.checksum);
        let generations = fs::read_dir(&checksum_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(generations, 1);

        let _cache_lock = acquire_registry_package_lock(&key).unwrap();
        let valid =
            find_cached_registry_package_locked(&key, &first.locked.checksum, false).unwrap();
        assert_eq!(valid.resolved.unwrap().root, first.root);
        write(&first.root.join("主.yx"), "损坏内容\n");
        let invalid =
            find_cached_registry_package_locked(&key, &first.locked.checksum, false).unwrap();
        assert!(invalid.resolved.is_none());
        assert!(invalid.invalid.is_some());
        assert!(first.root.is_dir());
        drop(_cache_lock);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn damaged_registry_snapshot_is_preserved_while_a_complete_repair_is_published() {
        let root = temp("registry-snapshot-repair");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "修复包",
            version: &version,
            requirement: &requirement,
        };
        let initial = staged_registry_fixture(&key, "修复包", "1.0.0", "主.yx", true).unwrap();
        let initial = publish_registry_snapshot(&key, initial).unwrap();
        let checksum = initial.locked.checksum.clone();
        write(&initial.root.join("主.yx"), "已损坏的旧快照\n");
        let damaged = fs::read(initial.root.join("主.yx")).unwrap();

        let replacement = staged_registry_fixture_with_expected(
            &key,
            "修复包",
            "1.0.0",
            "主.yx",
            true,
            Some(&checksum),
        )
        .unwrap();
        let replacement = publish_registry_snapshot(&key, replacement).unwrap();
        assert_ne!(initial.root, replacement.root);
        assert_eq!(fs::read(initial.root.join("主.yx")).unwrap(), damaged);
        assert_eq!(replacement.locked.checksum, checksum);

        let checksum_root = registry_snapshot_checksum_root(&key, &checksum);
        let generations = fs::read_dir(checksum_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(generations, 2);
        let _cache_lock = acquire_registry_package_lock(&key).unwrap();
        let lookup = find_cached_registry_package_locked(&key, &checksum, false).unwrap();
        assert_eq!(lookup.resolved.unwrap().root, replacement.root);
        drop(_cache_lock);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn windows_absolute_paths_accept_drive_letter_case_and_backslashes() {
        let root = temp("windows-paths");
        let dependency = root.join("Dependency");
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值 为 1；\n");
        let mut dependency_path = fs::canonicalize(&dependency)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if let Some(first) = dependency_path.get_mut(..1) {
            first.make_ascii_lowercase();
        }
        let application = root.join("Application");
        write(
            &application.join(MANIFEST_NAME),
            &format!(
                "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具={{路径='{dependency_path}',版='^1'}}\n"
            ),
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        let dependencies = ensure_lock(&manifest, false).unwrap();
        assert_eq!(
            dependencies["工具"].root,
            fs::canonicalize(dependency).unwrap()
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_restore_works_but_portable_pack_rejects_a_path_dependency() {
        let root = temp("pack-vendor");
        let app = root.join("app");
        let dependency = root.join("dependency");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(dependency.join("src")).unwrap();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n",
        );
        write(&dependency.join("src/主.yx"), "公 定 值 为 1；\n");
        write(
            &app.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n工具='../dependency'\n[导出]\n默认='src/主.yx'\n",
        );
        write(
            &app.join("src/主.yx"),
            "引「包:工具」为 工具；言 工具.值；\n",
        );
        let manifest = load(app.join(MANIFEST_NAME)).unwrap();
        let graph = ensure_lock_with_dev(&manifest, false).unwrap();
        let vendor = app.join("vendor");
        let vendored = vendor_dependencies(&graph, &vendor).unwrap();
        assert_eq!(vendored.packages.len(), 1);
        fs::remove_dir_all(&dependency).unwrap();
        let restored = ensure_lock_with_dev(&manifest, true).unwrap();
        assert_eq!(restored.packages.len(), 1);
        assert!(
            restored
                .packages
                .values()
                .next()
                .unwrap()
                .root
                .starts_with(fs::canonicalize(&vendor).unwrap())
        );

        let first = app.join("build/first.yxp");
        let second = app.join("build/second.yxp");
        for output in [first, second] {
            let error = pack_package(&manifest, &output).unwrap_err();
            assert!(error.message.contains("仅本机可用的依赖"));
            assert!(error.message.contains("path:../dependency"));
            assert!(!output.exists());
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn portable_pack_rejects_local_git_and_registry_source_forms() {
        assert!(locked_source_is_machine_local("path:../dependency"));
        assert!(locked_source_is_machine_local(
            "git:file:///tmp/package.git"
        ));
        assert!(locked_source_is_machine_local("git:../package.git"));
        assert!(locked_source_is_machine_local("registry:file:///tmp/index"));
        assert!(locked_source_is_machine_local("registry:../index"));
        assert!(!locked_source_is_machine_local(
            "git:https://example.invalid/package.git"
        ));
        assert!(!locked_source_is_machine_local(
            "git:git@example.invalid:group/package.git"
        ));
        assert!(!locked_source_is_machine_local(
            "registry:https://packages.example.invalid/v1"
        ));

        let root = temp("pack-local-registry");
        let registry = root.join("registry");
        let dependency = registry.join("工具/1.0.0");
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值 为 1；\n");
        let app = root.join("app");
        write(
            &app.join(MANIFEST_NAME),
            &format!(
                "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具={{源={:?},版='^1'}}\n",
                registry.to_string_lossy()
            ),
        );
        write(&app.join("主.yx"), "言 1；\n");
        let manifest = load(app.join(MANIFEST_NAME)).unwrap();
        let output = app.join("build/package.yxp");
        let error = pack_package(&manifest, &output).unwrap_err();
        assert!(error.message.contains("仅本机可用的依赖"));
        assert!(error.message.contains("registry:"));
        assert!(!output.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn reserved_directory_names_and_nested_lockfiles_remain_derived_content() {
        let root = temp("nested-generated-names");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='嵌套目录'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        for name in ["build", "target", "vendor", ".yanxu"] {
            write(
                &root.join("src").join(name).join("模块.yx"),
                &format!("公 定 名称 为「{name}」；\n"),
            );
        }
        write(&root.join("src").join(LOCK_NAME), "nested lock content\n");

        let checksum_before = tree_checksum(&root).unwrap();
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let first = root.join("build/first.yxp");
        let first_artifact = pack_package(&manifest, &first).unwrap();
        let unpacked = temp("nested-generated-names-unpacked");
        extract_archive_safely(&first, &unpacked).unwrap();
        assert_eq!(
            find_manifest_root(&unpacked).unwrap(),
            unpacked.join("package")
        );
        let unpacked_manifest = load(unpacked.join("package").join(MANIFEST_NAME)).unwrap();
        assert!(
            unpacked_manifest
                .root
                .join(&unpacked_manifest.entry)
                .is_file()
        );
        assert!(!unpacked.join("package/src").join(LOCK_NAME).exists());
        for name in ["build", "target", "vendor", ".yanxu"] {
            assert!(!unpacked.join("package/src").join(name).exists());
            write(
                &root.join("src").join(name).join("模块.yx"),
                &format!("公 定 名称 为「changed-{name}」；\n"),
            );
        }
        write(&root.join("src").join(LOCK_NAME), "changed nested lock\n");

        let checksum_after = tree_checksum(&root).unwrap();
        assert_eq!(checksum_before, checksum_after);
        let second = root.join("build/second.yxp");
        let second_artifact = pack_package(&manifest, &second).unwrap();
        assert_eq!(first_artifact.checksum, second_artifact.checksum);
        fs::remove_dir_all(unpacked).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn root_generated_directories_remain_excluded_from_packages_and_hashes() {
        let root = temp("root-generated-names");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='根目录排除'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        for name in ["build", "target", "vendor", ".yanxu"] {
            write(&root.join(name).join("noise.txt"), "before\n");
        }
        let checksum_before = tree_checksum(&root).unwrap();
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let first = root.join("build/first.yxp");
        let first_artifact = pack_package(&manifest, &first).unwrap();

        for name in ["build", "target", "vendor", ".yanxu"] {
            write(&root.join(name).join("noise.txt"), "after\n");
        }
        assert_eq!(checksum_before, tree_checksum(&root).unwrap());
        let second = root.join("build/second.yxp");
        let second_artifact = pack_package(&manifest, &second).unwrap();
        assert_eq!(first_artifact.checksum, second_artifact.checksum);

        let unpacked = root.join("unpacked");
        extract_archive_safely(&second, &unpacked).unwrap();
        for name in ["build", "target", "vendor", ".yanxu"] {
            assert!(!unpacked.join("package").join(name).exists());
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn manifest_validator_rejects_reserved_components_at_every_depth() {
        let root = temp("pack-excluded-manifest-paths");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='排除路径'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let base = load(root.join(MANIFEST_NAME)).unwrap();
        let mut cases = Vec::new();

        let mut entry = base.clone();
        entry.entry = PathBuf::from("src/build/主.yx");
        cases.push(entry);

        let mut export = base.clone();
        export
            .exports
            .insert("排除".into(), PathBuf::from("src/target/导出.yx"));
        cases.push(export);

        let mut resource = base.clone();
        resource.resources.push(PathBuf::from("src/vendor/assets"));
        cases.push(resource);

        let mut workspace = base.clone();
        workspace
            .workspace_members
            .push(PathBuf::from("workspace/.yanxu/member"));
        cases.push(workspace);

        let mut application = base.clone();
        application.application = Some(ApplicationConfig {
            kind: ApplicationKind::CommandLine,
            name: "排除路径".into(),
            identifier: "dev.yanxu.excluded".into(),
            version: Version::new(1, 0, 0),
            icon: Some(PathBuf::from("assets/.git/icon.png")),
            company: None,
            minimum_system_version: None,
            window: WindowConfig::default(),
        });
        cases.push(application);

        let mut native = base;
        native.native = Some(NativePackage {
            abi_version: 2,
            artifacts: BTreeMap::from([(
                "x86_64-unknown-linux-gnu".into(),
                NativeArtifact {
                    abi: 2,
                    target: "x86_64-unknown-linux-gnu".into(),
                    path: "native/target/native.so".into(),
                    checksum: "0".repeat(64),
                    size: 1,
                },
            )]),
        });
        cases.push(native);

        for manifest in cases {
            let error = validate_package_manifest_paths(&manifest).unwrap_err();
            assert!(error.message.contains("保留路径组件"));
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_rejects_nested_manifests_before_publishing() {
        let root = temp("nested-pack-manifest");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='额外清单'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        write(
            &root.join("nested").join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='嵌套'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        let error = pack_package(&manifest, &output).unwrap_err();
        assert!(error.message.contains("恰含根目录一个"));
        assert!(!output.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_validates_the_complete_archive_path() {
        let root = temp("pack-path-limit");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='路径限制'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let relative = Path::new("abcdefghijklmnop");
        write(&root.join(relative), "content\n");
        assert!(validate_archive_relative_path(relative, 20).is_ok());
        assert!(validate_archive_relative_path(&Path::new("package").join(relative), 20).is_err());

        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        let mut limits = ARCHIVE_LIMITS;
        limits.path_bytes = 20;
        let error = pack_package_with_limits(&manifest, &output, limits).unwrap_err();
        assert!(error.message.contains("过长路径"));
        assert!(!output.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_rejects_compressed_output_over_the_consumer_limit() {
        let root = temp("pack-compressed-limit");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='压缩限制'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        write(&output, "previous artifact\n");
        let previous = fs::read(&output).unwrap();
        let mut limits = ARCHIVE_LIMITS;
        limits.compressed_bytes = 1;
        let error = pack_package_with_limits(&manifest, &output, limits).unwrap_err();
        assert!(error.message.contains("压缩后"));
        assert_eq!(fs::read(output).unwrap(), previous);
        assert!(fs::read_dir(root.join("build")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_rejects_each_producer_resource_limit_without_replacing_output() {
        let root = temp("pack-producer-limits");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='生产限额'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();

        let mut entries = ARCHIVE_LIMITS;
        entries.entries = 1;
        let mut file = ARCHIVE_LIMITS;
        file.file_bytes = 1;
        let mut expanded = ARCHIVE_LIMITS;
        expanded.expanded_bytes = 1;
        for (name, limits, expected) in [
            ("entries", entries, "条目"),
            ("file", file, "规范包清单"),
            ("expanded", expanded, "打包内容"),
        ] {
            let output = root.join("build").join(format!("{name}.yxp"));
            write(&output, "previous artifact\n");
            let previous = fs::read(&output).unwrap();
            let error = pack_package_with_limits(&manifest, &output, limits).unwrap_err();
            assert!(error.message.contains(expected), "{name}: {error}");
            assert_eq!(fs::read(&output).unwrap(), previous);
        }
        assert!(fs::read_dir(root.join("build")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn wide_package_tree_keeps_open_directory_handles_bounded() {
        #[cfg(unix)]
        const CHILD_ENV: &str = "YANXU_WIDE_TREE_CHILD";
        #[cfg(unix)]
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("wide_package_tree_keeps_open_directory_handles_bounded")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "低句柄上限子进程遍历宽目录失败");
            return;
        }

        let root = temp("wide-package-tree");
        for index in 0..128 {
            write(
                &root.join(format!("directory-{index:03}/module.yx")),
                "言 1；\n",
            );
        }

        #[cfg(unix)]
        {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
                0
            );
            limit.rlim_cur = limit.rlim_max.min(64 as libc::rlim_t);
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        }

        let snapshot = capture_package_tree(
            &root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        )
        .unwrap();
        assert_eq!(snapshot.files.len(), 128);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn package_tree_rejects_excessive_directory_depth() {
        let root = temp("deep-package-tree");
        let excessive = root.join("one/two/three/four");
        write(&excessive.join("module.yx"), "言 1；\n");
        let mut limits = PackageTreeCaptureLimits::dependency();
        limits.depth = 3;

        let error = capture_package_tree(&root, PackagePathPurpose::TreeChecksum, limits, None)
            .unwrap_err();
        assert_eq!(error.path, fs::canonicalize(&excessive).unwrap());
        assert_eq!(error.message, "包目录深度不得超过 3 层");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn package_tree_rejects_entries_beyond_the_global_scan_limit() {
        let root = temp("package-tree-scan-limit");
        for name in ["one.yx", "two.yx", "three.yx"] {
            write(&root.join(name), "言 1；\n");
        }
        let mut limits = PackageTreeCaptureLimits::dependency();
        limits.scanned_entries = 2;

        let error = capture_package_tree(&root, PackagePathPurpose::TreeChecksum, limits, None)
            .unwrap_err();
        assert_eq!(error.path, fs::canonicalize(&root).unwrap());
        assert_eq!(error.message, "包目录项不得超过 2 个");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn package_tree_snapshot_survives_bound_root_replacement() {
        let root = temp("tree-bound-root-replacement");
        let backup = root.with_extension("original");
        write(&root.join("old.yx"), "言「可信根」；\n");
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();

        fs::rename(&root, &backup).unwrap();
        write(&root.join("new.yx"), "言「替换根」；\n");

        let captured = capture_package_tree_in(
            &roots,
            &root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        );
        #[cfg(target_os = "wasi")]
        if std::env::var_os("YANXU_EXPECT_WASI_BINDING_DRIFT").is_some() {
            let error = captured.unwrap_err();
            assert!(error.message.contains("WASI 宿主目录描述符绑定发生漂移"));
            fs::remove_dir_all(root).ok();
            fs::remove_dir_all(backup).ok();
            return;
        }
        let snapshot = captured.unwrap();
        assert_eq!(
            snapshot.get(Path::new("old.yx")),
            Some("言「可信根」；\n".as_bytes())
        );
        assert!(snapshot.get(Path::new("new.yx")).is_none());

        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[test]
    fn portable_tree_checksum_accepts_legacy_paths_and_normalizes_nfc() {
        let root = temp("portable-checksum-compatibility");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='摘要兼容'\n版本='1.0.0'\n入口='src/主.yx'\n",
        );
        write(&root.join("src/主.yx"), "言 1；\n");
        write(&root.join("assets/e\u{301}.txt"), "accent\n");

        let portable = tree_checksum(&root).unwrap();
        let legacy_unix = legacy_tree_checksum(&root, "/").unwrap();
        let legacy_windows = legacy_tree_checksum(&root, "\\").unwrap();
        assert_ne!(portable, legacy_unix);
        assert_ne!(portable, legacy_windows);
        assert!(tree_checksum_matches(&root, &legacy_unix).unwrap());
        assert!(tree_checksum_matches(&root, &legacy_windows).unwrap());

        fs::rename(root.join("assets/e\u{301}.txt"), root.join("assets/é.txt")).unwrap();
        assert_eq!(portable, tree_checksum(&root).unwrap());
        assert!(tree_checksum_matches(&root, &legacy_unix).unwrap());
        assert!(tree_checksum_matches(&root, &legacy_windows).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_paths_reject_backslashes_and_package_names_require_nfc() {
        let manifest_path = Path::new("言序.toml");
        for kind in ["入口", "导出", "资源", "工作区成员", "原生制品", "权限文件"]
        {
            let error = manifest_relative_path(r"dir\file.yx", manifest_path, kind).unwrap_err();
            assert_eq!(error.code(), PACKAGE_PATH_NON_PORTABLE_CODE, "{kind}");
        }
        let error = validate_package_name("e\u{301}").unwrap_err();
        assert!(error.contains(PACKAGE_PATH_NON_PORTABLE_CODE), "{error}");
        assert!(validate_package_name("é").is_ok());
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn pack_reads_from_the_open_root_after_root_replacement() {
        let root = temp("pack-root-handle");
        let backup = root.with_extension("original");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='根快照'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言「可信根」；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output_root = temp("pack-root-handle-output");
        fs::create_dir_all(&output_root).unwrap();
        let output = output_root.join("package.yxp");

        pack_package_with_limits_and_hook(&manifest, &output, ARCHIVE_LIMITS, |_| {
            fs::rename(&root, &backup).map_err(|error| {
                manifest_error(&root, None, format!("不能模拟包根替换：{error}"))
            })?;
            write(
                &root.join(MANIFEST_NAME),
                "[包]\n格式=2\n名称='根快照'\n版本='1.0.0'\n入口='主.yx'\n",
            );
            write(&root.join("主.yx"), "言「替换根」；\n");
            Ok(())
        })
        .unwrap();

        let unpacked = output_root.join("unpacked");
        extract_archive_safely(&output, &unpacked).unwrap();
        assert_eq!(
            fs::read_to_string(unpacked.join("package/主.yx")).unwrap(),
            "言「可信根」；\n"
        );
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
        fs::remove_dir_all(output_root).ok();
    }

    #[test]
    fn external_module_resolution_reads_only_from_its_bound_handle() {
        let root = temp("external-module-handle");
        let requested = root.join("模块.yx");
        write(&requested, "言「外部模块」；\n");
        let mut roots = TrustedPackageRoots::default();
        let (resolved, authority) = roots.resolve_import_file(&root, &requested, false).unwrap();
        assert!(!authority.is_verified());

        let resolved = resolved.open().unwrap();
        assert_eq!(
            read_resolved_module_source_snapshot(resolved).unwrap(),
            "言「外部模块」；\n"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn external_module_open_rejects_replacement_before_binding() {
        let root = temp("external-module-replacement");
        let module = root.join("模块.yx");
        let original = root.join("原模块.yx");
        write(&module, "言「可信」；\n");
        let canonical = fs::canonicalize(&module).unwrap();

        let error = open_external_module_file_with_hook(&canonical, || {
            fs::rename(&canonical, &original).map_err(|error| {
                manifest_error(&canonical, None, format!("不能模拟模块替换：{error}"))
            })?;
            write(&canonical, "言「替换」；\n");
            Ok(())
        })
        .unwrap_err();
        assert!(error.message.contains("被替换"), "{error}");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn resolved_module_handle_survives_package_root_replacement() {
        let root = temp("resolved-module-root");
        let requested = root.join("src/模块.yx");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='根句柄回归'\n版本='1.0.0'\n入口='src/模块.yx'\n",
        );
        write(&requested, "言「可信根」；\n");
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let (resolved, authority) = roots
            .resolve_import_file(requested.parent().unwrap(), &requested, false)
            .unwrap();
        assert!(authority.is_verified());

        let backup = root.with_extension("original");
        fs::rename(&root, &backup).unwrap();
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='根句柄回归'\n版本='1.0.0'\n入口='src/模块.yx'\n",
        );
        write(&requested, "言「替换根」；\n");

        let resolved = resolved.open().unwrap();
        assert_eq!(
            read_resolved_module_source_snapshot(resolved).unwrap(),
            "言「可信根」；\n"
        );
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[test]
    fn pack_rejects_missing_declared_content_without_replacing_output() {
        let root = temp("pack-missing-content");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缺失内容'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        fs::create_dir_all(root.join("assets")).unwrap();
        let base = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        write(&output, "previous artifact\n");
        let previous = fs::read(&output).unwrap();

        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缺失内容'\n版本='1.0.0'\n入口='missing.yx'\n",
        );
        let error = pack_package(&base, &output).unwrap_err();
        assert!(error.message.contains("不存在、不是普通文件或未进入包内容"));
        assert_eq!(fs::read(&output).unwrap(), previous);

        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缺失内容'\n版本='1.0.0'\n入口='主.yx'\n[导出]\n缺失='missing-export.yx'\n",
        );
        let error = pack_package(&base, &output).unwrap_err();
        assert!(error.message.contains("不存在、不是普通文件或未进入包内容"));
        assert_eq!(fs::read(&output).unwrap(), previous);

        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缺失内容'\n版本='1.0.0'\n入口='主.yx'\n[资源]\n目录=['assets']\n",
        );
        let error = pack_package(&base, &output).unwrap_err();
        assert!(error.message.contains("无法形成自包含内容"));
        assert_eq!(fs::read(&output).unwrap(), previous);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_uses_the_locked_manifest_and_exact_native_bytes_written_to_the_archive() {
        let root = temp("pack-snapshot-integrity");
        let manifest_path = root.join(MANIFEST_NAME);
        let valid_manifest = "[包]\n格式=2\n名称='快照完整性'\n版本='1.0.0'\n入口='主.yx'\n";
        write(&manifest_path, valid_manifest);
        write(&root.join("主.yx"), "言 1；\n");
        write(&root.join("另.yx"), "言 2；\n");
        let manifest = load(&manifest_path).unwrap();
        let output = root.join("build/package.yxp");
        write(&output, "previous artifact\n");
        let previous = fs::read(&output).unwrap();

        let error = pack_package_with_limits_and_hook(&manifest, &output, ARCHIVE_LIMITS, |_| {
            write(
                &manifest_path,
                "[包]\n格式=2\n名称='快照完整性'\n版本='1.0.0'\n入口='另.yx'\n",
            );
            Ok(())
        })
        .unwrap_err();
        assert!(error.message.contains("锁内读取后发生变化"));
        assert_eq!(fs::read(&output).unwrap(), previous);

        let native_path = root.join("native/library.bin");
        let native_before = b"AAAA";
        write(&native_path, std::str::from_utf8(native_before).unwrap());
        let native_checksum = format!("{:x}", Sha256::digest(native_before));
        write(
            &manifest_path,
            &format!(
                "{valid_manifest}[原生]\nABI=2\n[原生.linux.x86_64]\n文件='native/library.bin'\n校验和='{native_checksum}'\n大小=4\n"
            ),
        );
        let native_manifest = load(&manifest_path).unwrap();
        let error =
            pack_package_with_limits_and_hook(&native_manifest, &output, ARCHIVE_LIMITS, |_| {
                write(&native_path, "BBBB");
                Ok(())
            })
            .unwrap_err();
        assert!(error.message.contains("大小或 SHA-256 与清单不符"));
        assert_eq!(fs::read(&output).unwrap(), previous);
        assert!(fs::read_dir(root.join("build")).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_rejects_a_noncanonical_manifest_object_from_the_same_root() {
        let root = temp("pack-manifest-identity");
        let text = "[包]\n格式=2\n名称='清单身份'\n版本='1.0.0'\n入口='主.yx'\n";
        write(&root.join(MANIFEST_NAME), text);
        write(&root.join("other.toml"), text);
        write(&root.join("主.yx"), "言 1；\n");
        let other = load(root.join("other.toml")).unwrap();
        let output = root.join("build/package.yxp");
        let error = pack_package(&other, &output).unwrap_err();
        assert!(error.message.contains("规范清单"));
        assert!(!output.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_stops_at_real_entry_and_path_limits_without_replacing_output() {
        let root = temp("pack-real-entry-limit");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='真实限额'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        for index in 0..ARCHIVE_MAX_ENTRIES {
            write(&root.join("wide").join(format!("{index:04}.txt")), "x");
        }
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        write(&output, "previous artifact\n");
        let previous = fs::read(&output).unwrap();
        let error = pack_package(&manifest, &output).unwrap_err();
        assert!(error.message.contains("条目不得超过"));
        assert_eq!(fs::read(&output).unwrap(), previous);
        fs::remove_dir_all(root).ok();

        let root = temp("pack-real-path-limit");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='深路径'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let mut deep = root.clone();
        for _ in 0..64 {
            deep.push("abcdefgh");
        }
        write(&deep.join("file.txt"), "x");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output = root.join("build/package.yxp");
        let error = pack_package(&manifest, &output).unwrap_err();
        assert!(error.message.contains("过长路径"));
        assert!(!output.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn reserved_directory_aliases_are_rejected_on_every_filesystem() {
        let root = temp("reserved-case-aliases");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='大小写保留目录'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        for name in ["Build", "TARGET", "Vendor", ".YANXU"] {
            write(&root.join("src").join(name).join("noise.txt"), "before\n");
        }
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output_root = temp("reserved-case-output");
        let error = pack_package(&manifest, output_root.join("package.yxp")).unwrap_err();
        assert!(
            error
                .message
                .contains(crate::path_policy::PACKAGE_PATH_NON_PORTABLE_CODE)
        );
        let mut manifest_path = manifest.clone();
        manifest_path.entry = PathBuf::from("src/Build/入口.yx");
        let error = validate_package_manifest_paths(&manifest_path).unwrap_err();
        assert!(
            error
                .message
                .contains(crate::path_policy::PACKAGE_PATH_NON_PORTABLE_CODE)
        );
        fs::remove_dir_all(output_root).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn source_tree_outputs_are_self_excluding_and_never_clobber_source_content() {
        let root = temp("pack-output-location");
        let valid_manifest = "[包]\n格式=2\n名称='输出位置'\n版本='1.0.0'\n入口='主.yx'\n";
        write(&root.join(MANIFEST_NAME), valid_manifest);
        let source = root.join("主.yx");
        write(&source, "言 1；\n");
        let source_before = fs::read(&source).unwrap();
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();

        let overwrite = pack_package(&manifest, &source).unwrap_err();
        assert!(overwrite.message.contains("不是可安全替换的 YXP"));
        assert_eq!(fs::read(&source).unwrap(), source_before);

        let invalid_output = root.join("existing.bin");
        write(&invalid_output, "ordinary source content\n");
        let invalid_before = fs::read(&invalid_output).unwrap();
        let error = pack_package(&manifest, &invalid_output).unwrap_err();
        assert!(error.message.contains("不是可安全替换的 YXP"));
        assert_eq!(fs::read(&invalid_output).unwrap(), invalid_before);

        let duplicate_output = root.join("duplicate.yxp");
        write_archive(
            &duplicate_output,
            &[
                ("package/言序.toml", valid_manifest.as_bytes()),
                ("package/言序.toml", valid_manifest.as_bytes()),
                ("package/主.yx", "言 1；\n".as_bytes()),
            ],
        );
        let duplicate_before = fs::read(&duplicate_output).unwrap();
        let error = pack_package(&manifest, &duplicate_output).unwrap_err();
        assert!(error.message.contains("重复路径"));
        assert_eq!(fs::read(&duplicate_output).unwrap(), duplicate_before);

        let self_contained = root.join("package.yxp");
        let first = pack_package(&manifest, &self_contained).unwrap();
        let first_bytes = fs::read(&self_contained).unwrap();
        let second = pack_package(&manifest, &self_contained).unwrap();
        assert_eq!(first.checksum, second.checksum);
        assert_eq!(first_bytes, fs::read(&self_contained).unwrap());
        let normalized_escape = root.join("build/../package.yxp");
        let normalized = pack_package(&manifest, normalized_escape).unwrap();
        assert_eq!(first.checksum, normalized.checksum);

        let upper = root.join("dist/package.YXP");
        let upper_first = pack_package(&manifest, &upper).unwrap();
        let upper_bytes = fs::read(&upper).unwrap();
        let upper_second = pack_package(&manifest, &upper).unwrap();
        assert_eq!(upper_first.checksum, upper_second.checksum);
        assert_eq!(upper_bytes, fs::read(&upper).unwrap());

        let extensionless = root.join("artifacts/package");
        let extensionless_first = pack_package(&manifest, &extensionless).unwrap();
        let extensionless_bytes = fs::read(&extensionless).unwrap();
        let extensionless_second = pack_package(&manifest, &extensionless).unwrap();
        assert_eq!(extensionless_first.checksum, extensionless_second.checksum);
        assert_eq!(extensionless_bytes, fs::read(&extensionless).unwrap());

        let directory_output = root.join("build/directory.yxp");
        fs::create_dir_all(&directory_output).unwrap();
        let error = pack_package(&manifest, &directory_output).unwrap_err();
        assert!(error.message.contains("必须是普通文件"));
        assert!(directory_output.is_dir());

        write(&root.join("assets/data.txt"), "resource\n");
        write(
            &root.join(MANIFEST_NAME),
            &format!("{valid_manifest}[资源]\n目录=['assets']\n"),
        );
        let resource_output = root.join("assets/package.yxp");
        let error = pack_package(&manifest, &resource_output).unwrap_err();
        assert!(error.message.contains("位于资源目录"));
        assert!(!resource_output.exists());
        write(&root.join(MANIFEST_NAME), valid_manifest);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let alias_root = temp("pack-output-alias");
            fs::create_dir_all(&alias_root).unwrap();
            let alias = alias_root.join("project");
            symlink(&root, &alias).unwrap();
            let direct = pack_package(&manifest, &self_contained).unwrap();
            let aliased = pack_package(&manifest, alias.join("package.yxp")).unwrap();
            assert_eq!(direct.checksum, aliased.checksum);
            fs::remove_dir_all(alias_root).ok();

            let sentinel_root = temp("pack-output-symlink");
            fs::create_dir_all(&sentinel_root).unwrap();
            let sentinel = sentinel_root.join("sentinel");
            write(&sentinel, "sentinel content\n");
            let linked_output = root.join("build/linked.yxp");
            symlink(&sentinel, &linked_output).unwrap();
            let error = pack_package(&manifest, &linked_output).unwrap_err();
            assert!(error.message.contains("必须是普通文件"));
            assert_eq!(fs::read_to_string(&sentinel).unwrap(), "sentinel content\n");
            assert!(
                fs::symlink_metadata(&linked_output)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            fs::remove_dir_all(sentinel_root).ok();
        }

        let generated = root.join("build/package.yxp");
        write(&generated, "replaceable generated content\n");
        pack_package(&manifest, &generated).unwrap();
        validate_existing_package_archive(&generated, ARCHIVE_LIMITS).unwrap();

        let external_root = temp("pack-output-external");
        let external = external_root.join("package.yxp");
        pack_package(&manifest, &external).unwrap();
        assert!(external.is_file());
        fs::remove_dir_all(external_root).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn parses_full_manifest_and_validates_semver() {
        let root = temp("manifest");
        let path = root.join(MANIFEST_NAME);
        let text = r#"
            [包]
            名 = "算书"
            版 = "1.2.3"
            入口 = "src/主.yx"
            作者 = ["言序团队"]
            许可 = "MIT"

            [依赖]
            工具 = { 路径 = "../tools", 版 = "^1" }
            远程 = { git = "https://example.invalid/repo", 修订 = "main" }
            JSON = { 版 = ">=1, <2", 源 = "file:///registry" }

            [权限]
            文件 = ["data"]
            网络 = ["api.example.com"]
            本地网络 = true
            TCP监听 = ["127.0.0.1"]
            UDP绑定 = ["127.0.0.1"]
            环境 = ["YANXU_HOME"]
            进程 = true
        "#;
        let manifest = parse(text, path, root).unwrap();
        assert_eq!(manifest.format_version, 1);
        assert_eq!(manifest.name, "算书");
        assert_eq!(manifest.version, Version::new(1, 2, 3));
        assert!(matches!(
            manifest.dependencies["工具"],
            Dependency::Path { .. }
        ));
        assert!(
            manifest
                .permissions
                .check_file(manifest.root.join("data/a.txt"))
                .is_ok()
        );
        assert!(
            manifest
                .permissions
                .check_network("http://api.example.com/v1")
                .is_ok()
        );
        assert!(
            manifest
                .permissions
                .check_resolved_network("api.example.com:80", "10.0.0.1:80".parse().unwrap())
                .is_ok()
        );
        assert!(manifest.permissions.check_tcp_listen("127.0.0.1:0").is_ok());
        assert!(manifest.permissions.check_udp_bind("127.0.0.1:0").is_ok());
        assert!(manifest.permissions.check_environment("YANXU_HOME").is_ok());
        assert!(manifest.permissions.check_process().is_ok());

        let error = parse(
            "[包]\n名='坏/名'\n版='latest'\n入口='/主.yx'",
            PathBuf::from("言序.toml"),
            PathBuf::from("."),
        )
        .unwrap_err();
        assert!(error.message.contains("包名"));

        let error = parse(
            "[包]\n格式=3\n名='未来'\n版='1.0.0'\n入口='主.yx'",
            PathBuf::from("言序.toml"),
            PathBuf::from("."),
        )
        .unwrap_err();
        assert!(error.message.contains("不支持包清单格式版本 3"));
    }

    #[test]
    fn graphical_application_template_is_complete_and_valid() {
        let root = temp("gui-template");
        write(&root.join("src/主.yx"), "言「善哉」；\n");
        write(
            &root.join(MANIFEST_NAME),
            &gui_manifest_template("窗口应用", Some(Path::new("../yanxu-gui"))).unwrap(),
        );

        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let application = manifest.application.as_ref().unwrap();
        assert_eq!(
            manifest.minimum_yanxu.as_ref().unwrap().to_string(),
            ">=1.1.15"
        );
        assert_eq!(application.kind, ApplicationKind::Graphical);
        assert_eq!(application.name, "窗口应用");
        assert!(application.identifier.starts_with("dev.yanxu.app-"));
        assert_eq!(application.window.width, 800);
        assert_eq!(application.window.minimum_width, 480);
        assert!(manifest.permissions.check_graphical_interface().is_ok());
        assert!(
            manifest
                .permissions
                .check_native_extension("backend")
                .is_ok()
        );
        assert!(manifest.permissions.check_clipboard().is_err());
        assert!(matches!(
            manifest.dependencies.get("言窗"),
            Some(Dependency::Path { requirement: Some(requirement), .. })
                if requirement.to_string() == "^1.0"
        ));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn gui_permission_cannot_authorize_named_path_native_packages() {
        let root = temp("gui-native-permission");
        let path_dependency = root.join("path-dependency");
        write_native_package(&path_dependency, "yanxu-gui");
        let path_application = root.join("path-application");
        let path_manifest = "[包]\n格式=2\n名称='路径应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n言窗={包='yanxu-gui',路径='../path-dependency',版='^1'}\n[权限]\n图形界面=true\n";
        write(&path_application.join(MANIFEST_NAME), path_manifest);
        write(&path_application.join("主.yx"), "言 1；\n");
        let manifest = load(path_application.join(MANIFEST_NAME)).unwrap();
        let error = plan_update(&manifest, false).unwrap_err();
        assert!(error.message.contains("原生扩展 = true"), "{error}");
        assert!(error.message.contains("图形界面权限不能代替"), "{error}");
        write(
            &path_application.join(MANIFEST_NAME),
            &path_manifest.replace("图形界面=true", "图形界面=true\n原生扩展=true"),
        );
        let manifest = load(path_application.join(MANIFEST_NAME)).unwrap();
        assert_eq!(plan_update(&manifest, false).unwrap().packages.len(), 1);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn gui_permission_cannot_authorize_named_git_native_packages() {
        let root = temp("gui-git-native-permission");
        let git_dependency = root.join("git-dependency");
        write_native_package(&git_dependency, "yanxu-gui");
        for arguments in [
            ["init", "--quiet"].as_slice(),
            ["config", "user.email", "yanxu@example.invalid"].as_slice(),
            ["config", "user.name", "Yanxu Tests"].as_slice(),
            ["add", "."].as_slice(),
            ["commit", "--quiet", "-m", "initial"].as_slice(),
        ] {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&git_dependency)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let git_url = git_dependency.to_string_lossy().into_owned();
        let git_application = root.join("git-application");
        write(
            &git_application.join(MANIFEST_NAME),
            &format!(
                "[包]\n格式=2\n名称='Git应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n言窗={{包='yanxu-gui',git={git_url:?},修订='HEAD',版='^1'}}\n[权限]\n图形界面=true\n"
            ),
        );
        write(&git_application.join("主.yx"), "言 1；\n");
        let manifest = load(git_application.join(MANIFEST_NAME)).unwrap();
        let error = plan_update(&manifest, false).unwrap_err();
        assert!(error.message.contains("原生扩展 = true"), "{error}");
        assert!(error.message.contains("图形界面权限不能代替"), "{error}");
        let cache = cache_root().join("git").join(short_hash(&git_url));
        fs::remove_dir_all(cache).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn graphical_application_rejects_invalid_identity_dimensions_and_permissions() {
        let root = temp("invalid-gui-manifest");
        write(&root.join("src/主.yx"), "言「善哉」；\n");
        let valid = gui_manifest_template("窗口应用", Some(Path::new("../yanxu-gui"))).unwrap();
        let cases = [
            (
                valid.replace("dev.yanxu.app-", "没有反向域名-"),
                "ASCII 反向域名",
            ),
            (
                valid.replace("最小宽 = 480", "最小宽 = 900"),
                "最小尺寸不得大于默认尺寸",
            ),
            (
                valid.replace("图形界面 = true", "图形界面 = false"),
                "图形界面 = true",
            ),
        ];
        for (index, (text, expected)) in cases.into_iter().enumerate() {
            let path = root.join(format!("无效-{index}.toml"));
            write(&path, &text);
            let error = load(path).unwrap_err();
            assert!(
                error.message.contains(expected),
                "expected {expected:?} in {:?}",
                error.message
            );
        }
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn graphical_application_icon_must_be_a_regular_in_package_file() {
        use std::os::unix::fs::symlink;

        let root = temp("gui-icon-symlink");
        write(&root.join("src/主.yx"), "言「善哉」；\n");
        let outside = root.with_extension("outside.png");
        write(&outside, "not an icon");
        fs::create_dir_all(root.join("assets")).unwrap();
        symlink(&outside, root.join("assets/icon.png")).unwrap();
        let manifest = gui_manifest_template("窗口应用", Some(Path::new("../yanxu-gui")))
            .unwrap()
            .replace(
                "版本 = \"0.1.0\"\n\n[应用.窗口]",
                "版本 = \"0.1.0\"\n图标 = \"assets/icon.png\"\n\n[应用.窗口]",
            );
        write(&root.join(MANIFEST_NAME), &manifest);

        let error = load(root.join(MANIFEST_NAME)).unwrap_err();
        assert!(error.message.contains("不得为符号链接"));
        fs::remove_dir_all(root).ok();
        fs::remove_file(outside).ok();
    }

    #[test]
    fn accepts_standard_toml_quoted_chinese_keys() {
        let root = temp("quoted-manifest");
        let path = root.join(MANIFEST_NAME);
        let text = r#"
            ["包"]
            "格式" = 1
            "名" = "标准清单"
            "版" = "1.0.0"
            "入口" = "主.yx"

            ["依赖"]
            "工具" = { "路径" = "../工具", "版" = "^1" }
        "#;
        let manifest = parse(text, path, root).unwrap();
        assert_eq!(manifest.name, "标准清单");
        assert!(matches!(
            manifest.dependencies["工具"],
            Dependency::Path { .. }
        ));
    }

    #[test]
    fn rejects_unknown_lock_format_versions() {
        let root = temp("lock-format");
        let path = root.join(LOCK_NAME);
        write(
            &path,
            "lock_version = 3\nmanifest_checksum = 'none'\npackage = []\n",
        );
        let error = read_lock(&path).unwrap_err();
        assert!(error.message.contains("不支持锁文件版本 3"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolution_preserves_invalid_and_future_lock_files() {
        let root = temp("lock-preserve-invalid");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言「应用」；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let lock_path = root.join(LOCK_NAME);

        let future = "lock_version = 3\nmanifest_checksum = 'none'\npackage = []\n";
        write(&lock_path, future);
        let future_error = ensure_lock(&manifest, false).unwrap_err();
        assert!(future_error.message.contains("不支持锁文件版本 3"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), future);

        let malformed = "lock_version = [\n";
        write(&lock_path, malformed);
        let malformed_error = ensure_lock(&manifest, false).unwrap_err();
        assert!(malformed_error.message.contains("锁文件格式无效"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), malformed);

        fs::remove_file(&lock_path).unwrap();
        fs::create_dir(&lock_path).unwrap();
        let directory_error = ensure_lock(&manifest, false).unwrap_err();
        assert!(directory_error.message.contains("锁文件必须是普通文件"));
        assert!(lock_path.is_dir());

        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolution_rejects_lock_file_symlinks() {
        use std::os::unix::fs::symlink;

        let root = temp("lock-symlink");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言「应用」；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let outside = root.with_extension("outside.lock");
        write(&outside, "lock_version = 2\n");
        symlink(&outside, root.join(LOCK_NAME)).unwrap();

        let error = ensure_lock(&manifest, false).unwrap_err();
        assert!(error.message.contains("不得为符号链接"));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "lock_version = 2\n");

        fs::remove_dir_all(root).ok();
        fs::remove_file(outside).ok();
    }

    #[test]
    fn writes_and_verifies_reproducible_path_lock() {
        let root = temp("lock");
        let dependency = root.join("工具");
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n名='工具'\n版='1.4.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 答：数 为 42；\n");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n名='应用'\n版='0.5.0'\n入口='主.yx'\n[依赖]\n工具={路径='工具',版='^1'}\n",
        );
        write(&root.join("主.yx"), "引「包:工具」为 工具；\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let first = ensure_lock(&manifest, false).unwrap();
        assert!(root.join(LOCK_NAME).is_file());
        let second = ensure_lock(&manifest, true).unwrap();
        assert_eq!(first["工具"].locked, second["工具"].locked);

        write(&dependency.join(".DS_Store"), "本机元数据");
        write(&dependency.join(".yanxu/bin/yanxu"), "本机工具");
        let with_workspace_artifacts = ensure_lock(&manifest, true).unwrap();
        assert_eq!(
            first["工具"].locked,
            with_workspace_artifacts["工具"].locked
        );

        write(&dependency.join("主.yx"), "公 定 答：数 为 43；\n");
        let changed = ensure_lock(&manifest, true).unwrap_err();
        assert!(changed.message.contains("锁文件"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn format_two_resolves_aliases_exports_and_the_complete_transitive_graph() {
        let root = temp("format-two-graph");
        let application = root.join("应用");
        let first = root.join("甲库");
        let second = root.join("乙库");
        write(
            &second.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='乙库'\n版本='2.1.0'\n言序='>=1.1.5'\n入口='src/库.yx'\n[导出]\n默认='src/库.yx'\n工具='src/工具.yx'\n",
        );
        write(&second.join("src/库.yx"), "公 定 值：数 为 21；\n");
        write(&second.join("src/工具.yx"), "公 定 值：数 为 42；\n");
        write(
            &first.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='甲库'\n版本='1.0.0'\n言序='>=1.1.5'\n入口='src/库.yx'\n[依赖]\n乙={包='乙库',路径='../乙库',版='^2'}\n[导出]\n默认='src/库.yx'\n子模块='src/子.yx'\n",
        );
        write(
            &first.join("src/库.yx"),
            "引「包:乙」为 乙；\n公 定 值：数 为 乙.值；\n",
        );
        write(&first.join("src/子.yx"), "公 定 子：数 为 1；\n");
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='0.1.0'\n言序='>=1.1.5'\n入口='src/主.yx'\n[依赖]\n甲={包='甲库',路径='../甲库',版='^1'}\n[开发依赖]\n测试乙={包='乙库',路径='../乙库',版='^2'}\n[导出]\n默认='src/主.yx'\n[资源]\n目录=['assets']\n[构建]\n目标='字节码'\n",
        );
        write(
            &application.join("src/主.yx"),
            "引「包:甲/子模块」为 子；\n",
        );
        fs::create_dir_all(application.join("assets")).unwrap();

        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        assert_eq!(manifest.format_version, 2);
        assert_eq!(manifest.dependency_packages["甲"], "甲库");
        assert_eq!(manifest.dev_dependency_packages["测试乙"], "乙库");
        assert_eq!(manifest.exports["默认"], PathBuf::from("src/主.yx"));
        let graph = ensure_lock_with_dev(&manifest, false).unwrap();
        assert_eq!(graph.root_dependencies.len(), 1);
        assert_eq!(graph.root_dev_dependencies.len(), 1);
        assert_eq!(graph.packages.len(), 2);
        assert!(
            graph
                .packages
                .values()
                .all(|dependency| !dependency.locked.id.is_empty())
        );
        let lock_path = application.join(LOCK_NAME);
        let first_lock = fs::read(&lock_path).unwrap();
        ensure_lock_with_dev(&manifest, true).unwrap();
        assert_eq!(first_lock, fs::read(&lock_path).unwrap());

        let exported =
            resolve_dependency_scoped(Some(&application), &application.join("src"), "甲/子模块")
                .unwrap();
        assert_eq!(
            exported.entry,
            fs::canonicalize(first.join("src/子.yx")).unwrap()
        );
        let transitive =
            resolve_dependency_scoped(Some(&application), &first.join("src"), "乙/工具").unwrap();
        assert_eq!(
            transitive.entry,
            fs::canonicalize(second.join("src/工具.yx")).unwrap()
        );
        assert!(
            resolve_dependency_scoped(Some(&application), &application.join("src"), "乙").is_err()
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn application_nested_inside_a_path_dependency_uses_its_root_edges() {
        let parent = temp("nested-application-parent");
        let application = parent.join("examples/应用");
        write(
            &parent.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='父库'\n版本='1.0.0'\n入口='src/库.yx'\n[导出]\n默认='src/库.yx'\n",
        );
        write(&parent.join("src/库.yx"), "公 定 值：数 为 42；\n");
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='0.1.0'\n入口='主.yx'\n[依赖]\n父={包='父库',路径='../..',版='^1'}\n",
        );
        write(&application.join("主.yx"), "引「包:父」为 父；\n");

        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let dependency = resolve_dependency_scoped(Some(&application), &application, "父").unwrap();
        assert_eq!(
            dependency.entry,
            fs::canonicalize(parent.join("src/库.yx")).unwrap()
        );
        fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn selects_highest_matching_local_registry_version() {
        let root = temp("registry");
        for version in ["1.0.0", "1.5.0", "2.0.0"] {
            let package = root.join("索引").join("文字").join(version);
            write(
                &package.join(MANIFEST_NAME),
                &format!("[包]\n名='文字'\n版='{version}'\n入口='主.yx'\n"),
            );
            write(&package.join("主.yx"), "公 定 名：文 为「文字」；\n");
        }
        let selected = select_registry_version(
            &root.join("索引/文字"),
            &VersionReq::parse("^1").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(selected, Version::new(1, 5, 0));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn local_registry_metadata_skips_yanked_versions_unless_already_locked() {
        let root = temp("local-registry-yanked");
        let package_root = root.join("索引/文字");
        for version in ["1.0.0", "1.1.0"] {
            let package = package_root.join(version);
            write(
                &package.join(MANIFEST_NAME),
                &format!("[包]\n名='文字'\n版='{version}'\n入口='主.yx'\n"),
            );
            write(&package.join("主.yx"), "公 定 名：文 为「文字」；\n");
        }
        write(
            &package_root.join("index.json"),
            &serde_json::to_string_pretty(&serde_json::json!({
                "versions": [
                    {
                        "version": "1.0.0",
                        "url": "file:///tmp/文字-1.0.0.tar.gz",
                        "checksum": "a".repeat(64),
                        "yanked": false
                    },
                    {
                        "version": "1.1.0",
                        "url": "file:///tmp/文字-1.1.0.tar.gz",
                        "checksum": "b".repeat(64),
                        "yanked": true
                    }
                ]
            }))
            .unwrap(),
        );

        let selected = select_registry_version(&package_root, &VersionReq::STAR, None).unwrap();
        assert_eq!(selected, Version::new(1, 0, 0));
        let locked = Version::new(1, 1, 0);
        assert_eq!(
            select_registry_version(&package_root, &VersionReq::STAR, Some(&locked)).unwrap(),
            locked
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn reads_explicit_registry_security_metadata_without_network_access() {
        let root = temp("registry-audit-metadata");
        let registry = root.join("索引");
        write(
            &registry.join("示例/index.json"),
            &serde_json::to_string_pretty(&serde_json::json!({
                "versions": [
                    {
                        "version": "1.2.3",
                        "url": "https://packages.example.invalid/示例-1.2.3.tar.gz",
                        "checksum": "a".repeat(64),
                        "yanked": true,
                        "vulnerabilities": [
                            {
                                "id": "YXSA-2026-0001",
                                "severity": "high",
                                "summary": "示例漏洞",
                                "url": "https://security.example.invalid/YXSA-2026-0001"
                            },
                            {
                                "id": "YXSA-2026-0000",
                                "severity": "low",
                                "summary": "已撤回记录",
                                "withdrawn": true
                            }
                        ]
                    },
                    {
                        "version": "1.2.4",
                        "url": "https://packages.example.invalid/示例-1.2.4.tar.gz",
                        "checksum": "B".repeat(64)
                    }
                ]
            }))
            .unwrap(),
        );

        let metadata = registry_release_metadata(
            registry.to_str().unwrap(),
            "示例",
            &Version::new(1, 2, 3),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(metadata.yanked, Some(true));
        assert_eq!(metadata.checksum, "a".repeat(64));
        let vulnerabilities = metadata.vulnerabilities.unwrap();
        assert_eq!(vulnerabilities.len(), 2);
        assert_eq!(vulnerabilities[0].id, "YXSA-2026-0001");
        assert!(vulnerabilities[1].withdrawn);
        let unspecified = registry_release_metadata(
            registry.to_str().unwrap(),
            "示例",
            &Version::new(1, 2, 4),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(unspecified.yanked, None);
        assert_eq!(unspecified.vulnerabilities, None);
        assert!(valid_sha256(&unspecified.checksum));
        assert!(
            registry_release_metadata(
                registry.to_str().unwrap(),
                "示例",
                &Version::new(9, 9, 9),
                true,
            )
            .unwrap()
            .is_none()
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn registry_indexes_reject_ambiguous_and_unbounded_metadata() {
        let root = temp("registry-index-validation");
        let path = root.join("index.json");
        let checksum = "a".repeat(64);

        write(
            &path,
            &format!(
                r#"{{"versions":[{{"version":"1.0.0","url":"https://example.invalid/package.tar.gz","checksum":"{checksum}","yanked":false,"yanked":true}}]}}"#
            ),
        );
        let duplicate_key = read_registry_index(&path).unwrap_err();
        assert!(duplicate_key.message.contains("JSON 对象键重复：yanked"));

        let release = format!(
            r#"{{"version":"1.0.0","url":"https://example.invalid/package.tar.gz","checksum":"{checksum}"}}"#
        );
        write(&path, &format!(r#"{{"versions":[{release},{release}]}}"#));
        let duplicate_version = read_registry_index(&path).unwrap_err();
        assert!(duplicate_version.message.contains("索引版本重复：1.0.0"));

        write(
            &path,
            &format!(
                r#"{{"versions":[{{"version":"not-semver","url":"https://example.invalid/package.tar.gz","checksum":"{checksum}"}}]}}"#
            ),
        );
        let invalid_version = read_registry_index(&path).unwrap_err();
        assert!(invalid_version.message.contains("索引版本“not-semver”无效"));

        let oversized_id = "x".repeat(REGISTRY_VULNERABILITY_ID_MAX_BYTES + 1);
        write(
            &path,
            &format!(
                r#"{{"versions":[{{"version":"1.0.0","url":"https://example.invalid/package.tar.gz","checksum":"{checksum}","vulnerabilities":[{{"id":"{oversized_id}","severity":"high","summary":"test"}}]}}]}}"#
            ),
        );
        let oversized = read_registry_index(&path).unwrap_err();
        assert!(oversized.message.contains("漏洞元数据过长"));

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn new_registry_resolution_skips_yanked_versions_but_locks_remain_reproducible() {
        let release = |version: &str, yanked| RegistryRelease {
            version: version.into(),
            url: format!("https://example.invalid/{version}.tar.gz"),
            checksum: "a".repeat(64),
            yanked,
            vulnerabilities: Some(Vec::new()),
        };
        let releases = vec![release("1.0.0", Some(false)), release("1.1.0", Some(true))];

        let (selected, _) =
            select_remote_registry_release(releases.clone(), &VersionReq::STAR, None).unwrap();
        assert_eq!(selected, Version::new(1, 0, 0));

        let locked = Version::new(1, 1, 0);
        let (selected, metadata) =
            select_remote_registry_release(releases, &VersionReq::STAR, Some(&locked)).unwrap();
        assert_eq!(selected, locked);
        assert_eq!(metadata.yanked, Some(true));

        assert!(
            select_remote_registry_release(
                vec![release("2.0.0", Some(true))],
                &VersionReq::STAR,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_insecure_remote_sources_before_network_access() {
        assert!(!secure_git_source("--upload-pack=/tmp/command"));
        assert!(!secure_git_source(
            "https://example.invalid/package.git\nnext"
        ));
        assert!(secure_git_source("https://example.invalid/package.git"));
        assert!(secure_git_source("git@example.invalid:group/package.git"));

        #[cfg(unix)]
        {
            let unique = format!("yanxu-insecure-source-{}", std::process::id());
            let local_shape = Path::new("http:").join(&unique).join("package.git");
            fs::create_dir_all(&local_shape).unwrap();
            let disguised = format!("http://{unique}/package.git");
            assert!(Path::new(&disguised).exists());
            assert!(!secure_git_source(&disguised));
            fs::remove_dir_all(Path::new("http:").join(unique)).unwrap();
            fs::remove_dir("http:").ok();
        }

        let git_error =
            resolve_git("http://example.invalid/package.git", "HEAD", false).unwrap_err();
        assert!(git_error.message.contains("HTTPS 或 SSH"));
        let ftp_error =
            resolve_git("ftp://example.invalid/package.git", "HEAD", false).unwrap_err();
        assert!(ftp_error.message.contains("HTTPS 或 SSH"));

        let registry_error = resolve_registry(
            "示例",
            &VersionReq::STAR,
            "http://packages.example.invalid/v1",
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(registry_error.message.contains("索引须使用 HTTPS"));

        let metadata_error = registry_release_metadata(
            "http://packages.example.invalid/v1",
            "示例",
            &Version::new(1, 0, 0),
            true,
        )
        .unwrap_err();
        assert!(metadata_error.message.contains("索引须使用 HTTPS"));
    }

    #[test]
    fn source_policy_rejects_encoded_confusable_and_malformed_secret_shapes() {
        let marker = "source-policy-value-must-not-appear";
        let unsafe_sources = [
            format!("plain?access_token={marker}"),
            format!("plain?authorization_code={marker}"),
            format!("plain?x-sig={marker}"),
            format!("plain?ref=stable;access_token={marker}"),
            format!("plain?ref=stable%26access_token={marker}"),
            format!("plain?ref=stable%3Baccess_token={marker}"),
            format!("plain?%2561ccess_%2574oken={marker}"),
            format!("plain?%252561ccess_%252574oken={marker}"),
            format!("plain?%25252561ccess_%25252574oken={marker}"),
            format!("plain?ａｃｃｅｓｓ＿ｔｏｋｅｎ={marker}"),
            format!("plain?sеcret={marker}"),
            format!("plain?ref=%2&value={marker}"),
            format!("https:user:{marker}@example.invalid/package.git"),
            format!("user:{marker}@example.invalid:group/package.git"),
            format!("git@example.invalid@mirror.invalid:group/{marker}.git"),
            format!("ssh://deploy%3Auser@example.invalid/group/{marker}.git"),
            format!("git@bad;host.invalid:group/{marker}.git"),
        ];
        for source in unsafe_sources {
            assert_eq!(
                validate_source_url_security(&source),
                Err(SOURCE_SECURITY_ERROR),
                "unsafe source was accepted"
            );
            let displayed = safe_source_value_for_display(&source);
            assert!(!displayed.contains(marker), "source leaked: {displayed}");
        }

        let too_many_fields = format!(
            "plain?{}",
            (0..=SOURCE_QUERY_MAX_FIELDS)
                .map(|index| format!("field{index}=value"))
                .collect::<Vec<_>>()
                .join("&")
        );
        assert_eq!(
            validate_source_url_security(&too_many_fields),
            Err(SOURCE_SECURITY_ERROR)
        );
        assert_eq!(
            validate_source_url_security(&"x".repeat(SOURCE_VALUE_MAX_BYTES + 1)),
            Err(SOURCE_SECURITY_ERROR)
        );
        for source in [
            "plain?ref=stable;channel=release",
            "https://example.invalid/package.git?ref=stable&channel=release",
            "ssh://deploy-user@example.invalid/group/package.git",
            "deploy_user@example.invalid:group/package.git?ref=stable",
        ] {
            assert!(validate_source_url_security(source).is_ok(), "{source}");
        }
    }

    #[test]
    fn typed_sources_and_revisions_redact_network_user_information() {
        for source in [
            "https://example.invalid/group/package.git",
            "ssh://git@example.invalid/group/package.git",
            "ssh://deploy-user@example.invalid/group/package.git",
            "git@example.invalid:group/package.git",
        ] {
            assert!(validate_git_source_security(source).is_ok(), "{source}");
        }
        for source in [
            "http://example.invalid/package.git",
            "ftp://example.invalid/package.git",
            "ssh://user:password@example.invalid/package.git",
            "user:password@example.invalid:group/package.git",
            "git@example.invalid@mirror.invalid:group/package.git",
        ] {
            assert!(validate_git_source_security(source).is_err(), "{source}");
        }

        for revision in [
            "HEAD",
            "0123456789abcdef0123456789abcdef01234567",
            "refs/heads/main",
            "main~1",
            "feature%ready",
        ] {
            assert!(
                validate_git_revision_security(revision).is_ok(),
                "{revision}"
            );
            assert_eq!(safe_git_revision_for_display(revision), revision);
        }
        let marker = "revision-value-must-not-appear";
        for revision in [
            format!("https://user:{marker}@example.invalid/repo"),
            format!("user:{marker}@example.invalid"),
            format!("user@example.invalid:refs/{marker}"),
            format!("HEAD?access_token={marker}"),
            format!("refs%3Faccess_token={marker}"),
            format!("refs%253Fauthorization_code={marker}"),
            format!("https%253A%252F%252Fuser%253A{marker}%2540example.invalid%252Frevision"),
        ] {
            assert!(validate_git_revision_security(&revision).is_err());
            let displayed = safe_git_revision_for_display(&revision);
            assert!(!displayed.contains(marker), "revision leaked: {displayed}");

            let dependency = Dependency::Git {
                url: "https://example.invalid/package.git".into(),
                revision,
                requirement: None,
            };
            let dependency_display = dependency.to_string();
            assert!(
                !dependency_display.contains(marker),
                "dependency leaked: {dependency_display}"
            );
            assert!(validate_dependency_source_security(&dependency).is_err());
        }
    }

    #[test]
    fn path_sources_fail_at_parse_and_programmatic_resolution_boundaries() {
        let root = temp("path-source-security");
        fs::create_dir_all(&root).unwrap();
        let marker = "path-source-value-must-not-appear";
        for dependency in [
            format!("fixture = '../dependency?access_token={marker}'"),
            format!("fixture = {{路径='../dependency?authorization_code={marker}'}}"),
        ] {
            let text = format!(
                "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\n{dependency}\n"
            );
            let error = parse(&text, root.join(MANIFEST_NAME), root.clone())
                .unwrap_err()
                .to_string();
            assert!(!error.contains(marker), "{error}");
        }

        let safe = parse(
            "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\nfixture='../dependency#snapshot'\n",
            root.join(MANIFEST_NAME),
            root.clone(),
        )
        .unwrap();
        assert_eq!(
            safe.dependencies.get("fixture"),
            Some(&Dependency::Path {
                path: PathBuf::from("../dependency#snapshot"),
                requirement: None,
            })
        );
        let percent_path = parse(
            "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\nfixture='../100%/dep'\n",
            root.join(MANIFEST_NAME),
            root.clone(),
        )
        .unwrap();
        assert_eq!(
            percent_path.dependencies.get("fixture"),
            Some(&Dependency::Path {
                path: PathBuf::from("../100%/dep"),
                requirement: None,
            })
        );

        let encoded_network = format!(
            "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\nfixture='https%253A%252F%252Fuser%253A{marker}%2540example.invalid%252Fdep'\n"
        );
        let encoded_error = parse(&encoded_network, root.join(MANIFEST_NAME), root.clone())
            .unwrap_err()
            .to_string();
        assert!(!encoded_error.contains(marker), "{encoded_error}");

        for encoded_query in [
            format!("../dependency%3Faccess_token={marker}"),
            format!("../dependency%253Fauthorization_code={marker}"),
        ] {
            let text = format!(
                "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\nfixture={encoded_query:?}\n"
            );
            let error = parse(&text, root.join(MANIFEST_NAME), root.clone())
                .unwrap_err()
                .to_string();
            assert!(!error.contains(marker), "{error}");
        }

        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n",
        );
        write(&root.join("main.yx"), "言 1；\n");
        let mut manifest = load(root.join(MANIFEST_NAME)).unwrap();
        manifest.dependencies.insert(
            "fixture".into(),
            Dependency::Path {
                path: PathBuf::from(format!("../dependency?x-sig={marker}")),
                requirement: None,
            },
        );
        manifest
            .dependency_packages
            .insert("fixture".into(), "fixture".into());
        let error = resolve_graph(&manifest, true).unwrap_err().to_string();
        assert!(!error.contains(marker), "{error}");
        assert!(!root.join(LOCK_NAME).exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn lock_sources_are_exact_bounded_and_redacted() {
        for source in [
            "path:../dependency#snapshot",
            "git:https://example.invalid/package.git?ref=stable",
            "git:ssh://git@example.invalid/group/package.git",
            "registry:https://packages.example.invalid/v1?channel=stable",
        ] {
            assert!(
                validate_locked_dependency_source(source).is_ok(),
                "{source}"
            );
        }
        let marker = "lock-source-value-must-not-appear";
        for source in [
            "path:".to_owned(),
            format!("path:https://user:{marker}@example.invalid/package.git"),
            format!("git:plain?authorization_code={marker}"),
            format!("registry:https://packages.example.invalid/v1?x-sig={marker}"),
            format!("gitx:https://example.invalid/{marker}.git"),
        ] {
            assert!(validate_locked_dependency_source(&source).is_err());
            assert!(!safe_dependency_source_for_display(&source).contains(marker));
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn external_command_failures_do_not_echo_stderr() {
        let marker = "external-stderr-value-must-not-appear";
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg(format!("printf '{marker}\\nsecond-line' >&2; exit 17"));
            command
        };
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command
                .arg("/C")
                .arg(format!("echo {marker} 1>&2 & exit /B 17"));
            command
        };
        let error = run_command(&mut command, Path::new("external-command"), "执行外部命令")
            .unwrap_err()
            .to_string();
        assert!(!error.contains(marker), "{error}");
        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(error.contains("退出码 17"), "{error}");
    }

    #[test]
    fn unsafe_manifest_lock_and_registry_sources_never_echo_values() {
        let root = temp("unsafe-persisted-source");
        let marker = "persisted-value-must-not-appear";
        let unsafe_url = format!("https://user:{marker}@example.invalid/package.git");
        let manifest_path = root.join(MANIFEST_NAME);
        write(
            &manifest_path,
            &format!(
                "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n[依赖]\nfixture={{git={unsafe_url:?},修订='HEAD'}}\n"
            ),
        );
        write(&root.join("main.yx"), "言 1；\n");
        let manifest_error = load(&manifest_path).unwrap_err().to_string();
        assert!(!manifest_error.contains(marker), "{manifest_error}");

        let unsafe_lock = lock_with_source(format!("git:{unsafe_url}"));
        let old_lock_path = root.join("old.lock");
        write(
            &old_lock_path,
            &toml::to_string_pretty(&unsafe_lock).unwrap(),
        );
        let read_error = read_lock(&old_lock_path).unwrap_err().to_string();
        assert!(!read_error.contains(marker), "{read_error}");

        let new_lock_path = root.join("new.lock");
        let write_error = write_lock(&new_lock_path, &unsafe_lock)
            .unwrap_err()
            .to_string();
        assert!(!write_error.contains(marker), "{write_error}");
        assert!(!new_lock_path.exists());

        let artifact_index = root.join("artifact.json");
        write(
            &artifact_index,
            &serde_json::to_string(&serde_json::json!({
                "versions": [{
                    "version": "1.0.0",
                    "url": format!("https://user:{marker}@example.invalid/package.tar.gz"),
                    "checksum": "a".repeat(64),
                }]
            }))
            .unwrap(),
        );
        let artifact_error = read_registry_index(&artifact_index)
            .unwrap_err()
            .to_string();
        assert!(!artifact_error.contains(marker), "{artifact_error}");

        let advisory_index = root.join("advisory.json");
        write(
            &advisory_index,
            &serde_json::to_string(&serde_json::json!({
                "versions": [{
                    "version": "1.0.0",
                    "url": "https://example.invalid/package.tar.gz",
                    "checksum": "a".repeat(64),
                    "vulnerabilities": [{
                        "id": "YXSA-2026-0001",
                        "severity": "high",
                        "summary": "fixture advisory",
                        "url": format!("https://security.example.invalid/advisory?token={marker}"),
                    }]
                }]
            }))
            .unwrap(),
        );
        let advisory_error = read_registry_index(&advisory_index)
            .unwrap_err()
            .to_string();
        assert!(!advisory_error.contains(marker), "{advisory_error}");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn git_source_is_pinned_to_an_exact_revision_and_reused_offline() {
        let root = temp("git");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n名='Git包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "公 定 答：数 为 1；\n");
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.email", "yanxu@example.invalid"],
            vec!["config", "user.name", "Yanxu Tests"],
            vec!["add", "."],
            vec!["commit", "--quiet", "-m", "initial"],
        ] {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let url = root.to_string_lossy();
        let (cache, first_revision) = resolve_git(&url, "HEAD", false).unwrap();
        assert_eq!(first_revision.len(), 40);
        let resolved = lock_local(
            "Git包",
            &cache,
            &format!("git:{url}"),
            Some(first_revision.clone()),
            None,
        )
        .unwrap();
        assert_eq!(resolved.root, fs::canonicalize(&cache).unwrap());
        assert_eq!(resolved.entry, resolved.root.join("主.yx"));
        for arguments in [vec!["branch", "channel"], vec!["tag", "v1"]] {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let (_, branch_first) = resolve_git(&url, "channel", false).unwrap();
        let (_, tag_revision) = resolve_git(&url, "v1", false).unwrap();
        assert_eq!(branch_first, first_revision);
        assert_eq!(tag_revision, first_revision);

        write(&root.join("主.yx"), "公 定 答：数 为 2；\n");
        for arguments in [vec!["add", "."], vec!["commit", "--quiet", "-m", "second"]] {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        }

        let (_, second_revision) = resolve_git(&url, "HEAD", false).unwrap();
        assert_ne!(first_revision, second_revision);
        let status = Command::new("git")
            .args(["branch", "--force", "channel", "HEAD"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        let (_, branch_second) = resolve_git(&url, "channel", false).unwrap();
        let (_, stable_tag_revision) = resolve_git(&url, "v1", false).unwrap();
        assert_eq!(branch_second, second_revision);
        assert_eq!(stable_tag_revision, first_revision);
        let (_, offline_revision) = resolve_git(&url, &second_revision, true).unwrap();
        assert_eq!(second_revision, offline_revision);
        fs::remove_dir_all(cache).ok();
        fs::remove_dir_all(root).ok();
    }
}

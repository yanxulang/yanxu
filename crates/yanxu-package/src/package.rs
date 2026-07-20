//! 言序包清单、锁文件与可复现依赖解析。
//!
//! `言序.toml` 可以声明路径、Git 和中央索引依赖；`言序.lock` 固定最终
//! 版本、Git 修订和内容 SHA-256。解析器在使用锁文件时仍会校验缓存内容，
//! 因而损坏或被悄悄改写的依赖不会进入模块执行。

mod archive;

use crate::subprocess;

use crate::path_policy::{
    ModuleAuthority, PACKAGE_PATH_NON_PORTABLE_CODE, PackagePathDecision, PackagePathError,
    PackagePathPurpose, PackagePathReason, PortablePackagePaths, ResolvedPackageFile,
    TrustedPackageRoots, package_path_decision, portable_case_fold, portable_package_path,
    resolve_existing_package_path, resolve_existing_portable_relative_path,
};
#[cfg(target_os = "wasi")]
use crate::path_policy::{WasiPackageDirectory, WasiPackageDirectoryEntry, WasiPackageEntry};
use archive::{
    ARCHIVE_LIMITS, ArchiveLimits, extract_archive_bytes_safely, extract_tar_bytes_with_limits,
    find_manifest_root, validate_archive_relative_path, validate_existing_package_archive,
};
#[cfg(test)]
use archive::{extract_archive_safely, extract_archive_with_limits};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
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
#[doc(hidden)]
pub const MODULE_SOURCE_MAX_BYTES: u64 = 8 * 1024 * 1024;
#[doc(hidden)]
pub const PACKAGE_MODULE_SOURCE_LIMIT_CODE: &str = "PACKAGE_MODULE_SOURCE_LIMIT";
const PACKAGE_TREE_MAX_FILE_BYTES: u64 = NATIVE_ARTIFACT_MAX_BYTES;
const PACKAGE_TREE_MAX_BYTES: u64 = NATIVE_ARTIFACT_MAX_TOTAL_BYTES + ARCHIVE_MAX_EXPANDED_BYTES;
const PACKAGE_TREE_MAX_ENTRIES: usize = 100_000;
const PACKAGE_TREE_MAX_DEPTH: usize = 128;
const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
const LOCK_MAX_BYTES: u64 = 16 * 1024 * 1024;
const VENDOR_MANIFEST_MAX_BYTES: u64 = 8 * 1024 * 1024;
const REGISTRY_INDEX_MAX_BYTES: u64 = ARCHIVE_MAX_COMPRESSED_BYTES;
const REGISTRY_INDEX_MAX_VERSIONS: usize = 10_000;
const REGISTRY_RELEASE_URL_MAX_BYTES: usize = 4_096;
const REGISTRY_VULNERABILITY_MAX_COUNT: usize = 1_024;
const REGISTRY_VULNERABILITY_ID_MAX_BYTES: usize = 256;
const REGISTRY_VULNERABILITY_SUMMARY_MAX_BYTES: usize = 8_192;
const RESOLUTION_GENERATION_LAYOUT: &str = "tree-v1";
const GIT_CACHE_LAYOUT: &str = "v2";
const GIT_GENERATION_LAYOUT: &str = "tree-v1";
const GIT_CONFIG_MAX_BYTES: u64 = 64 * 1024;
const GIT_COMMAND_STDERR_MAX_BYTES: usize = 64 * 1024;
const GIT_INSPECT_TIMEOUT: Duration = Duration::from_secs(15);
const GIT_INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_FETCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const GIT_ARCHIVE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const GIT_INITIALIZE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const GIT_STORE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const GIT_STORE_MAX_ENTRIES: usize = 1_000_000;
const GIT_STORE_MAX_DEPTH: usize = 256;
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
    /// 已经规范化并通过清单、版本与内容校验的不可变内容 generation。
    /// 来源位置保留在 [`Self::locked`]；调用方不得假定本路径等于原路径依赖目录。
    pub root: PathBuf,
    /// 位于同一不可变 generation 中的默认导出入口。
    pub entry: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionGraph {
    pub root_dependencies: BTreeMap<String, String>,
    pub root_dev_dependencies: BTreeMap<String, String>,
    pub packages: BTreeMap<String, ResolvedDependency>,
    pub target: String,
}

/// 一次解析中与公开依赖图逐项对应的已打开根能力。
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct ResolutionCapabilities {
    roots: TrustedPackageRoots,
}

impl ResolutionCapabilities {
    /// 把解析阶段已经打开的根合并到模块加载上下文，不再按路径重新打开。
    pub fn extend(&self, destination: &mut TrustedPackageRoots) -> Result<(), PackagePathError> {
        destination.extend_opened(&self.roots)
    }

    pub fn roots(&self) -> &TrustedPackageRoots {
        &self.roots
    }
}

#[derive(Debug, Clone)]
struct ResolutionInputFingerprint {
    package_id: String,
    source_root: PathBuf,
    source_roots: TrustedPackageRoots,
    generation_root: PathBuf,
    generation_roots: TrustedPackageRoots,
    checksum: String,
}

#[derive(Debug, Clone)]
struct ResolvedGraphBundle {
    graph: ResolutionGraph,
    capabilities: ResolutionCapabilities,
    application_root: PathBuf,
    application_roots: TrustedPackageRoots,
    manifest_checksum: String,
    lock_checksum: Option<String>,
    inputs: Vec<ResolutionInputFingerprint>,
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
            Some("[PACKAGE_MODULE_SOURCE_LIMIT") => PACKAGE_MODULE_SOURCE_LIMIT_CODE,
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
    let host_candidates = discovery_manifest_candidates(&absolute_start)?;
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
    let resolved_candidates = discovery_manifest_candidates(&resolved_start)?;
    load(resolved_candidates.first().unwrap_or(host_nearest)).map(Some)
}

fn discovery_manifest_candidates(start: &Path) -> Result<Vec<PathBuf>, ManifestError> {
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
        match fs::symlink_metadata(&candidate) {
            Ok(_) => manifests.push(candidate),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(manifest_error(
                    &candidate,
                    None,
                    format!("不能检查包清单候选：{error}"),
                ));
            }
        }
        if !directory.pop() {
            break;
        }
    }
    Ok(manifests)
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
    let candidates = discovery_manifest_candidates(&absolute)?;
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
            if let Some(alias_root) = discovery_manifest_candidates(&absolute_start)?
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

    /// 只从调用方已经打开的根能力解析导入，不再执行环境路径包发现。
    ///
    /// 目录工具在完成快照后使用此入口，避免替换目录通过新增更深包清单改变
    /// 根选择。包外路径一律失败闭合；`包:` 依赖须先把解析所得能力并入本集合。
    #[doc(hidden)]
    pub fn resolve_import_file_from_opened_roots(
        &self,
        current_base: &Path,
        requested_or_joined: &Path,
        allow_cross_package: bool,
    ) -> Result<(ResolvedImportFile, ModuleAuthority), ManifestError> {
        self.validate_requested_portability(requested_or_joined)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
        self.validate_requested_import(current_base, requested_or_joined, allow_cross_package)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
        let resolved = self
            .resolve_existing_module_file(requested_or_joined)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?
            .ok_or_else(|| {
                manifest_error(
                    requested_or_joined,
                    None,
                    "模块不属于发现阶段已经打开的工具根",
                )
            })?;
        let canonical = resolved.path().to_path_buf();
        let authority = self
            .authorize_module(requested_or_joined, &canonical)
            .map_err(|error| package_path_manifest_error(requested_or_joined, error))?;
        Ok((ResolvedImportFile::package(resolved), authority))
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
    let bytes = read_stable_metadata_file_snapshot(&path, MANIFEST_MAX_BYTES, "包清单")?;
    let text = String::from_utf8(bytes)
        .map_err(|error| manifest_error(&path, None, format!("包清单不是 UTF-8：{error}")))?;
    let root = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    parse(&text, path, root)
}

/// 从解析阶段已经打开的根能力读取规范清单，不根据 generation 路径重新打开。
#[doc(hidden)]
pub fn load_manifest_from_roots(
    roots: &TrustedPackageRoots,
    root: &Path,
) -> Result<Manifest, ManifestError> {
    let canonical_root = roots
        .exact_root_identity(root)
        .ok_or_else(|| manifest_error(root, None, "包根不属于解析阶段的目录能力"))?
        .to_path_buf();
    let path = canonical_root.join(MANIFEST_NAME);
    let resolved = roots
        .resolve_existing_file(&path, PackagePathPurpose::ManifestReference)
        .map_err(|error| package_path_manifest_error(&path, error))?
        .ok_or_else(|| manifest_error(&path, None, "规范包清单不属于已打开的包根"))?;
    let bytes = read_resolved_regular_file_snapshot(resolved, MANIFEST_MAX_BYTES, "规范包清单")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| manifest_error(&path, None, format!("规范包清单不是 UTF-8：{error}")))?;
    parse(text, path, canonical_root)
}

/// 从调用方已经在可信根内绑定的规范清单句柄解析包，不再按路径重新打开。
#[doc(hidden)]
pub fn load_manifest_from_resolved_file(
    resolved: ResolvedPackageFile,
    root: &Path,
) -> Result<Manifest, ManifestError> {
    let path = resolved.path().to_path_buf();
    if path.file_name().is_none_or(|name| name != MANIFEST_NAME)
        || path.parent().is_none_or(|parent| parent != root)
    {
        return Err(manifest_error(
            &path,
            None,
            "已打开的包清单必须是所属包根下的规范清单",
        ));
    }
    let bytes = read_resolved_regular_file_snapshot(resolved, MANIFEST_MAX_BYTES, "规范包清单")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| manifest_error(&path, None, format!("规范包清单不是 UTF-8：{error}")))?;
    parse(text, path, root.to_path_buf())
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
    resolve_dependency_scoped_with_capabilities(package_root, current_base, name)
        .map(|(dependency, _)| dependency)
}

/// 解析依赖并返回与缓存校验、内容 generation 相同的已打开目录能力。
#[doc(hidden)]
pub fn resolve_dependency_scoped_with_capabilities(
    package_root: Option<&Path>,
    current_base: &Path,
    name: &str,
) -> Result<(ResolvedDependency, ResolutionCapabilities), ManifestError> {
    resolve_dependency_scoped_with_capabilities_inner(None, None, package_root, current_base, name)
}

/// 解析目录工具中的包依赖，并证明解析实际使用的应用根就是发现阶段的根能力。
#[doc(hidden)]
pub fn resolve_dependency_scoped_with_opened_capabilities(
    opened_roots: &TrustedPackageRoots,
    package_root: Option<&Path>,
    current_base: &Path,
    name: &str,
) -> Result<(ResolvedDependency, ResolutionCapabilities), ManifestError> {
    let expected_root = package_root
        .or_else(|| opened_roots.matching_root(current_base))
        .ok_or_else(|| manifest_error(current_base, None, "工具模块没有发现阶段的包根能力"))?;
    if !opened_roots
        .revalidate_exact_root(expected_root)
        .map_err(|error| package_path_manifest_error(expected_root, error))?
    {
        return Err(manifest_error(
            expected_root,
            None,
            "工具包根在目录发现后被替换；拒绝重新解析包依赖",
        ));
    }
    let manifest = load_manifest_from_roots(opened_roots, expected_root).map_err(|error| {
        if error.message == "规范包清单不属于已打开的包根" {
            manifest_error(
                current_base,
                None,
                format!("引用包“{name}”时未找到 {MANIFEST_NAME}"),
            )
        } else {
            error
        }
    })?;
    resolve_dependency_scoped_with_capabilities_inner(
        Some(opened_roots),
        Some(manifest),
        package_root,
        current_base,
        name,
    )
}

/// 按真实包名选择当前模块所属的锁定包自身或它的直接锁定依赖，并返回解析阶段
/// 已经打开的 generation 能力。该入口不改写锁文件；路径在选择前后都必须与
/// 顶层执行建立的根能力保持同一身份。
#[doc(hidden)]
pub fn resolve_native_dependency_scoped_with_opened_capabilities(
    opened_roots: &TrustedPackageRoots,
    package_root: Option<&Path>,
    current_base: &Path,
    package_name: &str,
) -> Result<(ResolvedDependency, ResolutionCapabilities), ManifestError> {
    validate_package_name(package_name)
        .map_err(|message| manifest_error(current_base, None, message))?;
    let expected_root = package_root
        .or_else(|| opened_roots.matching_root(current_base))
        .ok_or_else(|| manifest_error(current_base, None, "当前模块没有执行阶段的包根能力"))?;
    let current_root_identity = opened_roots
        .matching_root_identity(current_base)
        .ok_or_else(|| manifest_error(current_base, None, "当前模块不属于执行阶段的包根能力"))?;
    if !opened_roots
        .revalidate_exact_root(expected_root)
        .map_err(|error| package_path_manifest_error(expected_root, error))?
    {
        return Err(manifest_error(
            expected_root,
            None,
            "应用包根在执行开始后被替换；拒绝解析原生扩展",
        ));
    }
    let manifest = load_manifest_from_roots(opened_roots, expected_root).map_err(|error| {
        if error.message == "规范包清单不属于已打开的包根" {
            manifest_error(
                current_base,
                None,
                format!("装载原生包“{package_name}”时未找到 {MANIFEST_NAME}"),
            )
        } else {
            error
        }
    })?;
    let offline = std::env::var_os("YANXU_OFFLINE").is_some();
    let resolved = cached_or_resolve_graph_read_only(&manifest, offline)?;
    let expected_application_root = opened_roots
        .exact_root_identity(&resolved.application_root)
        .is_some();
    let mut combined = opened_roots.clone();
    let same_identity = combined.extend_opened(&resolved.application_roots).is_ok();
    if !expected_application_root || !same_identity {
        return Err(manifest_error(
            &resolved.application_root,
            None,
            "应用包根在执行开始后被替换；拒绝解析原生扩展",
        ));
    }
    cache_graph(&manifest, resolved.clone());

    let owner = dependency_for_bound_current_root(&resolved, &manifest, current_root_identity)?;
    if let Some(owner) = owner
        && owner.locked.name == package_name
    {
        return Ok((owner.clone(), resolved.capabilities));
    }
    let dependency_edges = owner.map_or(&resolved.graph.root_dependencies, |dependency| {
        &dependency.locked.dependencies
    });
    let mut seen = BTreeSet::new();
    let mut matches = Vec::new();
    for id in dependency_edges.values() {
        if !seen.insert(id) {
            continue;
        }
        let dependency = resolved.graph.packages.get(id).ok_or_else(|| {
            manifest_error(
                manifest.root.join(LOCK_NAME),
                None,
                format!("锁文件依赖边指向不存在的包“{id}”"),
            )
        })?;
        if dependency.locked.name == package_name {
            matches.push(dependency.clone());
        }
    }
    let dependency = match matches.len() {
        1 => matches.pop().expect("one direct native dependency"),
        0 => {
            return Err(manifest_error(
                &manifest.path,
                None,
                format!("当前包没有直接声明名为“{package_name}”的锁定依赖"),
            ));
        }
        _ => {
            return Err(manifest_error(
                &manifest.path,
                None,
                format!("当前包直接依赖多个名为“{package_name}”的包，不能消歧"),
            ));
        }
    };
    Ok((dependency, resolved.capabilities))
}

fn dependency_for_bound_current_root<'a>(
    resolved: &'a ResolvedGraphBundle,
    manifest: &Manifest,
    current_root: &Path,
) -> Result<Option<&'a ResolvedDependency>, ManifestError> {
    if current_root == resolved.application_root || current_root == manifest.root {
        return Ok(None);
    }
    let mut owners = resolved.graph.packages.values().filter(|dependency| {
        dependency.root == current_root
            || resolved
                .inputs
                .iter()
                .find(|input| input.package_id == dependency.locked.id)
                .is_some_and(|input| {
                    input.source_root == current_root || input.generation_root == current_root
                })
    });
    let owner = owners.next().ok_or_else(|| {
        manifest_error(
            current_root,
            None,
            "当前模块的包根身份不属于已验证依赖图；拒绝解析锁定依赖",
        )
    })?;
    if owners.next().is_some() {
        return Err(manifest_error(
            current_root,
            None,
            "当前模块的包根身份对应多个锁定包；拒绝解析锁定依赖",
        ));
    }
    Ok(Some(owner))
}

fn dependency_edges_for_current_base<'a>(
    resolved: &'a ResolvedGraphBundle,
    manifest: &Manifest,
    current_base: &Path,
) -> &'a BTreeMap<String, String> {
    let canonical_base =
        fs::canonicalize(current_base).unwrap_or_else(|_| current_base.to_path_buf());
    let canonical_manifest_root =
        fs::canonicalize(&manifest.root).unwrap_or_else(|_| manifest.root.clone());
    let current_is_application_source = canonical_base.starts_with(&canonical_manifest_root);
    resolved
        .graph
        .packages
        .values()
        .filter(|dependency| {
            let source_root = resolved
                .inputs
                .iter()
                .find(|input| input.package_id == dependency.locked.id)
                .map_or(dependency.root.as_path(), |input| {
                    input.source_root.as_path()
                });
            (canonical_base.starts_with(&dependency.root)
                || canonical_base.starts_with(source_root))
                && (!current_is_application_source
                    || (source_root != canonical_manifest_root
                        && source_root.starts_with(&canonical_manifest_root)))
        })
        .max_by_key(|dependency| {
            resolved
                .inputs
                .iter()
                .find(|input| input.package_id == dependency.locked.id)
                .map_or_else(
                    || dependency.root.components().count(),
                    |input| input.source_root.components().count(),
                )
        })
        .map_or(&resolved.graph.root_dependencies, |dependency| {
            &dependency.locked.dependencies
        })
}

fn resolve_dependency_scoped_with_capabilities_inner(
    opened_roots: Option<&TrustedPackageRoots>,
    bound_manifest: Option<Manifest>,
    package_root: Option<&Path>,
    current_base: &Path,
    name: &str,
) -> Result<(ResolvedDependency, ResolutionCapabilities), ManifestError> {
    let manifest = match bound_manifest {
        Some(manifest) => manifest,
        None => match package_root {
            Some(root) => discover(root)?,
            None => discover(current_base)?,
        }
        .ok_or_else(|| {
            manifest_error(
                current_base,
                None,
                format!("引用包“{name}”时未找到 {MANIFEST_NAME}"),
            )
        })?,
    };
    let offline = std::env::var_os("YANXU_OFFLINE").is_some();
    let resolved = if opened_roots.is_some() {
        cached_or_resolve_graph_read_only(&manifest, offline)?
    } else {
        cached_or_resolve_graph(&manifest, offline)?
    };
    if let Some(opened_roots) = opened_roots {
        let expected_root = opened_roots
            .exact_root_identity(&resolved.application_root)
            .is_some();
        let mut combined = opened_roots.clone();
        let same_identity = combined.extend_opened(&resolved.application_roots).is_ok();
        if !expected_root || !same_identity {
            return Err(manifest_error(
                &resolved.application_root,
                None,
                "工具包根在目录发现后被替换；拒绝重新解析包依赖",
            ));
        }
        cache_graph(&manifest, resolved.clone());
    }
    let graph = &resolved.graph;
    let (alias, export) = name
        .split_once('/')
        .map_or((name, None), |(alias, export)| (alias, Some(export)));
    let dependency_edges = if let Some(opened_roots) = opened_roots {
        let current_root = opened_roots
            .matching_root_identity(current_base)
            .ok_or_else(|| {
                manifest_error(current_base, None, "当前模块不属于发现阶段的包根能力")
            })?;
        dependency_for_bound_current_root(&resolved, &manifest, current_root)?
            .map_or(&graph.root_dependencies, |dependency| {
                &dependency.locked.dependencies
            })
    } else {
        dependency_edges_for_current_base(&resolved, &manifest, current_base)
    };
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
    let mut roots = TrustedPackageRoots::default();
    resolved
        .capabilities
        .extend(&mut roots)
        .map_err(|error| package_path_manifest_error(&dependency.root, error))?;
    let requested_entry = dependency.root.join(exported);
    let entry = roots
        .resolve_existing_module_path(&requested_entry)
        .map_err(|error| package_path_manifest_error(&requested_entry, error))?
        .ok_or_else(|| {
            manifest_error(
                &requested_entry,
                None,
                "锁定包导出模块不属于解析阶段的不可变 generation",
            )
        })?;
    roots
        .authorize_module(&entry, &entry)
        .map_err(|error| package_path_manifest_error(&entry, error))?;
    dependency.entry = entry;
    Ok((dependency, resolved.capabilities))
}

/// 解析全部依赖并写入或验证 `言序.lock`。
pub fn ensure_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let resolved = resolve_graph_mode(manifest, offline, true, true)?;
    let graph = resolved.graph.clone();
    cache_graph(manifest, resolved);
    direct_dependencies(&graph, &graph.root_dependencies, &manifest.path)
}

pub fn ensure_lock_with_dev(
    manifest: &Manifest,
    offline: bool,
) -> Result<ResolutionGraph, ManifestError> {
    let resolved = resolve_graph_mode(manifest, offline, true, true)?;
    let graph = resolved.graph.clone();
    cache_graph(manifest, resolved);
    Ok(graph)
}

pub fn resolve_graph(manifest: &Manifest, offline: bool) -> Result<ResolutionGraph, ManifestError> {
    resolve_graph_mode(manifest, offline, true, true).map(|resolved| resolved.graph)
}

/// 解析公开依赖图并同时返回其 generation 的已打开目录能力。
#[doc(hidden)]
pub fn resolve_graph_with_capabilities(
    manifest: &Manifest,
    offline: bool,
) -> Result<(ResolutionGraph, ResolutionCapabilities), ManifestError> {
    let resolved = resolve_graph_mode(manifest, offline, true, true)?;
    Ok((resolved.graph, resolved.capabilities))
}

/// 在不改写锁文件和运行时图缓存的前提下重新选择依赖，用于更新预演。
pub fn plan_update(manifest: &Manifest, offline: bool) -> Result<ResolutionGraph, ManifestError> {
    resolve_graph_mode(manifest, offline, false, false).map(|resolved| resolved.graph)
}

fn resolve_graph_mode(
    manifest: &Manifest,
    offline: bool,
    use_existing: bool,
    write: bool,
) -> Result<ResolvedGraphBundle, ManifestError> {
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
) -> Result<ResolvedGraphBundle, ManifestError> {
    let (application_root, application_roots, manifest_checksum) =
        bind_resolution_manifest(manifest)?;
    resolve_graph_mode_locked_with_checksum(
        manifest,
        offline,
        use_existing,
        write,
        manifest_checksum,
        application_root,
        application_roots,
    )
}

fn resolve_graph_mode_locked_with_checksum(
    manifest: &Manifest,
    offline: bool,
    use_existing: bool,
    write: bool,
    manifest_checksum: String,
    application_root: PathBuf,
    application_roots: TrustedPackageRoots,
) -> Result<ResolvedGraphBundle, ManifestError> {
    let lock_path = manifest.root.join(LOCK_NAME);
    let observed_lock = use_existing
        .then(|| read_optional_lock(&lock_path))
        .transpose()?
        .flatten();
    let existing = observed_lock.as_ref().filter(|lock| {
        lock.lock_version == LOCK_FORMAT_VERSION
            && lock.manifest_checksum == manifest_checksum
            && lock.target == current_target()
    });
    let mut builder = GraphBuilder {
        offline,
        existing,
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
        manifest_checksum: manifest_checksum.clone(),
        target: graph.target.clone(),
        generator: package_core_version(),
        root_dependencies: graph.root_dependencies.clone(),
        root_dev_dependencies: graph.root_dev_dependencies.clone(),
        packages,
    };
    if write && existing != Some(&lock) {
        write_lock(&lock_path, &lock)?;
    }
    let expected_lock = if write {
        Some(&lock)
    } else {
        observed_lock.as_ref()
    };
    freeze_resolution_graph(
        manifest,
        graph,
        manifest_checksum,
        application_root,
        application_roots,
        expected_lock,
    )
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
    let resolved = resolve_graph_mode_locked(manifest, offline, true, true).map_err(E::from)?;
    let graph = resolved.graph.clone();
    cache_graph(manifest, resolved);
    operation(graph)
}

/// 与项目锁一起把解析图和同一批已打开 generation 能力交给构建消费者。
#[doc(hidden)]
pub fn with_locked_resolution_capabilities<T, E>(
    manifest: &Manifest,
    offline: bool,
    operation: impl FnOnce(ResolutionGraph, ResolutionCapabilities) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<ManifestError>,
{
    let _project_lock = acquire_project_lock(&manifest.root).map_err(E::from)?;
    let resolved = resolve_graph_mode_locked(manifest, offline, true, true).map_err(E::from)?;
    let graph = resolved.graph.clone();
    let capabilities = resolved.capabilities.clone();
    cache_graph(manifest, resolved);
    operation(graph, capabilities)
}

pub fn update_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let resolved = resolve_graph_mode(manifest, offline, false, true)?;
    let graph = resolved.graph.clone();
    cache_graph(manifest, resolved);
    direct_dependencies(&graph, &graph.root_dependencies, &manifest.path)
}

pub fn read_lock(path: impl AsRef<Path>) -> Result<LockFile, ManifestError> {
    let path = path.as_ref();
    let bytes = read_stable_metadata_file_snapshot(path, LOCK_MAX_BYTES, "锁文件")?;
    let text = String::from_utf8(bytes)
        .map_err(|error| manifest_error(path, None, format!("锁文件不是 UTF-8：{error}")))?;
    parse_lock_text(path, &text)
}

fn parse_lock_text(path: &Path, text: &str) -> Result<LockFile, ManifestError> {
    let lock: LockFile = toml::from_str(text)
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
    let manifest_bytes =
        read_stable_metadata_file_snapshot(&manifest.path, MANIFEST_MAX_BYTES, "包清单")?;
    let checksum = format!("{:x}", Sha256::digest(&manifest_bytes));
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
    let manifest_path = manifest_path.as_ref();
    if let Some(dependency) = dependency {
        validate_dependency_source_security(dependency)
            .map_err(|message| manifest_error(manifest_path, None, message))?;
    }
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let _project_lock = acquire_project_lock(root)?;
    let original = String::from_utf8(read_stable_metadata_file_snapshot(
        manifest_path,
        MANIFEST_MAX_BYTES,
        "包清单",
    )?)
    .map_err(|error| manifest_error(manifest_path, None, format!("包清单不是 UTF-8：{error}")))?;
    parse(&original, manifest_path.to_path_buf(), root.to_path_buf())?;
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
    let original = String::from_utf8(read_stable_metadata_file_snapshot(
        manifest_path,
        MANIFEST_MAX_BYTES,
        "包清单",
    )?)
    .map_err(|error| manifest_error(manifest_path, None, format!("包清单不是 UTF-8：{error}")))?;
    parse(&original, manifest_path.to_path_buf(), root.to_path_buf())?;
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

static GRAPH_CACHE: OnceLock<Mutex<HashMap<PathBuf, ResolvedGraphBundle>>> = OnceLock::new();

fn graph_cache() -> &'static Mutex<HashMap<PathBuf, ResolvedGraphBundle>> {
    GRAPH_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn graph_cache_key(root: &Path) -> PathBuf {
    fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

fn cache_graph(manifest: &Manifest, resolved: ResolvedGraphBundle) {
    graph_cache()
        .lock()
        .expect("graph cache poisoned")
        .insert(graph_cache_key(&manifest.root), resolved);
}

fn cached_or_resolve_graph(
    manifest: &Manifest,
    offline: bool,
) -> Result<ResolvedGraphBundle, ManifestError> {
    cached_or_resolve_graph_mode(manifest, offline, true)
}

fn cached_or_resolve_graph_read_only(
    manifest: &Manifest,
    offline: bool,
) -> Result<ResolvedGraphBundle, ManifestError> {
    cached_or_resolve_graph_mode(manifest, offline, false)
}

fn cached_or_resolve_graph_mode(
    manifest: &Manifest,
    offline: bool,
    write: bool,
) -> Result<ResolvedGraphBundle, ManifestError> {
    let key = graph_cache_key(&manifest.root);
    let cached = graph_cache()
        .lock()
        .expect("graph cache poisoned")
        .get(&key)
        .cloned();
    if let Some(resolved) = cached {
        if validate_cached_resolution(&resolved)? {
            return Ok(resolved);
        }
        return Err(manifest_error(
            &manifest.path,
            None,
            "依赖图缓存的应用根、清单、锁文件、目标、来源树或不可变 generation 已改变；请显式运行 yanbao install 或 yanbao update",
        ));
    }
    let current = if write {
        load(&manifest.path)?
    } else {
        manifest.clone()
    };
    let resolved = resolve_graph_mode(&current, offline, true, write)?;
    if write {
        cache_graph(&current, resolved.clone());
    }
    Ok(resolved)
}

fn bound_file_snapshot(
    roots: &TrustedPackageRoots,
    path: &Path,
    purpose: PackagePathPurpose,
    max_bytes: u64,
    kind: &str,
) -> Result<Vec<u8>, ManifestError> {
    let resolved = roots
        .resolve_existing_file(path, purpose)
        .map_err(|error| package_path_manifest_error(path, error))?
        .ok_or_else(|| manifest_error(path, None, format!("{kind}不属于已打开的包根")))?;
    read_resolved_regular_file_snapshot(resolved, max_bytes, kind)
}

fn bound_file_checksum(
    roots: &TrustedPackageRoots,
    path: &Path,
    purpose: PackagePathPurpose,
    max_bytes: u64,
    kind: &str,
) -> Result<String, ManifestError> {
    let bytes = bound_file_snapshot(roots, path, purpose, max_bytes, kind)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn bind_resolution_manifest(
    manifest: &Manifest,
) -> Result<(PathBuf, TrustedPackageRoots, String), ManifestError> {
    let mut application_roots = TrustedPackageRoots::new();
    application_roots
        .insert(&manifest.root)
        .map_err(|error| package_path_manifest_error(&manifest.path, error))?;
    let application_root = application_roots
        .exact_root_identity(&manifest.root)
        .ok_or_else(|| manifest_error(&manifest.root, None, "不能绑定应用包根能力"))?
        .to_path_buf();
    let bound_manifest_path = application_root.join(MANIFEST_NAME);
    let caller_manifest_path = fs::canonicalize(&manifest.path).map_err(|error| {
        manifest_error(
            &manifest.path,
            None,
            format!("不能定位调用方包清单：{error}"),
        )
    })?;
    let canonical_manifest_path = fs::canonicalize(&bound_manifest_path).map_err(|error| {
        manifest_error(
            &bound_manifest_path,
            None,
            format!("不能定位规范包清单：{error}"),
        )
    })?;
    if caller_manifest_path != canonical_manifest_path {
        return Err(manifest_error(
            &manifest.path,
            None,
            format!("依赖解析只能使用包根目录中的规范清单 {MANIFEST_NAME}"),
        ));
    }
    let bytes = bound_file_snapshot(
        &application_roots,
        &bound_manifest_path,
        PackagePathPurpose::ManifestReference,
        MANIFEST_MAX_BYTES,
        "包清单",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        manifest_error(
            &bound_manifest_path,
            None,
            format!("规范包清单不是 UTF-8：{error}"),
        )
    })?;
    let current = parse(text, manifest.path.clone(), manifest.root.clone())?;
    if current != *manifest {
        return Err(manifest_error(
            &manifest.path,
            None,
            "包清单在调用方读取后发生变化；请重新加载清单并重试",
        ));
    }
    Ok((
        application_root,
        application_roots,
        format!("{:x}", Sha256::digest(&bytes)),
    ))
}

fn freeze_resolution_graph(
    manifest: &Manifest,
    mut graph: ResolutionGraph,
    manifest_checksum: String,
    application_root: PathBuf,
    application_roots: TrustedPackageRoots,
    expected_lock: Option<&LockFile>,
) -> Result<ResolvedGraphBundle, ManifestError> {
    let bound_manifest_path = application_root.join(MANIFEST_NAME);
    let bound_manifest_bytes = bound_file_snapshot(
        &application_roots,
        &bound_manifest_path,
        PackagePathPurpose::ManifestReference,
        MANIFEST_MAX_BYTES,
        "包清单",
    )?;
    let bound_manifest_checksum = format!("{:x}", Sha256::digest(&bound_manifest_bytes));
    if bound_manifest_checksum != manifest_checksum {
        return Err(manifest_error(
            &manifest.path,
            None,
            "包清单在依赖解析期间发生变化；请重试",
        ));
    }
    let bound_manifest_text = std::str::from_utf8(&bound_manifest_bytes).map_err(|error| {
        manifest_error(
            &bound_manifest_path,
            None,
            format!("规范包清单不是 UTF-8：{error}"),
        )
    })?;
    let bound_manifest = parse(
        bound_manifest_text,
        manifest.path.clone(),
        manifest.root.clone(),
    )?;
    if bound_manifest != *manifest {
        return Err(manifest_error(
            &manifest.path,
            None,
            "包清单在依赖解析期间改变了结构；请重试",
        ));
    }

    let lock_path = application_root.join(LOCK_NAME);
    let lock_checksum = match expected_lock {
        Some(expected) => {
            let bytes = bound_file_snapshot(
                &application_roots,
                &lock_path,
                PackagePathPurpose::YxpEntry,
                LOCK_MAX_BYTES,
                "锁文件",
            )?;
            let text = std::str::from_utf8(&bytes).map_err(|error| {
                manifest_error(&lock_path, None, format!("锁文件不是 UTF-8：{error}"))
            })?;
            let current = parse_lock_text(&lock_path, text)?;
            if &current != expected {
                return Err(manifest_error(
                    &lock_path,
                    None,
                    "锁文件在依赖解析期间改变了结构；请重试",
                ));
            }
            Some(format!("{:x}", Sha256::digest(&bytes)))
        }
        None => None,
    };

    let mut capabilities = application_roots.clone();
    let mut inputs = Vec::with_capacity(graph.packages.len());
    for (package_id, dependency) in &mut graph.packages {
        let source_root = dependency.root.clone();
        let source_entry = dependency.entry.clone();
        let mut source_roots = TrustedPackageRoots::new();
        source_roots
            .insert(&source_root)
            .map_err(|error| package_path_manifest_error(&source_root, error))?;
        let snapshot = capture_package_tree_in(
            &source_roots,
            &source_root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        )?;
        if !tree_snapshot_checksum_matches(&snapshot, &dependency.locked.checksum)? {
            return Err(manifest_error(
                &source_root,
                None,
                format!(
                    "依赖“{}”在锁定校验后发生变化；拒绝创建可执行 generation",
                    dependency.locked.name
                ),
            ));
        }
        let checksum = portable_tree_snapshot_checksum(&snapshot)?;
        let generation_root = publish_resolution_generation(&snapshot, &checksum)?;
        let generation_roots = validate_resolution_generation(
            &generation_root,
            &checksum,
            &dependency.locked,
            &graph.target,
        )?;
        let entry_relative = source_entry.strip_prefix(&source_root).map_err(|_| {
            manifest_error(&source_entry, None, "锁定导出入口不属于经过校验的依赖根")
        })?;
        dependency.root.clone_from(&generation_root);
        dependency.entry = generation_root.join(entry_relative);
        capabilities
            .extend_opened(&generation_roots)
            .map_err(|error| package_path_manifest_error(&generation_root, error))?;
        inputs.push(ResolutionInputFingerprint {
            package_id: package_id.clone(),
            source_root,
            source_roots,
            generation_root,
            generation_roots,
            checksum,
        });
    }

    if !application_roots
        .revalidate_exact_root(&application_root)
        .unwrap_or(false)
    {
        return Err(manifest_error(
            &application_root,
            None,
            "应用包根在依赖解析期间被替换；请重试",
        ));
    }

    Ok(ResolvedGraphBundle {
        graph,
        capabilities: ResolutionCapabilities {
            roots: capabilities,
        },
        application_root,
        application_roots,
        manifest_checksum,
        lock_checksum,
        inputs,
    })
}

fn validate_cached_resolution(resolved: &ResolvedGraphBundle) -> Result<bool, ManifestError> {
    if resolved.graph.target != current_target()
        || !resolved
            .application_roots
            .revalidate_exact_root(&resolved.application_root)
            .unwrap_or(false)
    {
        return Ok(false);
    }
    let manifest_path = resolved.application_root.join(MANIFEST_NAME);
    if bound_file_checksum(
        &resolved.application_roots,
        &manifest_path,
        PackagePathPurpose::ManifestReference,
        MANIFEST_MAX_BYTES,
        "包清单",
    )
    .ok()
    .as_deref()
        != Some(resolved.manifest_checksum.as_str())
    {
        return Ok(false);
    }
    let lock_path = resolved.application_root.join(LOCK_NAME);
    let current_lock = bound_file_checksum(
        &resolved.application_roots,
        &lock_path,
        PackagePathPurpose::YxpEntry,
        LOCK_MAX_BYTES,
        "锁文件",
    )
    .ok();
    if current_lock != resolved.lock_checksum {
        return Ok(false);
    }
    for input in &resolved.inputs {
        if !input
            .source_roots
            .revalidate_exact_root(&input.source_root)
            .unwrap_or(false)
            || !input
                .generation_roots
                .revalidate_exact_root(&input.generation_root)
                .unwrap_or(false)
        {
            return Ok(false);
        }
        let source = capture_package_tree_in(
            &input.source_roots,
            &input.source_root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        );
        let generation = capture_package_tree_in(
            &input.generation_roots,
            &input.generation_root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        );
        if source
            .and_then(|snapshot| portable_tree_snapshot_checksum(&snapshot))
            .ok()
            .as_deref()
            != Some(input.checksum.as_str())
            || generation
                .and_then(|snapshot| portable_tree_snapshot_checksum(&snapshot))
                .ok()
                .as_deref()
                != Some(input.checksum.as_str())
        {
            return Ok(false);
        }
    }
    Ok(true)
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
    let exact_requested = exact_git_commit(revision);
    if offline && !exact_requested {
        return Err(manifest_error(
            "Git 来源",
            None,
            "离线模式只接受锁文件中的 40 位精确 Git 提交；请先联网完成依赖锁定",
        ));
    }

    let cache = git_cache_layout_root()?;
    let identity = git_cache_identity(url);
    let _lock = acquire_git_cache_lock(&cache, &identity)?;
    let url_root = create_checked_cache_directory(&cache, &identity, "Git 来源缓存")?;
    let (existing_store, invalid_store) = find_git_object_store(&url_root)?;
    let (store, exact) = match existing_store {
        Some(store) => {
            let exact = if exact_requested && git_commit_exists(&store, revision)? {
                git_exact_revision(&store, revision)?
            } else if offline {
                let url = safe_git_source_value_for_display(url);
                let revision = safe_git_revision_for_display(revision);
                return Err(manifest_error(
                    &url_root,
                    None,
                    format!("离线模式下未缓存 Git 依赖 {url}@{revision}"),
                ));
            } else {
                fetch_git_revision(&store, url, revision)?
            };
            validate_git_object_store(&store)?;
            (store, exact)
        }
        None if offline => {
            if let Some(error) = invalid_store {
                return Err(error);
            }
            let url = safe_git_source_value_for_display(url);
            let revision = safe_git_revision_for_display(revision);
            return Err(manifest_error(
                &url_root,
                None,
                format!("离线模式下未缓存 Git 依赖 {url}@{revision}"),
            ));
        }
        None => create_git_object_store(&url_root, url, revision)?,
    };
    if !exact_git_commit(&exact) {
        return Err(manifest_error(
            &store,
            None,
            "Git 没有返回 40 位精确提交，拒绝建立依赖 generation",
        ));
    }
    let snapshot = capture_git_commit_snapshot(&store, &url_root, &exact)?;
    let generation = publish_git_generation(&url_root, &exact, &snapshot)?;
    Ok((generation, exact))
}

fn git_cache_identity(url: &str) -> String {
    format!("{:x}", Sha256::digest(url.as_bytes()))
}

fn exact_git_commit(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn create_checked_cache_directory(
    parent: &Path,
    component: &str,
    kind: &str,
) -> Result<PathBuf, ManifestError> {
    let relative = Path::new(component);
    if relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        return Err(manifest_error(
            parent,
            None,
            format!("{kind}组件不是单一普通路径名"),
        ));
    }
    let path = parent.join(component);
    let created = match fs::create_dir(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(manifest_error(
                &path,
                None,
                format!("不能创建{kind}：{error}"),
            ));
        }
    };
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| manifest_error(&path, None, format!("不能检查{kind}：{error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &path,
            None,
            format!("{kind}不得为链接、重解析点或特殊文件"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions)
            .map_err(|error| manifest_error(&path, None, format!("不能收紧{kind}权限：{error}")))?;
    }
    if created {
        sync_registry_directory_parent(&path)?;
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| manifest_error(parent, None, format!("不能定位{kind}父目录：{error}")))?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| manifest_error(&path, None, format!("不能定位{kind}：{error}")))?;
    if !canonical.starts_with(canonical_parent) {
        return Err(manifest_error(&path, None, format!("{kind}越出缓存边界")));
    }
    Ok(canonical)
}

fn git_cache_layout_root() -> Result<PathBuf, ManifestError> {
    let root = cache_root();
    fs::create_dir_all(&root)
        .map_err(|error| manifest_error(&root, None, format!("不能创建 Git 缓存根：{error}")))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| manifest_error(&root, None, format!("不能检查 Git 缓存根：{error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &root,
            None,
            "Git 缓存根不得为链接、重解析点或特殊文件",
        ));
    }
    let root = fs::canonicalize(&root)
        .map_err(|error| manifest_error(&root, None, format!("不能定位 Git 缓存根：{error}")))?;
    let git = create_checked_cache_directory(&root, "git", "Git 缓存目录")?;
    create_checked_cache_directory(&git, GIT_CACHE_LAYOUT, "Git 缓存布局目录")
}

fn reject_invalid_existing_cache_directory(path: &Path, kind: &str) -> Result<(), ManifestError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || standard_metadata_is_reparse(&metadata) =>
        {
            Err(manifest_error(
                path,
                None,
                format!("{kind}不得为链接、重解析点或特殊文件"),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(manifest_error(
            path,
            None,
            format!("不能检查{kind}：{error}"),
        )),
    }
}

fn acquire_git_cache_lock(
    cache: &Path,
    identity: &str,
) -> Result<crate::storage::ProjectLock, ManifestError> {
    let locks = cache.join(".locks");
    let lock_root = locks.join(identity);
    reject_invalid_existing_cache_directory(&locks, "Git 缓存锁目录")?;
    reject_invalid_existing_cache_directory(&lock_root, "Git 缓存锁组件")?;
    reject_invalid_existing_cache_directory(&lock_root.join(".yanxu"), "Git 缓存锁状态")?;
    let lock = crate::storage::ProjectLock::acquire_under(cache, &[".locks", identity]).map_err(
        |error| {
            manifest_error(
                &lock_root,
                None,
                format!("不能取得 Git 来源缓存锁：{error}"),
            )
        },
    )?;
    for directory in [&locks, &lock_root, &lock_root.join(".yanxu")] {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            manifest_error(directory, None, format!("不能复验 Git 缓存锁组件：{error}"))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                directory,
                None,
                "Git 缓存锁组件不得为链接、重解析点或特殊文件",
            ));
        }
    }
    let lock_file = lock_root.join(".yanxu/package.lock");
    let metadata = fs::symlink_metadata(&lock_file).map_err(|error| {
        manifest_error(
            &lock_file,
            None,
            format!("不能复验 Git 缓存锁文件：{error}"),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &lock_file,
            None,
            "Git 缓存锁文件不得为链接、重解析点或特殊文件",
        ));
    }
    let canonical = fs::canonicalize(&lock_root).map_err(|error| {
        manifest_error(&lock_root, None, format!("不能定位 Git 缓存锁：{error}"))
    })?;
    if !canonical.starts_with(cache) {
        return Err(manifest_error(&lock_root, None, "Git 缓存锁越出缓存边界"));
    }
    Ok(lock)
}

fn hardened_git_command() -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "file:https:ssh:git+ssh")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_NAMESPACE");
    command
}

fn git_store_command(store: &Path) -> Command {
    let mut command = hardened_git_command();
    command
        .arg("-c")
        .arg("core.attributesFile=")
        .arg("--no-optional-locks")
        .arg("--git-dir")
        .arg(store);
    command
}

fn git_command_output(
    command: &mut Command,
    path: &Path,
    action: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ManifestError> {
    let output = bounded_command_output(
        command,
        path,
        action,
        "Git",
        subprocess::CommandBudget {
            timeout: GIT_INSPECT_TIMEOUT,
            stdout_bytes: max_bytes,
            stderr_bytes: GIT_COMMAND_STDERR_MAX_BYTES,
            disk: Some(subprocess::DiskBudget {
                root: path,
                max_bytes: GIT_STORE_MAX_BYTES,
                max_entries: GIT_STORE_MAX_ENTRIES,
                max_depth: GIT_STORE_MAX_DEPTH,
            }),
            cancellation: None,
        },
    )?;
    if !output.status.success() {
        return Err(if let Some(code) = output.status.code() {
            manifest_error(path, None, format!("{action}失败（退出码 {code}）"))
        } else {
            manifest_error(path, None, format!("{action}失败（进程异常终止）"))
        });
    }
    Ok(output.stdout)
}

fn git_exact_revision(store: &Path, revision: &str) -> Result<String, ManifestError> {
    let output = git_command_output(
        git_store_command(store)
            .arg("rev-parse")
            .arg("--verify")
            .arg(format!("{revision}^{{commit}}")),
        store,
        "读取 Git 精确提交",
        128,
    )?;
    let exact = std::str::from_utf8(&output)
        .map_err(|_| manifest_error(store, None, "Git 精确提交输出不是 UTF-8"))?
        .trim()
        .to_ascii_lowercase();
    if !exact_git_commit(&exact) {
        return Err(manifest_error(
            store,
            None,
            "Git 精确提交不是 40 位十六进制",
        ));
    }
    Ok(exact)
}

fn git_commit_exists(store: &Path, revision: &str) -> Result<bool, ManifestError> {
    let output = bounded_command_output(
        git_store_command(store)
            .arg("rev-parse")
            .arg("--verify")
            .arg("--quiet")
            .arg(format!("{revision}^{{commit}}")),
        store,
        "检查 Git 精确提交",
        "Git",
        subprocess::CommandBudget {
            timeout: GIT_INSPECT_TIMEOUT,
            stdout_bytes: 128,
            stderr_bytes: GIT_COMMAND_STDERR_MAX_BYTES,
            disk: Some(subprocess::DiskBudget {
                root: store,
                max_bytes: GIT_STORE_MAX_BYTES,
                max_entries: GIT_STORE_MAX_ENTRIES,
                max_depth: GIT_STORE_MAX_DEPTH,
            }),
            cancellation: None,
        },
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => {
            command_status_result(output, store, "检查 Git 精确提交")?;
            unreachable!("成功和缺失状态已在前面处理")
        }
    }
}

fn fetch_git_revision(store: &Path, url: &str, revision: &str) -> Result<String, ManifestError> {
    run_git_command(
        git_store_command(store)
            .arg("fetch")
            .arg("--quiet")
            .arg("--force")
            .arg("--no-tags")
            .arg("--")
            .arg(url)
            .arg(revision),
        store,
        "获取 Git 修订",
        GIT_FETCH_TIMEOUT,
        Some(subprocess::DiskBudget {
            root: store,
            max_bytes: GIT_STORE_MAX_BYTES,
            max_entries: GIT_STORE_MAX_ENTRIES,
            max_depth: GIT_STORE_MAX_DEPTH,
        }),
    )?;
    git_exact_revision(store, "FETCH_HEAD")
}

fn validate_git_store_config(store: &Path) -> Result<(), ManifestError> {
    let path = store.join("config");
    let file = open_regular_file_for_snapshot(&path).map_err(|error| {
        manifest_error(&path, None, format!("不能打开 Git 对象库配置：{error}"))
    })?;
    let bytes = read_opened_regular_file_snapshot(
        file,
        &path,
        GIT_CONFIG_MAX_BYTES,
        "Git 对象库配置",
        None,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| manifest_error(&path, None, "Git 对象库配置不是 UTF-8"))?;
    let mut section = None;
    let mut repository_format = false;
    let mut bare = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if name != "core" {
                return Err(manifest_error(
                    &path,
                    None,
                    "Git 对象库配置含非 core 节，拒绝可能改变命令行为的本地配置",
                ));
            }
            section = Some(name);
            continue;
        }
        if section.as_deref() != Some("core") || line.ends_with('\\') {
            return Err(manifest_error(&path, None, "Git 对象库配置结构无效"));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| manifest_error(&path, None, "Git 对象库配置项缺少等号"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        match key.as_str() {
            "repositoryformatversion" if value == "0" => repository_format = true,
            "bare" if value == "true" => bare = true,
            "filemode" | "ignorecase" | "precomposeunicode" | "logallrefupdates" | "symlinks"
                if matches!(value.as_str(), "true" | "false") => {}
            _ => {
                return Err(manifest_error(
                    &path,
                    None,
                    format!("Git 对象库配置项 core.{key} 不在安全允许列表中"),
                ));
            }
        }
    }
    if !repository_format || !bare {
        return Err(manifest_error(
            &path,
            None,
            "Git 对象库必须明确使用格式 0 且 bare=true",
        ));
    }
    Ok(())
}

fn validate_git_store_tree(store: &Path) -> Result<(), ManifestError> {
    let metadata = fs::symlink_metadata(store).map_err(|error| {
        manifest_error(store, None, format!("不能检查 Git bare 对象库：{error}"))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            store,
            None,
            "Git bare 对象库不得为链接、重解析点或特殊文件",
        ));
    }
    let mut pending = vec![(store.to_path_buf(), 0_usize)];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some((directory, depth)) = pending.pop() {
        if depth > GIT_STORE_MAX_DEPTH {
            return Err(manifest_error(
                &directory,
                None,
                format!("Git 对象库目录深度超过 {GIT_STORE_MAX_DEPTH}"),
            ));
        }
        for entry in fs::read_dir(&directory).map_err(|error| {
            manifest_error(&directory, None, format!("不能遍历 Git 对象库：{error}"))
        })? {
            let entry = entry.map_err(|error| {
                manifest_error(
                    &directory,
                    None,
                    format!("不能读取 Git 对象库目录项：{error}"),
                )
            })?;
            entries = entries.saturating_add(1);
            if entries > GIT_STORE_MAX_ENTRIES {
                return Err(manifest_error(
                    store,
                    None,
                    format!("Git 对象库条目超过 {GIT_STORE_MAX_ENTRIES}"),
                ));
            }
            let path = entry.path();
            let relative = path
                .strip_prefix(store)
                .expect("Git object store walk remains inside root");
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                manifest_error(&path, None, format!("不能检查 Git 对象库目录项：{error}"))
            })?;
            if metadata.file_type().is_symlink() || standard_metadata_is_reparse(&metadata) {
                return Err(manifest_error(
                    &path,
                    None,
                    "Git 对象库不得包含链接或重解析点",
                ));
            }
            if matches!(
                relative,
                path if path == Path::new("objects/info/alternates")
                    || path == Path::new("objects/info/http-alternates")
                    || path == Path::new("info/attributes")
                    || path == Path::new("packed-refs")
            ) || relative.starts_with("hooks") && metadata.is_file()
                || relative.starts_with("refs") && metadata.is_file()
            {
                return Err(manifest_error(
                    &path,
                    None,
                    "Git 对象库不得包含外部对象替代、仓库级属性、持久引用或可执行 hook",
                ));
            }
            if metadata.is_dir() {
                pending.push((path, depth.saturating_add(1)));
            } else if metadata.is_file() {
                bytes = bytes
                    .checked_add(measured_standard_file_bytes(&metadata))
                    .filter(|bytes| *bytes <= GIT_STORE_MAX_BYTES)
                    .ok_or_else(|| {
                        manifest_error(
                            store,
                            None,
                            format!("Git 对象库内容超过 {GIT_STORE_MAX_BYTES} 字节"),
                        )
                    })?;
            } else {
                return Err(manifest_error(
                    &path,
                    None,
                    "Git 对象库只能包含普通目录和文件",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn measured_standard_file_bytes(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.len().max(metadata.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn measured_standard_file_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

fn validate_git_object_store(store: &Path) -> Result<(), ManifestError> {
    validate_git_store_tree(store)?;
    validate_git_store_config(store)?;
    let head = store.join("HEAD");
    let file = open_regular_file_for_snapshot(&head).map_err(|error| {
        manifest_error(&head, None, format!("不能打开 Git 对象库 HEAD：{error}"))
    })?;
    let head_bytes =
        read_opened_regular_file_snapshot(file, &head, 4_096, "Git 对象库 HEAD", None)?;
    let head_text = std::str::from_utf8(&head_bytes)
        .map_err(|_| manifest_error(&head, None, "Git 对象库 HEAD 不是 UTF-8"))?
        .trim();
    if !head_text.starts_with("ref: refs/heads/") && !exact_git_commit(head_text) {
        return Err(manifest_error(&head, None, "Git 对象库 HEAD 引用无效"));
    }
    let bare = git_command_output(
        git_store_command(store)
            .arg("rev-parse")
            .arg("--is-bare-repository"),
        store,
        "验证 Git bare 对象库",
        32,
    )?;
    if bare != b"true\n" && bare != b"true\r\n" {
        return Err(manifest_error(store, None, "Git 缓存不是 bare 对象库"));
    }
    let format = git_command_output(
        git_store_command(store)
            .arg("rev-parse")
            .arg("--show-object-format"),
        store,
        "验证 Git 对象格式",
        32,
    )?;
    if format != b"sha1\n" && format != b"sha1\r\n" {
        return Err(manifest_error(
            store,
            None,
            "Git 依赖锁当前只支持产生 40 位提交的 SHA-1 对象格式",
        ));
    }
    Ok(())
}

fn find_git_object_store(
    url_root: &Path,
) -> Result<(Option<PathBuf>, Option<ManifestError>), ManifestError> {
    let mut candidates = fs::read_dir(url_root)
        .map_err(|error| {
            manifest_error(url_root, None, format!("不能枚举 Git bare 对象库：{error}"))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            manifest_error(
                url_root,
                None,
                format!("不能读取 Git bare 对象库目录项：{error}"),
            )
        })?;
    candidates.retain(|candidate| {
        let name = candidate.file_name();
        let name = name.to_string_lossy();
        name == "objects.git" || name.starts_with("objects-repair-") && name.ends_with(".git")
    });
    candidates.sort_by_key(|candidate| {
        let name = candidate.file_name();
        let primary = name == "objects.git";
        (!primary, name)
    });
    let mut invalid = None;
    for candidate in candidates {
        let path = candidate.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            manifest_error(
                &path,
                None,
                format!("不能检查 Git bare 对象库候选：{error}"),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                &path,
                None,
                "Git bare 对象库候选不得为链接、重解析点或特殊文件",
            ));
        }
        match validate_git_object_store(&path) {
            Ok(()) => {
                let canonical = fs::canonicalize(&path).map_err(|error| {
                    manifest_error(&path, None, format!("不能定位 Git bare 对象库：{error}"))
                })?;
                if !canonical.starts_with(url_root) {
                    return Err(manifest_error(
                        &path,
                        None,
                        "Git bare 对象库越出来源缓存边界",
                    ));
                }
                return Ok((Some(canonical), invalid));
            }
            Err(error) => {
                invalid.get_or_insert(error);
            }
        }
    }
    Ok((None, invalid))
}

fn git_object_store_destination(url_root: &Path) -> Result<PathBuf, ManifestError> {
    let primary = url_root.join("objects.git");
    match fs::symlink_metadata(&primary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(primary),
        Ok(_) => {}
        Err(error) => {
            return Err(manifest_error(
                &primary,
                None,
                format!("不能检查 Git bare 对象库发布位置：{error}"),
            ));
        }
    }
    for _ in 0..1_024 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let repair = url_root.join(format!(
            "objects-repair-{}-{sequence}.git",
            std::process::id()
        ));
        match fs::symlink_metadata(&repair) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(repair),
            Ok(_) => continue,
            Err(error) => {
                return Err(manifest_error(
                    &repair,
                    None,
                    format!("不能检查 Git bare 对象库修复位置：{error}"),
                ));
            }
        }
    }
    Err(manifest_error(
        url_root,
        None,
        "不能分配唯一 Git bare 对象库发布位置",
    ))
}

fn create_git_object_store(
    url_root: &Path,
    url: &str,
    revision: &str,
) -> Result<(PathBuf, String), ManifestError> {
    let temporary = RegistryTemporaryDirectory::create_within(url_root, url_root, "git-objects")?;
    run_git_command(
        hardened_git_command()
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg("--template=")
            .arg(temporary.path()),
        temporary.path(),
        "初始化 Git bare 对象库",
        GIT_INITIALIZE_TIMEOUT,
        Some(subprocess::DiskBudget {
            root: temporary.path(),
            max_bytes: GIT_INITIALIZE_MAX_BYTES,
            max_entries: 4_096,
            max_depth: 32,
        }),
    )?;
    let exact = fetch_git_revision(temporary.path(), url, revision)?;
    validate_git_object_store(temporary.path())?;
    let destination = git_object_store_destination(url_root)?;
    temporary.publish(&destination)?;
    sync_registry_directory_parent(&destination)?;
    let canonical = fs::canonicalize(&destination).map_err(|error| {
        manifest_error(
            &destination,
            None,
            format!("不能定位已发布 Git bare 对象库：{error}"),
        )
    })?;
    validate_git_object_store(&canonical)?;
    Ok((canonical, exact))
}

fn capture_git_commit_snapshot(
    store: &Path,
    url_root: &Path,
    exact: &str,
) -> Result<PackageTreeSnapshot, ManifestError> {
    let temporary =
        RegistryTemporaryDirectory::create_within(url_root, url_root, "git-materialize")?;
    let archive_path = temporary.path().join("tree.tar");
    run_git_command(
        git_store_command(store)
            .arg("archive")
            .arg("--format=tar")
            .arg("--output")
            .arg(&archive_path)
            .arg(exact),
        store,
        "导出精确 Git 提交",
        GIT_ARCHIVE_TIMEOUT,
        Some(subprocess::DiskBudget {
            root: temporary.path(),
            max_bytes: PACKAGE_TREE_MAX_BYTES,
            max_entries: 16,
            max_depth: 1,
        }),
    )?;
    let archive = open_regular_file_for_snapshot(&archive_path).map_err(|error| {
        manifest_error(
            &archive_path,
            None,
            format!("不能打开 Git 提交归档：{error}"),
        )
    })?;
    let bytes = read_opened_regular_file_snapshot(
        archive,
        &archive_path,
        PACKAGE_TREE_MAX_BYTES,
        "Git 提交归档",
        None,
    )?;
    let unpacked = temporary.path().join("package-source");
    fs::create_dir(&unpacked).map_err(|error| {
        manifest_error(
            &unpacked,
            None,
            format!("不能创建 Git 提交展开目录：{error}"),
        )
    })?;
    extract_tar_bytes_with_limits(
        &bytes,
        &archive_path,
        &unpacked,
        ArchiveLimits {
            compressed_bytes: PACKAGE_TREE_MAX_BYTES,
            file_bytes: PACKAGE_TREE_MAX_FILE_BYTES,
            expanded_bytes: PACKAGE_TREE_MAX_BYTES,
            entries: PACKAGE_TREE_MAX_ENTRIES,
            path_bytes: ARCHIVE_MAX_PATH_BYTES,
            metadata_headers: true,
        },
    )?;
    capture_package_tree(
        &unpacked,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )
}

fn create_git_commit_generation_root(
    url_root: &Path,
    exact: &str,
) -> Result<PathBuf, ManifestError> {
    if !exact_git_commit(exact) {
        return Err(manifest_error(
            url_root,
            None,
            "Git generation 只接受 40 位精确提交",
        ));
    }
    let generations =
        create_checked_cache_directory(url_root, GIT_GENERATION_LAYOUT, "Git generation 布局")?;
    create_checked_cache_directory(&generations, exact, "Git 精确提交 generation")
}

fn existing_git_generation(
    commit_root: &Path,
    checksum: &str,
) -> Result<Option<PathBuf>, ManifestError> {
    let mut candidates = fs::read_dir(commit_root)
        .map_err(|error| {
            manifest_error(
                commit_root,
                None,
                format!("不能枚举 Git generation：{error}"),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            manifest_error(
                commit_root,
                None,
                format!("不能读取 Git generation 目录项：{error}"),
            )
        })?;
    candidates.sort_by_key(fs::DirEntry::file_name);
    for candidate in candidates {
        let path = candidate.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            manifest_error(
                &path,
                None,
                format!("不能检查 Git generation 候选：{error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || standard_metadata_is_reparse(&metadata) {
            return Err(manifest_error(
                &path,
                None,
                "Git generation 不得为链接或重解析点",
            ));
        }
        if candidate.file_name().to_string_lossy().starts_with('.') {
            if !metadata.is_dir() {
                return Err(manifest_error(
                    &path,
                    None,
                    "Git generation 临时项必须是普通目录",
                ));
            }
            continue;
        }
        if !metadata.is_dir() {
            return Err(manifest_error(
                &path,
                None,
                "Git generation 候选必须是普通目录",
            ));
        }
        let root = path.join("package");
        if matches!(resolution_generation_checksum(&root), Ok(actual) if actual == checksum) {
            set_resolution_generation_read_only(&path)?;
            let canonical = fs::canonicalize(&root).map_err(|error| {
                manifest_error(&root, None, format!("不能定位 Git generation：{error}"))
            })?;
            if !canonical.starts_with(commit_root) {
                return Err(manifest_error(
                    &root,
                    None,
                    "Git generation 越出精确提交缓存边界",
                ));
            }
            return Ok(Some(canonical));
        }
    }
    Ok(None)
}

fn publish_git_generation(
    url_root: &Path,
    exact: &str,
    snapshot: &PackageTreeSnapshot,
) -> Result<PathBuf, ManifestError> {
    let checksum = portable_tree_snapshot_checksum(snapshot)?;
    let commit_root = create_git_commit_generation_root(url_root, exact)?;
    if let Some(root) = existing_git_generation(&commit_root, &checksum)? {
        return Ok(root);
    }
    let temporary =
        RegistryTemporaryDirectory::create_within(url_root, &commit_root, "git-generation")?;
    write_resolution_snapshot(snapshot, &temporary.path().join("package"))?;
    let destination = resolution_generation_destination(&commit_root)?;
    temporary.publish(&destination)?;
    sync_registry_directory_parent(&destination)?;
    set_resolution_generation_read_only(&destination)?;
    let root = destination.join("package");
    let actual = resolution_generation_checksum(&root)?;
    if actual != checksum {
        return Err(manifest_error(
            &root,
            None,
            format!("Git generation 发布后摘要改变：预期 {checksum}，实际 {actual}"),
        ));
    }
    let canonical = fs::canonicalize(&root).map_err(|error| {
        manifest_error(
            &root,
            None,
            format!("不能定位已发布 Git generation：{error}"),
        )
    })?;
    if !canonical.starts_with(commit_root) {
        return Err(manifest_error(
            &root,
            None,
            "已发布 Git generation 越出精确提交缓存边界",
        ));
    }
    Ok(canonical)
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

/// 在来源进入网络命令、锁文件或诊断前拒绝内嵌认证信息。
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

/// 校验本地来源路径文本，保留普通文件名中的 `#`。
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

/// 校验 Git 来源的传输类型、认证形状和查询字段。
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

/// 校验索引来源；远程索引只允许 HTTPS，本地路径与 file URL 仍可用。
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

/// 校验索引制品地址；网络制品只允许 HTTPS。
#[doc(hidden)]
pub fn validate_artifact_source_security(source: &str) -> Result<(), &'static str> {
    validate_registry_source_security(source)
}

/// 校验漏洞参考地址；远程参考必须使用 HTTPS。
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
        || revision.starts_with('+')
        || revision.contains('#')
        || revision.contains(':')
        || revision.contains('*')
        || revision.chars().any(char::is_control)
    {
        return Err(GIT_REVISION_ERROR);
    }
    validate_local_source_path_text(revision).map_err(|_| GIT_REVISION_ERROR)
}

/// 判断远程来源是否为不携带内嵌认证信息的 HTTPS URL。
#[doc(hidden)]
pub fn secure_https_source(source: &str) -> bool {
    validate_url_source(source)
        .is_ok_and(|parsed| parsed.scheme() == "https" && parsed.host_str().is_some())
}

/// 校验一个公开依赖声明是否可以安全持久化和显示。
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

/// 返回可用于诊断或结构化输出的来源值；不安全值永远不会部分回显。
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

/// 返回经过本地路径策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_local_source_path_for_display(path: &Path) -> String {
    path.to_str()
        .filter(|source| validate_local_source_path_text(source).is_ok())
        .map(str::to_owned)
        .unwrap_or_else(|| HIDDEN_SOURCE_VALUE.into())
}

/// 返回经过 Git 来源策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_git_source_value_for_display(source: &str) -> String {
    if validate_git_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

/// 返回经过索引来源策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_registry_source_value_for_display(source: &str) -> String {
    if validate_registry_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

/// 返回经过制品来源策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_artifact_source_value_for_display(source: &str) -> String {
    if validate_artifact_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

/// 返回经过漏洞参考来源策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_advisory_source_value_for_display(source: &str) -> String {
    if validate_advisory_source_security(source).is_ok() {
        source.to_owned()
    } else {
        HIDDEN_SOURCE_VALUE.into()
    }
}

/// 返回经过 Git 修订策略校验的可显示文本。
#[doc(hidden)]
pub fn safe_git_revision_for_display(revision: &str) -> String {
    if validate_git_revision_security(revision).is_ok() {
        revision.to_owned()
    } else {
        "<已隐藏的不安全修订>".into()
    }
}

/// 对锁文件中的带类型来源执行同样的全值脱敏。
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
        rename_directory(&self.path, destination).map_err(|error| {
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
fn rename_directory(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn rename_directory(source: &Path, destination: &Path) -> io::Result<()> {
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
    let (index, bytes) = read_registry_index_snapshot(&downloaded)?;
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
    fs::create_dir_all(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能创建索引缓存根目录：{error}"),
        )
    })?;
    let cache_metadata = fs::symlink_metadata(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能检查索引缓存根目录：{error}"),
        )
    })?;
    if cache_metadata.file_type().is_symlink()
        || !cache_metadata.is_dir()
        || standard_metadata_is_reparse(&cache_metadata)
    {
        return Err(manifest_error(
            key.registry_cache,
            None,
            "索引缓存根目录不得为链接、重解析点或特殊文件",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = cache_metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(key.registry_cache, permissions).map_err(|error| {
            manifest_error(
                key.registry_cache,
                None,
                format!("不能收紧索引缓存根目录权限：{error}"),
            )
        })?;
    }
    let canonical_cache = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    let locks = canonical_cache.join(".locks");
    let lock_root = locks.join(&digest);
    reject_invalid_existing_cache_directory(&locks, "索引缓存锁目录")?;
    reject_invalid_existing_cache_directory(&lock_root, "索引缓存锁组件")?;
    reject_invalid_existing_cache_directory(&lock_root.join(".yanxu"), "索引缓存锁状态")?;
    let lock =
        crate::storage::ProjectLock::acquire_under(&canonical_cache, &[".locks", digest.as_str()])
            .map_err(|error| {
                manifest_error(&lock_root, None, format!("不能取得索引版本缓存锁：{error}"))
            })?;
    for directory in [&locks, &lock_root, &lock_root.join(".yanxu")] {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            manifest_error(directory, None, format!("不能复验索引缓存锁组件：{error}"))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                directory,
                None,
                "索引缓存锁组件不得为链接、重解析点或特殊文件",
            ));
        }
    }
    let lock_file = lock_root.join(".yanxu/package.lock");
    let lock_metadata = fs::symlink_metadata(&lock_file).map_err(|error| {
        manifest_error(&lock_file, None, format!("不能复验索引缓存锁文件：{error}"))
    })?;
    if lock_metadata.file_type().is_symlink()
        || !lock_metadata.is_file()
        || standard_metadata_is_reparse(&lock_metadata)
    {
        return Err(manifest_error(
            &lock_file,
            None,
            "索引缓存锁文件不得为链接、重解析点或特殊文件",
        ));
    }
    let canonical_lock = fs::canonicalize(&lock_root).map_err(|error| {
        manifest_error(&lock_root, None, format!("不能定位索引版本缓存锁：{error}"))
    })?;
    if !canonical_lock.starts_with(&canonical_cache) {
        return Err(manifest_error(
            &lock_root,
            None,
            "索引版本缓存锁越出缓存根目录",
        ));
    }
    Ok(lock)
}

#[cfg(test)]
fn registry_snapshot_checksum_root(key: &RegistryPackageKey<'_>, checksum: &str) -> PathBuf {
    key.registry_cache
        .join(key.name)
        .join(".snapshots")
        .join(REGISTRY_SNAPSHOT_LAYOUT)
        .join(key.version.to_string())
        .join(checksum.to_ascii_lowercase())
}

fn existing_registry_snapshot_checksum_root(
    key: &RegistryPackageKey<'_>,
    checksum: &str,
) -> Result<Option<PathBuf>, ManifestError> {
    let cache_metadata = fs::symlink_metadata(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能检查索引缓存根目录：{error}"),
        )
    })?;
    if cache_metadata.file_type().is_symlink()
        || !cache_metadata.is_dir()
        || standard_metadata_is_reparse(&cache_metadata)
    {
        return Err(manifest_error(
            key.registry_cache,
            None,
            "索引缓存根目录不得为链接、重解析点或特殊文件",
        ));
    }
    let mut directory = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    for component in [
        key.name.to_owned(),
        ".snapshots".to_owned(),
        REGISTRY_SNAPSHOT_LAYOUT.to_owned(),
        key.version.to_string(),
        checksum.to_ascii_lowercase(),
    ] {
        let relative = Path::new(&component);
        if relative.components().count() != 1
            || !matches!(relative.components().next(), Some(Component::Normal(_)))
        {
            return Err(manifest_error(
                &directory,
                None,
                "索引快照目录组件不是单一普通路径名",
            ));
        }
        let path = directory.join(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(manifest_error(
                    &path,
                    None,
                    format!("不能检查索引快照目录：{error}"),
                ));
            }
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                &path,
                None,
                "索引快照目录不得为链接、重解析点或特殊文件",
            ));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| {
            manifest_error(&path, None, format!("不能定位索引快照目录：{error}"))
        })?;
        if !canonical.starts_with(&directory) {
            return Err(manifest_error(&path, None, "索引快照目录越出缓存边界"));
        }
        directory = canonical;
    }
    Ok(Some(directory))
}

fn create_registry_snapshot_checksum_root(
    key: &RegistryPackageKey<'_>,
    checksum: &str,
) -> Result<PathBuf, ManifestError> {
    let mut directory = fs::canonicalize(key.registry_cache).map_err(|error| {
        manifest_error(
            key.registry_cache,
            None,
            format!("不能定位索引缓存根目录：{error}"),
        )
    })?;
    for component in [
        key.name.to_owned(),
        ".snapshots".to_owned(),
        REGISTRY_SNAPSHOT_LAYOUT.to_owned(),
        key.version.to_string(),
        checksum.to_ascii_lowercase(),
    ] {
        directory = create_checked_cache_directory(&directory, &component, "索引快照目录")?;
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
    if !valid_sha256(artifact_checksum) {
        return Err(manifest_error(
            checksum_root,
            None,
            "索引 generation 身份必须是 SHA-256",
        ));
    }
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
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            root,
            None,
            "索引包缓存根必须是普通非重解析目录",
        ));
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
            if metadata.file_type().is_symlink() || standard_metadata_is_reparse(&metadata) {
                return Err(manifest_error(
                    &path,
                    None,
                    "发布包不得包含符号链接或重解析点",
                ));
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

fn validate_registry_generation(
    key: &RegistryPackageKey<'_>,
    root: &Path,
    expected_tree_checksum: &str,
) -> Result<ResolvedDependency, ManifestError> {
    validate_registry_root(key, root, Some(expected_tree_checksum))?;
    set_resolution_generation_read_only(root)?;
    validate_registry_root(key, root, Some(expected_tree_checksum))
}

fn registry_legacy_generation_id(expected_tree_checksum: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"yanxu-registry-legacy-generation-v1\0");
    digest.update(expected_tree_checksum.to_ascii_lowercase().as_bytes());
    format!("{:x}", digest.finalize())
}

fn publish_registry_tree_locked(
    key: &RegistryPackageKey<'_>,
    source_root: &Path,
    tree_checksum: &str,
    generation_id: &str,
    checkpoint: &mut impl FnMut(RegistryInstallCheckpoint, &Path) -> Result<(), ManifestError>,
) -> Result<ResolvedDependency, ManifestError> {
    if !valid_sha256(tree_checksum) || !valid_sha256(generation_id) {
        return Err(manifest_error(
            source_root,
            None,
            "索引 generation 的内容摘要或身份不是 SHA-256",
        ));
    }
    validate_registry_root(key, source_root, Some(tree_checksum))?;
    let checksum_root = create_registry_snapshot_checksum_root(key, tree_checksum)?;
    let candidate =
        RegistryTemporaryDirectory::create_within(key.registry_cache, &checksum_root, "candidate")?;
    copy_registry_tree_with_checkpoint(source_root, candidate.path(), checkpoint)?;
    checkpoint(RegistryInstallCheckpoint::CandidateCopied, candidate.path())?;
    validate_registry_root(key, candidate.path(), Some(tree_checksum))?;

    let generation = registry_generation_destination(&checksum_root, generation_id)?;
    checkpoint(RegistryInstallCheckpoint::BeforePublish, &generation)?;
    prepare_resolution_generation_for_publish(candidate.path())?;
    validate_registry_root(key, candidate.path(), Some(tree_checksum))?;
    candidate.publish(&generation)?;
    sync_registry_directory_parent(&generation)?;
    validate_registry_generation(key, &generation, tree_checksum)
}

fn migrate_legacy_registry_package_locked(
    key: &RegistryPackageKey<'_>,
    legacy: &Path,
    expected_tree_checksum: &str,
) -> Result<ResolvedDependency, ManifestError> {
    let generation_id = registry_legacy_generation_id(expected_tree_checksum);
    publish_registry_tree_locked(
        key,
        legacy,
        expected_tree_checksum,
        &generation_id,
        &mut |_, _| Ok(()),
    )
}

fn find_cached_registry_package_locked(
    key: &RegistryPackageKey<'_>,
    expected_tree_checksum: &str,
    include_legacy: bool,
) -> Result<RegistryCacheLookup, ManifestError> {
    let package_component = Path::new(key.name);
    if package_component.components().count() != 1
        || !matches!(
            package_component.components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(manifest_error(
            key.registry_cache,
            None,
            "索引包名不能用作单一缓存路径组件",
        ));
    }
    if !valid_sha256(expected_tree_checksum) {
        return Err(manifest_error(
            key.registry_cache,
            None,
            "索引包内容 SHA-256 无效",
        ));
    }
    let mut invalid = None;
    match existing_registry_snapshot_checksum_root(key, expected_tree_checksum) {
        Ok(Some(checksum_root)) => {
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
                        match validate_registry_generation(key, &path, expected_tree_checksum) {
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
        Ok(None) => {}
        Err(error) => invalid = Some(error),
    }
    if include_legacy {
        let legacy = registry_legacy_root(key);
        match fs::symlink_metadata(&legacy) {
            Ok(_) => {
                match migrate_legacy_registry_package_locked(key, &legacy, expected_tree_checksum) {
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
    publish_registry_tree_locked(
        key,
        &staged.root,
        &staged.tree_checksum,
        &staged.artifact_checksum,
        &mut checkpoint,
    )
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
    match fs::symlink_metadata(&index_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(manifest_error(
                &index_path,
                None,
                format!("不能检查索引元数据：{error}"),
            ));
        }
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
    read_registry_index_snapshot(path).map(|(index, _)| index)
}

fn read_registry_index_snapshot(path: &Path) -> Result<(RegistryIndex, Vec<u8>), ManifestError> {
    let bytes = read_stable_metadata_file_snapshot(path, REGISTRY_INDEX_MAX_BYTES, "索引元数据")?;
    reject_duplicate_registry_json_keys(path, &bytes)?;
    let index: RegistryIndex = serde_json::from_slice(&bytes)
        .map_err(|error| manifest_error(path, None, format!("索引元数据无效：{error}")))?;
    validate_registry_index(path, &index)?;
    Ok((index, bytes))
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
    match fs::symlink_metadata(&index_path) {
        Ok(_) => {
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(manifest_error(
                &index_path,
                None,
                format!("不能检查索引元数据：{error}"),
            ));
        }
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
    let manifest_bytes = read_resolved_regular_file_snapshot(
        manifest_file,
        limits.file_bytes.min(MANIFEST_MAX_BYTES),
        "规范包清单",
    )?;
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
    let resolved = resolve_graph_mode_locked_with_checksum(
        manifest,
        false,
        true,
        true,
        manifest_checksum,
        expected_root,
        trusted_root.clone(),
    )?;
    if let Some(dependency) = resolved
        .graph
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
    cache_graph(manifest, resolved);
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

fn read_stable_metadata_file_snapshot(
    path: &Path,
    max_bytes: u64,
    kind: &str,
) -> Result<Vec<u8>, ManifestError> {
    read_stable_metadata_file_snapshot_with_hook(path, max_bytes, kind, || Ok(()))
}

fn read_stable_metadata_file_snapshot_with_hook(
    path: &Path,
    max_bytes: u64,
    kind: &str,
    after_open: impl FnOnce() -> Result<(), ManifestError>,
) -> Result<Vec<u8>, ManifestError> {
    let file = match open_regular_file_for_snapshot(path) {
        Ok(file) => file,
        Err(_)
            if fs::symlink_metadata(path)
                .is_ok_and(|metadata| !is_regular_file_metadata(&metadata)) =>
        {
            return Err(manifest_error(
                path,
                None,
                format!("{kind}必须是普通文件，不得为符号链接、重解析点或特殊文件"),
            ));
        }
        Err(error) => {
            return Err(manifest_error(
                path,
                None,
                format!("不能打开{kind}：{error}"),
            ));
        }
    };
    let identity = file.try_clone().map_err(|error| {
        manifest_error(path, None, format!("不能保留已打开的{kind}身份：{error}"))
    })?;
    after_open()?;
    let bytes = read_opened_regular_file_snapshot(file, path, max_bytes, kind, None)?;
    let verification = open_regular_file_for_snapshot(path).map_err(|error| {
        manifest_error(
            path,
            None,
            format!("不能重新打开{kind}以复验读取后身份：{error}"),
        )
    })?;
    let unchanged = same_opened_file_identity(&identity, &verification).map_err(|error| {
        manifest_error(path, None, format!("不能复验读取后的{kind}身份：{error}"))
    })?;
    if !unchanged {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在读取期间被替换"),
        ));
    }
    Ok(bytes)
}

fn read_package_file_snapshot(
    canonical_root: &Path,
    path: &Path,
    max_bytes: u64,
    kind: &str,
    limit_code: Option<&str>,
) -> Result<Vec<u8>, ManifestError> {
    read_package_file_snapshot_with_hook(canonical_root, path, max_bytes, kind, limit_code, || {
        Ok(())
    })
}

fn read_package_file_snapshot_with_hook(
    canonical_root: &Path,
    path: &Path,
    max_bytes: u64,
    kind: &str,
    limit_code: Option<&str>,
    before_open: impl FnOnce() -> Result<(), ManifestError>,
) -> Result<Vec<u8>, ManifestError> {
    let before_file = open_regular_file_for_snapshot(path)
        .map_err(|error| manifest_error(path, None, format!("不能预先打开{kind}：{error}")))?;
    let before = before_file.metadata().map_err(|error| {
        manifest_error(path, None, format!("不能检查预先打开的{kind}：{error}"))
    })?;
    if !is_regular_file_metadata(&before) {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}必须是普通文件，不得为符号链接或特殊文件"),
        ));
    }
    if before.len() > max_bytes {
        return Err(snapshot_limit_error(path, kind, max_bytes, limit_code));
    }

    before_open()?;
    let mut file = open_regular_file_for_snapshot(path).map_err(|error| {
        manifest_error(
            path,
            None,
            format!("不能打开{kind}；文件可能在检查后被替换：{error}"),
        )
    })?;
    let opened = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能检查已打开的{kind}：{error}")))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| manifest_error(path, None, format!("不能定位{kind}：{error}")))?;
    let canonical_file = open_regular_file_for_snapshot(&canonical).map_err(|error| {
        manifest_error(
            &canonical,
            None,
            format!("不能打开已定位的{kind}以复验身份：{error}"),
        )
    })?;
    let canonical_metadata = canonical_file.metadata().map_err(|error| {
        manifest_error(&canonical, None, format!("不能检查已定位的{kind}：{error}"))
    })?;
    let before_matches_opened =
        same_opened_file_identity(&before_file, &file).map_err(|error| {
            manifest_error(path, None, format!("不能比较{kind}打开前后的身份：{error}"))
        })?;
    let opened_matches_canonical =
        same_opened_file_identity(&file, &canonical_file).map_err(|error| {
            manifest_error(path, None, format!("不能复验已定位的{kind}身份：{error}"))
        })?;
    if !is_regular_file_metadata(&opened)
        || !is_regular_file_metadata(&canonical_metadata)
        || !canonical.starts_with(canonical_root)
        || !before_matches_opened
        || !opened_matches_canonical
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在读取前被替换、经链接越出包根目录或身份不稳定"),
        ));
    }

    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| manifest_error(path, None, format!("不能读取{kind}：{error}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(snapshot_limit_error(path, kind, max_bytes, limit_code));
    }

    let after_file = open_regular_file_for_snapshot(path).map_err(|error| {
        manifest_error(
            path,
            None,
            format!("不能重新打开{kind}以复验读取后身份：{error}"),
        )
    })?;
    let after = after_file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能复验读取后的{kind}：{error}")))?;
    let path_identity_unchanged =
        same_opened_file_identity(&file, &after_file).map_err(|error| {
            manifest_error(path, None, format!("不能复验读取后的{kind}身份：{error}"))
        })?;
    if !is_regular_file_metadata(&after)
        || !path_identity_unchanged
        || opened.len() != bytes.len() as u64
        || after.len() != bytes.len() as u64
        || metadata_modified_changed(&opened, &after)
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在打包读取期间发生变化"),
        ));
    }
    Ok(bytes)
}

/// 从已经规范化的模块路径读取一份身份稳定的 UTF-8 快照。
///
/// 打开前、已打开句柄和读取后路径必须始终指向同一普通文件；受支持平台会以
/// no-follow、non-blocking 或重解析点检查避免竞态替换成链接或特殊文件后阻塞。
#[doc(hidden)]
pub fn read_module_source_snapshot(path: &Path) -> Result<String, ManifestError> {
    if !path.is_absolute() {
        return Err(manifest_error(path, None, "模块快照路径必须是规范绝对路径"));
    }
    let expected_root = path
        .parent()
        .ok_or_else(|| manifest_error(path, None, "模块快照路径缺少父目录"))?;
    let bytes = read_package_file_snapshot(
        expected_root,
        path,
        MODULE_SOURCE_MAX_BYTES,
        "模块源码",
        Some(PACKAGE_MODULE_SOURCE_LIMIT_CODE),
    )?;
    String::from_utf8(bytes)
        .map_err(|error| manifest_error(path, None, format!("模块源码不是 UTF-8：{error}")))
}

/// 相对已经打开的可信包根读取模块；包根被重命名或同名替换时，仍只访问
/// 原目录句柄所代表的树。包外路径沿用普通稳定快照。
#[doc(hidden)]
pub fn read_module_source_snapshot_in(
    roots: &TrustedPackageRoots,
    path: &Path,
) -> Result<String, ManifestError> {
    match roots
        .resolve_existing_module_file(path)
        .map_err(|error| package_path_manifest_error(path, error))?
    {
        Some(resolved) => read_resolved_module_source_snapshot(resolved),
        None => {
            let expected_root = path
                .parent()
                .ok_or_else(|| manifest_error(path, None, "模块快照路径缺少父目录"))?;
            let bytes = read_package_file_snapshot(
                expected_root,
                path,
                MODULE_SOURCE_MAX_BYTES,
                "模块源码",
                Some(PACKAGE_MODULE_SOURCE_LIMIT_CODE),
            )?;
            String::from_utf8(bytes)
                .map_err(|error| manifest_error(path, None, format!("模块源码不是 UTF-8：{error}")))
        }
    }
}

/// 从已经规范化的普通文件路径读取一份身份稳定且有界的字节快照。
#[doc(hidden)]
pub fn read_stable_regular_file_snapshot(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, ManifestError> {
    if !path.is_absolute() {
        return Err(manifest_error(path, None, "文件快照路径必须是规范绝对路径"));
    }
    let expected_root = path
        .parent()
        .ok_or_else(|| manifest_error(path, None, "文件快照路径缺少父目录"))?;
    read_package_file_snapshot(expected_root, path, max_bytes, "文件", None)
}

/// 相对已经打开的可信包根读取普通文件；包外路径沿用普通稳定快照。
#[doc(hidden)]
pub fn read_stable_regular_file_snapshot_in(
    roots: &TrustedPackageRoots,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, ManifestError> {
    match roots
        .resolve_existing_file(path, PackagePathPurpose::ManifestReference)
        .map_err(|error| package_path_manifest_error(path, error))?
    {
        Some(resolved) => read_resolved_regular_file_snapshot(resolved, max_bytes, "文件"),
        None => read_stable_regular_file_snapshot(path, max_bytes),
    }
}

/// 统一验证内存或宿主直接提供的模块源码字节数。
#[doc(hidden)]
pub fn validate_module_source_size(
    path: impl AsRef<Path>,
    byte_len: u64,
) -> Result<(), ManifestError> {
    if byte_len > MODULE_SOURCE_MAX_BYTES {
        return Err(snapshot_limit_error(
            path.as_ref(),
            "模块源码",
            MODULE_SOURCE_MAX_BYTES,
            Some(PACKAGE_MODULE_SOURCE_LIMIT_CODE),
        ));
    }
    Ok(())
}

/// 只消费安全解析令牌中已经打开的模块句柄。
#[doc(hidden)]
pub fn read_resolved_module_source_snapshot(
    resolved: ResolvedPackageFile,
) -> Result<String, ManifestError> {
    let path = resolved.path().to_path_buf();
    let bytes = read_opened_regular_file_snapshot(
        resolved.into_file(),
        &path,
        MODULE_SOURCE_MAX_BYTES,
        "模块源码",
        Some(PACKAGE_MODULE_SOURCE_LIMIT_CODE),
    )?;
    String::from_utf8(bytes)
        .map_err(|error| manifest_error(&path, None, format!("模块源码不是 UTF-8：{error}")))
}

/// 从解析阶段持有的普通文件句柄读取有界快照。
#[doc(hidden)]
pub fn read_resolved_regular_file_snapshot(
    resolved: ResolvedPackageFile,
    max_bytes: u64,
    kind: &str,
) -> Result<Vec<u8>, ManifestError> {
    let path = resolved.path().to_path_buf();
    read_opened_regular_file_snapshot(resolved.into_file(), &path, max_bytes, kind, None)
}

fn read_opened_regular_file_snapshot(
    file: fs::File,
    path: &Path,
    max_bytes: u64,
    kind: &str,
    limit_code: Option<&str>,
) -> Result<Vec<u8>, ManifestError> {
    read_opened_regular_file_snapshot_with_hook(file, path, max_bytes, kind, limit_code, || Ok(()))
}

fn read_opened_regular_file_snapshot_with_hook(
    mut file: fs::File,
    path: &Path,
    max_bytes: u64,
    kind: &str,
    limit_code: Option<&str>,
    after_first_read: impl FnOnce() -> Result<(), ManifestError>,
) -> Result<Vec<u8>, ManifestError> {
    let before = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能检查已打开的{kind}：{error}")))?;
    if !before.is_file() {
        return Err(manifest_error(path, None, format!("{kind}必须是普通文件")));
    }
    if before.len() > max_bytes {
        return Err(snapshot_limit_error(path, kind, max_bytes, limit_code));
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
        return Err(snapshot_limit_error(path, kind, max_bytes, limit_code));
    }
    let after_first = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能复验已打开的{kind}：{error}")))?;
    if !after_first.is_file()
        || before.len() != bytes.len() as u64
        || after_first.len() != bytes.len() as u64
        || metadata_modified_changed(&before, &after_first)
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在读取期间发生变化"),
        ));
    }

    after_first_read()?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        manifest_error(path, None, format!("不能重新定位{kind}以复验内容：{error}"))
    })?;
    let offset = {
        let mut verifier = (&mut file).take(max_bytes.saturating_add(1));
        let mut buffer = [0_u8; 64 * 1024];
        let mut offset = 0_usize;
        loop {
            let read = verifier.read(&mut buffer).map_err(|error| {
                manifest_error(path, None, format!("不能再次读取{kind}以复验内容：{error}"))
            })?;
            if read == 0 {
                break;
            }
            let end = offset.saturating_add(read);
            if end > bytes.len() || bytes[offset..end] != buffer[..read] {
                return Err(manifest_error(
                    path,
                    None,
                    format!("{kind}在快照复验期间发生同长或原地变化"),
                ));
            }
            offset = end;
        }
        offset
    };
    let after_second = file
        .metadata()
        .map_err(|error| manifest_error(path, None, format!("不能完成{kind}内容复验：{error}")))?;
    if offset != bytes.len()
        || !after_second.is_file()
        || after_second.len() != bytes.len() as u64
        || metadata_modified_changed(&after_first, &after_second)
    {
        return Err(manifest_error(
            path,
            None,
            format!("{kind}在快照复验期间发生变化"),
        ));
    }
    Ok(bytes)
}

fn snapshot_limit_error(
    path: &Path,
    kind: &str,
    max_bytes: u64,
    code: Option<&str>,
) -> ManifestError {
    let message = format!("{kind}不得超过 {max_bytes} 字节");
    manifest_error(
        path,
        None,
        code.map_or(message.clone(), |code| format!("[{code}] {message}")),
    )
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
pub(crate) fn standard_metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn standard_metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
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

fn resolution_generation_cache_root() -> Result<PathBuf, ManifestError> {
    let cache = cache_root();
    fs::create_dir_all(&cache).map_err(|error| {
        manifest_error(
            &cache,
            None,
            format!("不能创建依赖 generation 缓存根：{error}"),
        )
    })?;
    let cache_metadata = fs::symlink_metadata(&cache).map_err(|error| {
        manifest_error(
            &cache,
            None,
            format!("不能检查依赖 generation 缓存根：{error}"),
        )
    })?;
    if cache_metadata.file_type().is_symlink()
        || !cache_metadata.is_dir()
        || standard_metadata_is_reparse(&cache_metadata)
    {
        return Err(manifest_error(
            &cache,
            None,
            "依赖 generation 缓存根不得为链接、重解析点或特殊文件",
        ));
    }
    let mut directory = cache.clone();
    for component in ["resolution", RESOLUTION_GENERATION_LAYOUT] {
        directory.push(component);
        match fs::create_dir(&directory) {
            Ok(()) => sync_registry_directory_parent(&directory)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(manifest_error(
                    &directory,
                    None,
                    format!("不能创建依赖 generation 缓存目录：{error}"),
                ));
            }
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            manifest_error(
                &directory,
                None,
                format!("不能检查依赖 generation 缓存目录：{error}"),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                &directory,
                None,
                "依赖 generation 缓存目录不得为链接、重解析点或特殊文件",
            ));
        }
    }
    let canonical_cache = fs::canonicalize(&cache)
        .map_err(|error| manifest_error(&cache, None, format!("不能定位依赖缓存根：{error}")))?;
    let canonical_directory = fs::canonicalize(&directory).map_err(|error| {
        manifest_error(
            &directory,
            None,
            format!("不能定位依赖 generation 缓存目录：{error}"),
        )
    })?;
    if !canonical_directory.starts_with(canonical_cache) {
        return Err(manifest_error(
            &directory,
            None,
            "依赖 generation 缓存目录越出缓存根",
        ));
    }
    Ok(canonical_directory)
}

fn acquire_resolution_generation_lock(
    cache: &Path,
    checksum: &str,
) -> Result<crate::storage::ProjectLock, ManifestError> {
    let locks = cache.join(".locks");
    match fs::create_dir(&locks) {
        Ok(()) => sync_registry_directory_parent(&locks)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(manifest_error(
                &locks,
                None,
                format!("不能创建依赖 generation 缓存锁目录：{error}"),
            ));
        }
    }
    let locks_metadata = fs::symlink_metadata(&locks).map_err(|error| {
        manifest_error(
            &locks,
            None,
            format!("不能检查依赖 generation 缓存锁目录：{error}"),
        )
    })?;
    if locks_metadata.file_type().is_symlink()
        || !locks_metadata.is_dir()
        || standard_metadata_is_reparse(&locks_metadata)
    {
        return Err(manifest_error(
            &locks,
            None,
            "依赖 generation 缓存锁目录不得为链接、重解析点或特殊文件",
        ));
    }
    let lock_root = locks.join(checksum);
    match fs::symlink_metadata(&lock_root) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || standard_metadata_is_reparse(&metadata) =>
        {
            return Err(manifest_error(
                &lock_root,
                None,
                "依赖 generation 缓存锁组件不得为链接、重解析点或特殊文件",
            ));
        }
        Ok(_) => {
            let lock_state = lock_root.join(".yanxu");
            match fs::symlink_metadata(&lock_state) {
                Ok(metadata)
                    if metadata.file_type().is_symlink()
                        || !metadata.is_dir()
                        || standard_metadata_is_reparse(&metadata) =>
                {
                    return Err(manifest_error(
                        &lock_state,
                        None,
                        "依赖 generation 缓存锁组件不得为链接、重解析点或特殊文件",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(manifest_error(
                        &lock_state,
                        None,
                        format!("不能预先检查依赖 generation 缓存锁状态：{error}"),
                    ));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(manifest_error(
                &lock_root,
                None,
                format!("不能预先检查依赖 generation 缓存锁：{error}"),
            ));
        }
    }
    let lock = crate::storage::ProjectLock::acquire_under(cache, &[".locks", checksum]).map_err(
        |error| {
            manifest_error(
                &lock_root,
                None,
                format!("不能取得依赖 generation 缓存锁：{error}"),
            )
        },
    )?;
    let canonical_lock = fs::canonicalize(&lock_root).map_err(|error| {
        manifest_error(
            &lock_root,
            None,
            format!("不能定位依赖 generation 缓存锁：{error}"),
        )
    })?;
    if !canonical_lock.starts_with(cache) {
        return Err(manifest_error(
            &lock_root,
            None,
            "依赖 generation 缓存锁越出缓存根",
        ));
    }
    let lock_state = lock_root.join(".yanxu");
    for directory in [&lock_root, &lock_state] {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            manifest_error(
                directory,
                None,
                format!("不能检查依赖 generation 缓存锁组件：{error}"),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                directory,
                None,
                "依赖 generation 缓存锁组件不得为链接、重解析点或特殊文件",
            ));
        }
    }
    let lock_file = lock_root.join(".yanxu/package.lock");
    let metadata = fs::symlink_metadata(&lock_file).map_err(|error| {
        manifest_error(
            &lock_file,
            None,
            format!("不能检查依赖 generation 缓存锁文件：{error}"),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &lock_file,
            None,
            "依赖 generation 缓存锁文件不得为链接、重解析点或特殊文件",
        ));
    }
    Ok(lock)
}

fn create_resolution_checksum_root(cache: &Path, checksum: &str) -> Result<PathBuf, ManifestError> {
    let root = cache.join(checksum);
    match fs::create_dir(&root) {
        Ok(()) => sync_registry_directory_parent(&root)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(manifest_error(
                &root,
                None,
                format!("不能创建依赖 generation 摘要目录：{error}"),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&root).map_err(|error| {
        manifest_error(
            &root,
            None,
            format!("不能检查依赖 generation 摘要目录：{error}"),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &root,
            None,
            "依赖 generation 摘要目录不得为链接、重解析点或特殊文件",
        ));
    }
    let canonical = fs::canonicalize(&root).map_err(|error| {
        manifest_error(
            &root,
            None,
            format!("不能定位依赖 generation 摘要目录：{error}"),
        )
    })?;
    if !canonical.starts_with(cache) {
        return Err(manifest_error(
            &root,
            None,
            "依赖 generation 摘要目录越出缓存根",
        ));
    }
    Ok(canonical)
}

fn existing_resolution_generation(
    checksum_root: &Path,
    checksum: &str,
) -> Result<Option<PathBuf>, ManifestError> {
    let mut candidates = fs::read_dir(checksum_root)
        .map_err(|error| {
            manifest_error(
                checksum_root,
                None,
                format!("不能枚举依赖 generation：{error}"),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            manifest_error(
                checksum_root,
                None,
                format!("不能读取依赖 generation 目录项：{error}"),
            )
        })?;
    candidates.sort_by_key(fs::DirEntry::file_name);
    for candidate in candidates {
        if candidate.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let file_type = candidate.file_type().map_err(|error| {
            manifest_error(
                candidate.path(),
                None,
                format!("不能检查依赖 generation 目录项：{error}"),
            )
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let root = candidate.path().join("package");
        if matches!(resolution_generation_checksum(&root), Ok(actual) if actual == checksum) {
            set_resolution_generation_read_only(&candidate.path())?;
            return fs::canonicalize(&root).map(Some).map_err(|error| {
                manifest_error(&root, None, format!("不能定位依赖 generation：{error}"))
            });
        }
    }
    Ok(None)
}

fn resolution_generation_checksum(root: &Path) -> Result<String, ManifestError> {
    let snapshot = capture_package_tree(
        root,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )?;
    portable_tree_snapshot_checksum(&snapshot)
}

fn write_resolution_snapshot(
    snapshot: &PackageTreeSnapshot,
    root: &Path,
) -> Result<(), ManifestError> {
    fs::create_dir(root).map_err(|error| {
        manifest_error(root, None, format!("不能创建依赖 generation 包根：{error}"))
    })?;
    for entry in &snapshot.files {
        let path = root.join(&entry.relative);
        let parent = path
            .parent()
            .ok_or_else(|| manifest_error(&path, None, "依赖 generation 文件缺少父目录"))?;
        fs::create_dir_all(parent).map_err(|error| {
            manifest_error(
                parent,
                None,
                format!("不能创建依赖 generation 子目录：{error}"),
            )
        })?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            manifest_error(
                &path,
                None,
                format!("不能创建依赖 generation 文件：{error}"),
            )
        })?;
        file.write_all(&entry.bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                manifest_error(
                    &path,
                    None,
                    format!("不能写入依赖 generation 文件：{error}"),
                )
            })?;
    }
    sync_resolution_directories(root)
}

#[cfg(unix)]
fn sync_resolution_directories(root: &Path) -> Result<(), ManifestError> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        for entry in fs::read_dir(&directory).map_err(|error| {
            manifest_error(
                &directory,
                None,
                format!("不能枚举依赖 generation 目录以同步：{error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                manifest_error(
                    &directory,
                    None,
                    format!("不能读取依赖 generation 目录项：{error}"),
                )
            })?;
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                directories.push(entry.path());
            }
        }
        index += 1;
    }
    for directory in directories.into_iter().rev() {
        fs::File::open(&directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                manifest_error(
                    &directory,
                    None,
                    format!("不能同步依赖 generation 目录：{error}"),
                )
            })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_resolution_directories(_root: &Path) -> Result<(), ManifestError> {
    Ok(())
}

fn set_resolution_generation_read_only(path: &Path) -> Result<(), ManifestError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        manifest_error(path, None, format!("不能检查依赖 generation 权限：{error}"))
    })?;
    if metadata.file_type().is_symlink() || standard_metadata_is_reparse(&metadata) {
        return Err(manifest_error(
            path,
            None,
            "依赖 generation 不得包含链接或重解析点",
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|error| {
            manifest_error(
                path,
                None,
                format!("不能枚举依赖 generation 以收紧权限：{error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                manifest_error(
                    path,
                    None,
                    format!("不能读取依赖 generation 目录项：{error}"),
                )
            })?;
            set_resolution_generation_read_only(&entry.path())?;
        }
    } else if !metadata.is_file() {
        return Err(manifest_error(
            path,
            None,
            "依赖 generation 只能包含普通目录和文件",
        ));
    }
    let mut permissions = metadata.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(if metadata.is_dir() { 0o500 } else { 0o400 });
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|error| {
        manifest_error(path, None, format!("不能锁定依赖 generation 权限：{error}"))
    })
}

fn prepare_resolution_generation_for_publish(path: &Path) -> Result<(), ManifestError> {
    set_resolution_generation_read_only(path)?;
    sync_resolution_generation_metadata(path)
}

#[cfg(unix)]
fn sync_resolution_generation_metadata(root: &Path) -> Result<(), ManifestError> {
    let mut entries = vec![root.to_path_buf()];
    let mut index = 0;
    while index < entries.len() {
        let path = entries[index].clone();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            manifest_error(&path, None, format!("不能检查待发布 generation：{error}"))
        })?;
        if metadata.file_type().is_symlink()
            || standard_metadata_is_reparse(&metadata)
            || (!metadata.is_dir() && !metadata.is_file())
        {
            return Err(manifest_error(
                &path,
                None,
                "待发布 generation 只能包含普通目录和文件",
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                manifest_error(&path, None, format!("不能枚举待发布 generation：{error}"))
            })? {
                entries.push(
                    entry
                        .map_err(|error| {
                            manifest_error(
                                &path,
                                None,
                                format!("不能读取待发布 generation 目录项：{error}"),
                            )
                        })?
                        .path(),
                );
            }
        }
        index += 1;
    }
    for path in entries.into_iter().rev() {
        fs::File::open(&path)
            .and_then(|entry| entry.sync_all())
            .map_err(|error| {
                manifest_error(&path, None, format!("不能同步待发布 generation：{error}"))
            })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_resolution_generation_metadata(_root: &Path) -> Result<(), ManifestError> {
    Ok(())
}

fn resolution_generation_destination(checksum_root: &Path) -> Result<PathBuf, ManifestError> {
    let primary = checksum_root.join("complete");
    match fs::symlink_metadata(&primary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(primary),
        Ok(_) => {}
        Err(error) => {
            return Err(manifest_error(
                &primary,
                None,
                format!("不能检查依赖 generation 发布位置：{error}"),
            ));
        }
    }
    for _ in 0..1_024 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let repair = checksum_root.join(format!("repair-{}-{sequence}", std::process::id()));
        match fs::symlink_metadata(&repair) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(repair),
            Ok(_) => continue,
            Err(error) => {
                return Err(manifest_error(
                    &repair,
                    None,
                    format!("不能检查依赖 generation 修复位置：{error}"),
                ));
            }
        }
    }
    Err(manifest_error(
        checksum_root,
        None,
        "不能分配唯一依赖 generation 发布位置",
    ))
}

fn publish_resolution_generation(
    snapshot: &PackageTreeSnapshot,
    checksum: &str,
) -> Result<PathBuf, ManifestError> {
    let cache = resolution_generation_cache_root()?;
    let _lock = acquire_resolution_generation_lock(&cache, checksum)?;
    let checksum_root = create_resolution_checksum_root(&cache, checksum)?;
    if let Some(root) = existing_resolution_generation(&checksum_root, checksum)? {
        return Ok(root);
    }
    let temporary =
        RegistryTemporaryDirectory::create_within(&cache, &checksum_root, "resolution-generation")?;
    write_resolution_snapshot(snapshot, &temporary.path().join("package"))?;
    let destination = resolution_generation_destination(&checksum_root)?;
    temporary.publish(&destination)?;
    sync_registry_directory_parent(&destination)?;
    set_resolution_generation_read_only(&destination)?;
    let root = destination.join("package");
    let actual = resolution_generation_checksum(&root)?;
    if actual != checksum {
        return Err(manifest_error(
            &root,
            None,
            format!("依赖 generation 发布后摘要改变：预期 {checksum}，实际 {actual}"),
        ));
    }
    fs::canonicalize(&root).map_err(|error| {
        manifest_error(
            &root,
            None,
            format!("不能定位已发布依赖 generation：{error}"),
        )
    })
}

fn validate_resolution_generation(
    root: &Path,
    checksum: &str,
    locked: &LockedPackage,
    target: &str,
) -> Result<TrustedPackageRoots, ManifestError> {
    let mut roots = TrustedPackageRoots::new();
    roots
        .insert(root)
        .map_err(|error| package_path_manifest_error(root, error))?;
    let snapshot = capture_package_tree_in(
        &roots,
        root,
        PackagePathPurpose::TreeChecksum,
        PackageTreeCaptureLimits::dependency(),
        None,
    )?;
    if portable_tree_snapshot_checksum(&snapshot)? != checksum {
        return Err(manifest_error(
            root,
            None,
            "依赖 generation 内容与锁定摘要不一致",
        ));
    }
    let manifest_path = root.join(MANIFEST_NAME);
    let manifest_bytes = snapshot
        .get(Path::new(MANIFEST_NAME))
        .ok_or_else(|| manifest_error(&manifest_path, None, "依赖 generation 缺少规范包清单"))?;
    let manifest_text = std::str::from_utf8(manifest_bytes).map_err(|error| {
        manifest_error(
            &manifest_path,
            None,
            format!("依赖 generation 包清单不是 UTF-8：{error}"),
        )
    })?;
    let manifest = parse(manifest_text, manifest_path, root.to_path_buf())?;
    validate_package_root(&manifest)?;
    let exports = manifest
        .exports
        .iter()
        .map(|(name, path)| (name.clone(), path.to_string_lossy().into_owned()))
        .collect::<BTreeMap<_, _>>();
    let native = selected_native_artifact(&manifest, target)?;
    if locked.name != manifest.name
        || locked.version != manifest.version.to_string()
        || locked.entry != manifest.entry.to_string_lossy()
        || locked.exports != exports
        || locked.minimum_yanxu != manifest.minimum_yanxu.as_ref().map(ToString::to_string)
        || locked.target != target
        || locked.native != native
    {
        return Err(manifest_error(
            &manifest.path,
            None,
            format!(
                "依赖“{}”的不可变 generation 与锁定身份、导出、目标或原生制品不一致",
                locked.name
            ),
        ));
    }
    Ok(roots)
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
            None,
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
pub(crate) fn cap_metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(not(windows), not(target_os = "wasi")))]
pub(crate) fn cap_metadata_is_reparse(_metadata: &cap_std::fs::Metadata) -> bool {
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
                let bytes = read_opened_regular_file_snapshot(
                    file,
                    &display,
                    limits.file_bytes,
                    "包内容",
                    None,
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
    }
}

/// 把完整锁定图复制到项目内目录；解析器会自动优先使用祖先目录中的辖制清单。
pub fn vendor_dependencies(
    graph: &ResolutionGraph,
    destination: impl AsRef<Path>,
) -> Result<VendorManifest, ManifestError> {
    vendor_dependencies_with_checkpoint(graph, destination.as_ref(), |_, _| Ok(()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VendorInstallCheckpoint {
    Backup,
    BackupSync,
    Publish,
    PublishValidation,
    PublishSync,
    BackupCleanup,
    RollbackPublished,
    RestoreValidation,
    Restore,
    RollbackValidation,
    RollbackSync,
    RollbackCleanup,
}

fn vendor_dependencies_with_checkpoint(
    graph: &ResolutionGraph,
    destination: &Path,
    mut checkpoint: impl FnMut(VendorInstallCheckpoint, &Path) -> Result<(), ManifestError>,
) -> Result<VendorManifest, ManifestError> {
    if graph.packages.values().any(|dependency| {
        validate_locked_dependency_source(&dependency.locked.source).is_err()
            || dependency
                .locked
                .revision
                .as_deref()
                .is_some_and(|revision| validate_git_revision_security(revision).is_err())
    }) {
        return Err(manifest_error(destination, None, SOURCE_SECURITY_ERROR));
    }
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        manifest_error(parent, None, format!("不能创建辖制目录父目录：{error}"))
    })?;
    let _project_lock = acquire_project_lock(parent)?;
    let previous = match fs::symlink_metadata(destination) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !standard_metadata_is_reparse(&metadata) =>
        {
            Some(validate_owned_vendor_directory(destination)?)
        }
        Ok(_) => {
            return Err(manifest_error(
                destination,
                None,
                "既有辖制目标必须是真实目录，不得为链接、重解析点或特殊文件",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(manifest_error(
                destination,
                None,
                format!("不能检查既有辖制目标：{error}"),
            ));
        }
    };
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vendor");
    let staging = parent.join(format!(".{name}.staging-{}-{sequence}", std::process::id()));
    let backup = parent.join(format!(".{name}.backup-{}-{sequence}", std::process::id()));
    fs::create_dir(&staging).map_err(|error| {
        manifest_error(&staging, None, format!("不能创建辖制暂存目录：{error}"))
    })?;

    let vendor = match build_staged_vendor(graph, &staging) {
        Ok(vendor) => vendor,
        Err(error) => return Err(vendor_build_failure(&staging, error)),
    };
    let staged = match validate_owned_vendor_directory(&staging) {
        Ok(staged) => staged,
        Err(error) => return Err(vendor_build_failure(&staging, error)),
    };
    if staged != vendor {
        return Err(vendor_build_failure(
            &staging,
            manifest_error(&staging, None, "辖制暂存目录在发布前发生变化"),
        ));
    }
    install_staged_vendor_directory(
        &staging,
        destination,
        &backup,
        &vendor,
        previous.as_ref(),
        &mut checkpoint,
    )?;
    Ok(vendor)
}

fn build_staged_vendor(
    graph: &ResolutionGraph,
    staging: &Path,
) -> Result<VendorManifest, ManifestError> {
    let mut packages = BTreeMap::new();
    for (id, dependency) in &graph.packages {
        let directory = format!("{}-{}", dependency.locked.name, &short_hash(id)[..12]);
        let target = staging.join(&directory);
        let snapshot = capture_package_tree(
            &dependency.root,
            PackagePathPurpose::TreeChecksum,
            PackageTreeCaptureLimits::dependency(),
            None,
        )?;
        let checksum = portable_tree_snapshot_checksum(&snapshot)?;
        if !tree_snapshot_checksum_matches(&snapshot, &dependency.locked.checksum)? {
            return Err(manifest_error(
                &target,
                None,
                format!(
                    "辖制包校验不符：锁定 {}，快照为 {checksum}",
                    dependency.locked.checksum
                ),
            ));
        }
        write_package_tree_snapshot(&snapshot, &target)?;
        if !tree_checksum_matches(&target, &dependency.locked.checksum)? {
            return Err(manifest_error(
                &target,
                None,
                "辖制包写入暂存目录后校验不符",
            ));
        }
        packages.insert(
            id.clone(),
            VendorPackage {
                path: directory,
                checksum: dependency.locked.checksum.clone(),
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
    let manifest_path = staging.join("言序-vendor.json");
    let document = serde_json::to_vec_pretty(&vendor).map_err(|error| {
        manifest_error(&manifest_path, None, format!("不能生成辖制清单：{error}"))
    })?;
    atomic_write(&manifest_path, &document, "辖制清单")?;
    sync_vendor_tree(staging)?;
    Ok(vendor)
}

fn vendor_build_failure(staging: &Path, primary: ManifestError) -> ManifestError {
    match fs::remove_dir_all(staging) {
        Ok(()) => primary,
        Err(error) => vendor_combined_error(
            staging,
            primary,
            &[format!("不能清理失败的辖制暂存目录：{error}")],
        ),
    }
}

fn validate_owned_vendor_directory(destination: &Path) -> Result<VendorManifest, ManifestError> {
    if destination.join(MANIFEST_NAME).exists() {
        return Err(manifest_error(
            destination,
            None,
            "辖制目标不能覆盖言序项目根目录",
        ));
    }
    let manifest_path = destination.join("言序-vendor.json");
    let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| {
        manifest_error(
            &manifest_path,
            None,
            format!("既有目录没有可验证的辖制清单，拒绝覆盖：{error}"),
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || standard_metadata_is_reparse(&metadata)
    {
        return Err(manifest_error(
            &manifest_path,
            None,
            "既有目录没有普通、非重解析的辖制清单，拒绝覆盖",
        ));
    }
    let mut roots = TrustedPackageRoots::default();
    roots
        .insert(destination)
        .map_err(|error| package_path_manifest_error(destination, error))?;
    let manifest = roots
        .resolve_existing_file(&manifest_path, PackagePathPurpose::ManifestReference)
        .map_err(|error| package_path_manifest_error(&manifest_path, error))?
        .ok_or_else(|| {
            manifest_error(destination, None, "既有目录没有可验证的辖制清单，拒绝覆盖")
        })?;
    let bytes =
        read_resolved_regular_file_snapshot(manifest, VENDOR_MANIFEST_MAX_BYTES, "辖制清单")?;
    let vendor: VendorManifest = serde_json::from_slice(&bytes).map_err(|error| {
        manifest_error(
            &manifest_path,
            None,
            format!("既有辖制清单无效，拒绝覆盖：{error}"),
        )
    })?;
    if vendor.format_version != 1 {
        return Err(manifest_error(
            &manifest_path,
            None,
            "既有辖制清单格式不受支持，拒绝覆盖",
        ));
    }
    let mut allowed = BTreeSet::from([PathBuf::from("言序-vendor.json")]);
    for package in vendor.packages.values() {
        validate_locked_dependency_source(&package.source)
            .map_err(|_| manifest_error(&manifest_path, None, "既有辖制清单含不安全的依赖来源"))?;
        if let Some(revision) = &package.revision {
            validate_git_revision_security(revision).map_err(|_| {
                manifest_error(&manifest_path, None, "既有辖制清单含不安全的 Git 修订")
            })?;
        }
        if !valid_sha256(&package.checksum) {
            return Err(manifest_error(
                &manifest_path,
                None,
                "既有辖制清单含无效的内容 SHA-256",
            ));
        }
        crate::path_policy::validate_portable_path_text(&package.path)
            .map_err(|error| package_path_manifest_error(destination, error))?;
        let relative = Path::new(&package.path);
        if relative.components().count() != 1 {
            return Err(manifest_error(
                &manifest_path,
                None,
                "既有辖制清单的包目录必须是单一相对组件",
            ));
        }
        package_path_decision(relative, PackagePathPurpose::ManifestReference)
            .map_err(|error| package_path_manifest_error(&manifest_path, error))?;
        let root = destination.join(relative);
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| manifest_error(&root, None, format!("不能检查既有辖制包：{error}")))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || standard_metadata_is_reparse(&metadata)
        {
            return Err(manifest_error(
                &root,
                None,
                "既有辖制包必须是真实、非重解析目录",
            ));
        }
        if !tree_checksum_matches(&root, &package.checksum)? {
            return Err(manifest_error(
                &root,
                None,
                "既有辖制包内容与辖制清单不符，拒绝覆盖",
            ));
        }
        allowed.insert(relative.to_path_buf());
    }
    for entry in fs::read_dir(destination).map_err(|error| {
        manifest_error(destination, None, format!("不能枚举既有辖制目录：{error}"))
    })? {
        let entry = entry.map_err(|error| {
            manifest_error(
                destination,
                None,
                format!("不能读取既有辖制目录项：{error}"),
            )
        })?;
        if !allowed.contains(&PathBuf::from(entry.file_name())) {
            return Err(manifest_error(
                entry.path(),
                None,
                "既有目录含不属于辖制清单的内容，拒绝覆盖",
            ));
        }
    }
    Ok(vendor)
}

fn sync_vendor_parent(path: &Path) -> Result<(), ManifestError> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| manifest_error(path, None, format!("不能同步辖制目录父目录：{error}")))?;
    #[cfg(not(unix))]
    // Windows 目录改名统一经过带 MOVEFILE_WRITE_THROUGH 的 rename_directory；
    // 其他非 Unix 目标没有可移植的父目录同步接口。
    let _ = path;
    Ok(())
}

fn sync_vendor_tree(root: &Path) -> Result<(), ManifestError> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        for entry in fs::read_dir(&directory).map_err(|error| {
            manifest_error(&directory, None, format!("不能枚举辖制暂存目录：{error}"))
        })? {
            let entry = entry.map_err(|error| {
                manifest_error(&directory, None, format!("不能读取辖制暂存目录项：{error}"))
            })?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                manifest_error(
                    entry.path(),
                    None,
                    format!("不能检查辖制暂存目录项：{error}"),
                )
            })?;
            if metadata.file_type().is_symlink() || standard_metadata_is_reparse(&metadata) {
                return Err(manifest_error(
                    entry.path(),
                    None,
                    "辖制暂存目录不得包含链接或重解析点",
                ));
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if !metadata.is_file() {
                return Err(manifest_error(
                    entry.path(),
                    None,
                    "辖制暂存目录不得包含特殊文件",
                ));
            }
        }
        index += 1;
    }
    #[cfg(unix)]
    for directory in directories.into_iter().rev() {
        fs::File::open(&directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                manifest_error(&directory, None, format!("不能同步辖制暂存目录：{error}"))
            })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VendorInstallState {
    Prepared,
    BackupReady,
    Published,
    Committed,
    RolledBack,
}

struct VendorInstallTransaction<'a, F> {
    staging: &'a Path,
    destination: &'a Path,
    backup: &'a Path,
    parent: &'a Path,
    previous: Option<&'a VendorManifest>,
    expected: &'a VendorManifest,
    state: VendorInstallState,
    checkpoint: &'a mut F,
}

impl<F> VendorInstallTransaction<'_, F>
where
    F: FnMut(VendorInstallCheckpoint, &Path) -> Result<(), ManifestError>,
{
    fn run(mut self) -> Result<(), ManifestError> {
        if self.previous.is_some()
            && let Err(error) = self.backup_existing()
        {
            return Err(self.rollback(error));
        }
        if let Err(error) = self.publish() {
            return Err(self.rollback(error));
        }
        if let Err(error) =
            (self.checkpoint)(VendorInstallCheckpoint::PublishValidation, self.destination)
        {
            return Err(self.rollback(error));
        }
        match validate_owned_vendor_directory(self.destination) {
            Ok(installed) if installed == *self.expected => {}
            Ok(_) => {
                let error =
                    manifest_error(self.destination, None, "发布后的辖制目录与暂存清单不一致");
                return Err(self.rollback(error));
            }
            Err(error) => return Err(self.rollback(error)),
        }
        if let Err(error) = self.sync_parent(VendorInstallCheckpoint::PublishSync) {
            return Err(self.rollback(error));
        }
        if self.previous.is_some() {
            if let Err(error) =
                (self.checkpoint)(VendorInstallCheckpoint::BackupCleanup, self.backup)
            {
                return Err(self.rollback(error));
            }
            if let Err(error) =
                self.validate_backup("旧辖制目录备份在最终清理前与事务开始时的清单不一致")
            {
                return Err(self.rollback(error));
            }
            if let Err(error) = fs::remove_dir_all(self.backup) {
                let error = manifest_error(
                    self.backup,
                    None,
                    format!("不能清理旧辖制目录备份：{error}"),
                );
                return Err(self.rollback(error));
            }
        }
        self.state = VendorInstallState::Committed;
        Ok(())
    }

    fn backup_existing(&mut self) -> Result<(), ManifestError> {
        (self.checkpoint)(VendorInstallCheckpoint::Backup, self.destination)?;
        rename_directory(self.destination, self.backup).map_err(|error| {
            manifest_error(
                self.destination,
                None,
                format!("不能暂存旧辖制目录：{error}"),
            )
        })?;
        self.state = VendorInstallState::BackupReady;
        self.validate_backup("旧辖制目录备份在发布前与事务开始时的清单不一致")?;
        self.sync_parent(VendorInstallCheckpoint::BackupSync)
    }

    fn validate_backup(&self, mismatch: &str) -> Result<(), ManifestError> {
        let Some(previous) = self.previous else {
            return Ok(());
        };
        match validate_owned_vendor_directory(self.backup) {
            Ok(found) if found == *previous => Ok(()),
            Ok(_) => Err(manifest_error(self.backup, None, mismatch)),
            Err(error) => Err(error),
        }
    }

    fn publish(&mut self) -> Result<(), ManifestError> {
        (self.checkpoint)(VendorInstallCheckpoint::Publish, self.destination)?;
        rename_directory(self.staging, self.destination).map_err(|error| {
            manifest_error(
                self.destination,
                None,
                format!("不能安装完整辖制目录：{error}"),
            )
        })?;
        self.state = VendorInstallState::Published;
        Ok(())
    }

    fn sync_parent(&mut self, point: VendorInstallCheckpoint) -> Result<(), ManifestError> {
        (self.checkpoint)(point, self.parent)?;
        sync_vendor_parent(self.parent)
    }

    fn rollback(&mut self, primary: ManifestError) -> ManifestError {
        let mut failures = Vec::new();
        let backup_valid = if let Some(previous) = self.previous {
            if matches!(
                self.state,
                VendorInstallState::BackupReady | VendorInstallState::Published
            ) {
                match (self.checkpoint)(VendorInstallCheckpoint::RestoreValidation, self.backup)
                    .and_then(|()| validate_owned_vendor_directory(self.backup))
                {
                    Ok(found) if found == *previous => true,
                    Ok(_) => {
                        failures.push(format!(
                            "{}：旧辖制目录备份与事务开始时的清单不一致",
                            self.backup.display()
                        ));
                        false
                    }
                    Err(error) => {
                        failures.push(vendor_transaction_failure_text(error));
                        false
                    }
                }
            } else {
                true
            }
        } else {
            true
        };

        let mut restored = backup_valid;
        if self.state == VendorInstallState::Published && restored {
            match (self.checkpoint)(VendorInstallCheckpoint::RollbackPublished, self.destination)
                .and_then(|()| {
                    rename_directory(self.destination, self.staging).map_err(|error| {
                        manifest_error(
                            self.destination,
                            None,
                            format!("不能撤回新辖制目录：{error}"),
                        )
                    })
                }) {
                Ok(()) => self.state = VendorInstallState::BackupReady,
                Err(error) => {
                    failures.push(vendor_transaction_failure_text(error));
                    restored = false;
                }
            }
        }
        if self.previous.is_some() && self.state == VendorInstallState::BackupReady && restored {
            match (self.checkpoint)(VendorInstallCheckpoint::Restore, self.destination).and_then(
                |()| {
                    rename_directory(self.backup, self.destination).map_err(|error| {
                        manifest_error(
                            self.destination,
                            None,
                            format!("不能恢复旧辖制目录：{error}"),
                        )
                    })
                },
            ) {
                Ok(()) => self.state = VendorInstallState::Prepared,
                Err(error) => {
                    failures.push(vendor_transaction_failure_text(error));
                    restored = false;
                }
            }
        }
        if restored {
            let validation = (self.checkpoint)(
                VendorInstallCheckpoint::RollbackValidation,
                self.destination,
            )
            .and_then(|()| match self.previous {
                Some(previous) => {
                    validate_owned_vendor_directory(self.destination).and_then(|found| {
                        if found == *previous {
                            Ok(())
                        } else {
                            Err(manifest_error(
                                self.destination,
                                None,
                                "恢复后的辖制目录与原清单不一致",
                            ))
                        }
                    })
                }
                None => match fs::symlink_metadata(self.destination) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Ok(_) => Err(manifest_error(
                        self.destination,
                        None,
                        "回滚后仍存在原先不存在的辖制目录",
                    )),
                    Err(error) => Err(manifest_error(
                        self.destination,
                        None,
                        format!("不能验证辖制目录回滚结果：{error}"),
                    )),
                },
            });
            if let Err(error) = validation {
                failures.push(vendor_transaction_failure_text(error));
                restored = false;
            }
        }
        if let Err(error) = self.sync_parent(VendorInstallCheckpoint::RollbackSync) {
            failures.push(vendor_transaction_failure_text(error));
            restored = false;
        }
        if restored && fs::symlink_metadata(self.staging).is_ok() {
            match (self.checkpoint)(VendorInstallCheckpoint::RollbackCleanup, self.staging)
                .and_then(|()| {
                    fs::remove_dir_all(self.staging).map_err(|error| {
                        manifest_error(
                            self.staging,
                            None,
                            format!("不能清理已撤回的辖制暂存目录：{error}"),
                        )
                    })
                }) {
                Ok(()) => {}
                Err(error) => failures.push(vendor_transaction_failure_text(error)),
            }
        }
        if restored {
            self.state = VendorInstallState::RolledBack;
        }
        for recovery in [self.staging, self.backup] {
            if fs::symlink_metadata(recovery).is_ok() {
                failures.push(format!("保留辖制事务恢复路径：{}", recovery.display()));
            }
        }
        vendor_combined_error(self.destination, primary, &failures)
    }
}

fn install_staged_vendor_directory(
    staging: &Path,
    destination: &Path,
    backup: &Path,
    expected: &VendorManifest,
    previous: Option<&VendorManifest>,
    checkpoint: &mut impl FnMut(VendorInstallCheckpoint, &Path) -> Result<(), ManifestError>,
) -> Result<(), ManifestError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    VendorInstallTransaction {
        staging,
        destination,
        backup,
        parent,
        previous,
        expected,
        state: VendorInstallState::Prepared,
        checkpoint,
    }
    .run()
}

fn vendor_transaction_failure_text(error: ManifestError) -> String {
    format!("{}：{}", error.path.display(), error.message)
}

fn vendor_combined_error(
    path: &Path,
    primary: ManifestError,
    failures: &[String],
) -> ManifestError {
    if failures.is_empty() {
        primary
    } else {
        manifest_error(
            path,
            None,
            format!(
                "{}；辖制事务回滚不完整：{}",
                primary.message,
                failures.join("；")
            ),
        )
    }
}

fn find_vendored_package(
    start: &Path,
    locked: &LockedPackage,
) -> Result<Option<PathBuf>, ManifestError> {
    for ancestor in start.ancestors() {
        for vendor_root in [ancestor.join("vendor"), ancestor.to_path_buf()] {
            let manifest_path = vendor_root.join("言序-vendor.json");
            match fs::symlink_metadata(&manifest_path) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(manifest_error(
                        &manifest_path,
                        None,
                        format!("不能检查辖制清单：{error}"),
                    ));
                }
            }
            let bytes = read_stable_metadata_file_snapshot(
                &manifest_path,
                VENDOR_MANIFEST_MAX_BYTES,
                "辖制清单",
            )?;
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

fn write_package_tree_snapshot(
    snapshot: &PackageTreeSnapshot,
    destination: &Path,
) -> Result<(), ManifestError> {
    fs::create_dir(destination).map_err(|error| {
        manifest_error(destination, None, format!("不能创建辖制包目录：{error}"))
    })?;
    for entry in &snapshot.files {
        let target = destination.join(&entry.relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                manifest_error(parent, None, format!("不能创建辖制目录：{error}"))
            })?;
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| {
                manifest_error(&target, None, format!("不能创建辖制包文件：{error}"))
            })?;
        output.write_all(&entry.bytes).map_err(|error| {
            manifest_error(&target, None, format!("不能写入辖制包文件：{error}"))
        })?;
        output.sync_all().map_err(|error| {
            manifest_error(&target, None, format!("不能同步辖制包文件：{error}"))
        })?;
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
        let bytes = read_stable_metadata_file_snapshot(
            &temporary,
            ARCHIVE_MAX_COMPRESSED_BYTES,
            "下载结果",
        )?;
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

fn bounded_command_output(
    command: &mut Command,
    path: &Path,
    action: &str,
    program_kind: &str,
    budget: subprocess::CommandBudget<'_>,
) -> Result<subprocess::CommandOutput, ManifestError> {
    subprocess::run(command, budget)
        .map_err(|failure| bounded_command_error(path, action, program_kind, failure))
}

fn bounded_command_error(
    path: &Path,
    action: &str,
    program_kind: &str,
    failure: subprocess::CommandFailure,
) -> ManifestError {
    use subprocess::{CommandFailure, OutputStream};

    let stream_name = |stream| match stream {
        OutputStream::Stdout => "标准输出",
        OutputStream::Stderr => "标准错误",
    };
    let message = match failure {
        CommandFailure::Spawn => format!("{action}失败：不能启动{program_kind}"),
        CommandFailure::Containment => format!(
            "[PACKAGE_SUBPROCESS_CONTAINMENT] {action}失败：不能建立可完整回收的{program_kind}进程树"
        ),
        CommandFailure::Wait => format!("{action}失败：不能等候{program_kind}进程"),
        CommandFailure::ReaderSpawn(stream) => format!(
            "{action}失败：不能启动{program_kind}{}有界读取线程",
            stream_name(stream)
        ),
        CommandFailure::Read(stream) => format!(
            "{action}失败：不能有界读取{program_kind}{}",
            stream_name(stream)
        ),
        CommandFailure::ReaderPanicked(stream) => format!(
            "{action}失败：读取{program_kind}{}的线程异常",
            stream_name(stream)
        ),
        CommandFailure::Timeout(timeout) => format!(
            "[PACKAGE_SUBPROCESS_TIMEOUT] {action}超过 {} 毫秒，已终止并回收{program_kind}进程树",
            timeout.as_millis()
        ),
        CommandFailure::Cancelled => format!(
            "[PACKAGE_SUBPROCESS_CANCELLED] {action}已取消，已终止并回收{program_kind}进程树"
        ),
        CommandFailure::OutputLimit { stream, max_bytes } => format!(
            "[PACKAGE_SUBPROCESS_OUTPUT_LIMIT] {action}的{program_kind}{}超过 {max_bytes} 字节上限，已终止并回收进程树",
            stream_name(stream)
        ),
        CommandFailure::DiskBytes(max_bytes) => format!(
            "[PACKAGE_SUBPROCESS_DISK_LIMIT] {action}的临时磁盘内容超过 {max_bytes} 字节上限，已终止并回收{program_kind}进程树"
        ),
        CommandFailure::DiskEntries(max_entries) => format!(
            "[PACKAGE_SUBPROCESS_DISK_LIMIT] {action}的临时磁盘内容超过 {max_entries} 项上限，已终止并回收{program_kind}进程树"
        ),
        CommandFailure::DiskDepth(max_depth) => format!(
            "[PACKAGE_SUBPROCESS_DISK_LIMIT] {action}的临时磁盘目录超过 {max_depth} 层上限，已终止并回收{program_kind}进程树"
        ),
        CommandFailure::DiskSpecial => format!(
            "[PACKAGE_SUBPROCESS_DISK_LIMIT] {action}的临时磁盘内容出现链接、重解析点或特殊文件，已终止并回收{program_kind}进程树"
        ),
        CommandFailure::DiskRead => format!(
            "[PACKAGE_SUBPROCESS_DISK_LIMIT] {action}的临时磁盘内容无法安全计量，已终止并回收{program_kind}进程树"
        ),
        #[cfg(target_os = "wasi")]
        CommandFailure::Unsupported => {
            format!("{action}失败：当前目标不支持启动{program_kind}")
        }
    };
    manifest_error(path, None, message)
}

fn command_status_result(
    output: subprocess::CommandOutput,
    path: &Path,
    action: &str,
) -> Result<(), ManifestError> {
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

fn run_git_command(
    command: &mut Command,
    path: &Path,
    action: &str,
    timeout: Duration,
    disk: Option<subprocess::DiskBudget<'_>>,
) -> Result<(), ManifestError> {
    let output = bounded_command_output(
        command,
        path,
        action,
        "Git",
        subprocess::CommandBudget {
            timeout,
            stdout_bytes: 0,
            stderr_bytes: GIT_COMMAND_STDERR_MAX_BYTES,
            disk,
            cancellation: None,
        },
    )?;
    command_status_result(output, path, action)
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

    fn vendor_fixture_graph(root: &Path, marker: &str) -> ResolutionGraph {
        let dependency_root = root.join(format!("dependency-{marker}"));
        write(
            &dependency_root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='fixture'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(
            &dependency_root.join("主.yx"),
            &format!("公 定 标记 为「{marker}」；\n"),
        );
        let checksum = tree_checksum(&dependency_root).unwrap();
        let id = "fixture@1.0.0".to_owned();
        let locked = LockedPackage {
            id: id.clone(),
            name: "fixture".into(),
            version: "1.0.0".into(),
            source: "registry:https://packages.example.invalid/v1".into(),
            revision: None,
            checksum,
            entry: "主.yx".into(),
            dependencies: BTreeMap::new(),
            exports: BTreeMap::new(),
            target: current_target(),
            native: None,
            minimum_yanxu: None,
        };
        ResolutionGraph {
            root_dependencies: BTreeMap::from([("fixture".into(), id.clone())]),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::from([(
                id,
                ResolvedDependency {
                    locked,
                    entry: dependency_root.join("主.yx"),
                    root: dependency_root,
                },
            )]),
            target: current_target(),
        }
    }

    fn vendor_tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(base: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(!metadata.file_type().is_symlink());
                if metadata.is_dir() {
                    visit(base, &path, files);
                } else {
                    assert!(metadata.is_file());
                    files.insert(
                        path.strip_prefix(base).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn vendor_transaction_artifacts(parent: &Path, destination_name: &str) -> Vec<PathBuf> {
        let staging_prefix = format!(".{destination_name}.staging-");
        let backup_prefix = format!(".{destination_name}.backup-");
        let mut artifacts = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.starts_with(&staging_prefix) || name.starts_with(&backup_prefix)
            })
            .collect::<Vec<_>>();
        artifacts.sort();
        artifacts
    }

    fn run_git_fixture(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?}");
    }

    fn git_fixture_head(root: &Path) -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn make_git_fixture_cache_writable(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(if metadata.is_dir() { 0o700 } else { 0o600 });
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).ok();
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(path) else {
                return;
            };
            for entry in entries.filter_map(Result::ok) {
                make_git_fixture_cache_writable(&entry.path());
            }
        }
    }

    fn remove_git_fixture_cache(url: &str) {
        let Ok(cache) = git_cache_layout_root() else {
            return;
        };
        let identity = git_cache_identity(url);
        let source = cache.join(&identity);
        make_git_fixture_cache_writable(&source);
        fs::remove_dir_all(source).ok();
        fs::remove_dir_all(cache.join(".locks").join(identity)).ok();
    }

    fn read_dependency_entry(
        dependency: &ResolvedDependency,
        capabilities: &ResolutionCapabilities,
    ) -> String {
        let mut roots = TrustedPackageRoots::new();
        capabilities.extend(&mut roots).unwrap();
        let resolved = roots
            .resolve_existing_module_file(&dependency.entry)
            .unwrap()
            .expect("dependency entry belongs to the resolved generation");
        read_resolved_module_source_snapshot(resolved).unwrap()
    }

    fn lock_with_source(source: impl Into<String>) -> LockFile {
        LockFile {
            lock_version: 1,
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
    fn pack_accepts_a_manifest_loaded_from_a_relative_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let relative_root = PathBuf::from(format!("relative-pack-{unique}"));
        write(
            &relative_root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='相对打包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&relative_root.join("主.yx"), "言「相对打包」；\n");
        let manifest = load(relative_root.join(MANIFEST_NAME)).unwrap();
        assert!(manifest.root.is_relative());
        let output_root = temp("relative-pack-output");
        fs::create_dir_all(&output_root).unwrap();
        let output = output_root.join("package.yxp");

        pack_package(&manifest, &output).unwrap();
        let unpacked = output_root.join("unpacked");
        extract_archive_safely(&output, &unpacked).unwrap();
        assert_eq!(
            fs::read_to_string(unpacked.join("package/主.yx")).unwrap(),
            "言「相对打包」；\n"
        );
        fs::remove_dir_all(relative_root).unwrap();
        fs::remove_dir_all(output_root).unwrap();
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
            tar::EntryType::GNULongName,
            tar::EntryType::GNULongLink,
            tar::EntryType::XHeader,
            tar::EntryType::XGlobalHeader,
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
                .map(|resolved| resolved.graph.clone());
            assert_eq!(cached, Some(graph));
            Ok::<_, ManifestError>(())
        })
        .unwrap();
        fs::remove_dir_all(relative).ok();
    }

    #[test]
    fn cached_resolution_rejects_replaced_source_root_and_keeps_verified_generation() {
        let root = temp("resolution-root-replacement");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let verified = format!("# {marker}\n公 定 值：数 为 1；\n");
        let replaced = format!("# {marker}\n公 定 值：数 为 2；\n");
        write(&dependency.join("主.yx"), &verified);
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let (resolved, capabilities) =
            resolve_dependency_scoped_with_capabilities(Some(&application), &application, "工具")
                .unwrap();
        assert_eq!(read_dependency_entry(&resolved, &capabilities), verified);

        let original = root.join("dependency-original");
        fs::rename(&dependency, &original).unwrap();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), &replaced);
        let error =
            resolve_dependency_scoped(Some(&application), &application, "工具").unwrap_err();
        assert!(error.message.contains("锁") || error.message.contains("变化"));
        assert_eq!(read_dependency_entry(&resolved, &capabilities), verified);

        fs::remove_dir_all(&dependency).unwrap();
        fs::rename(original, dependency).unwrap();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tooling_dependency_resolution_binds_the_discovered_application_root() {
        let root = temp("tooling-resolution-root");
        let application = root.join("application");
        let original = root.join("application-original");
        let dependency = root.join("dependency");
        let manifest_text =
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n";
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值：数 为 1；\n");
        write(&application.join(MANIFEST_NAME), manifest_text);
        write(&application.join("主.yx"), "引「包:工具」为 工具；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let lock_before = fs::read(application.join(LOCK_NAME)).unwrap();
        graph_cache()
            .lock()
            .expect("graph cache poisoned")
            .remove(&graph_cache_key(&application));
        let mut opened_roots = TrustedPackageRoots::default();
        opened_roots.insert(&application).unwrap();

        let (resolved, capabilities) = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "工具",
        )
        .unwrap();
        assert_eq!(
            read_dependency_entry(&resolved, &capabilities),
            "公 定 值：数 为 1；\n"
        );
        assert_eq!(fs::read(application.join(LOCK_NAME)).unwrap(), lock_before);
        let (reused, reused_capabilities) = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "工具",
        )
        .unwrap();
        assert_eq!(
            read_dependency_entry(&reused, &reused_capabilities),
            "公 定 值：数 为 1；\n"
        );

        let lock_path = application.join(LOCK_NAME);
        let mut stale_lock = read_optional_lock(&lock_path).unwrap().unwrap();
        stale_lock.manifest_checksum = "0".repeat(64);
        write(&lock_path, &toml::to_string(&stale_lock).unwrap());
        let stale_lock_before = fs::read(&lock_path).unwrap();
        graph_cache()
            .lock()
            .expect("graph cache poisoned")
            .remove(&graph_cache_key(&application));
        for _ in 0..2 {
            let (resolved, capabilities) = resolve_dependency_scoped_with_opened_capabilities(
                &opened_roots,
                Some(&application),
                &application,
                "工具",
            )
            .unwrap();
            assert_eq!(
                read_dependency_entry(&resolved, &capabilities),
                "公 定 值：数 为 1；\n"
            );
            assert_eq!(fs::read(&lock_path).unwrap(), stale_lock_before);
        }

        fs::rename(&application, &original).unwrap();
        write(&application.join(MANIFEST_NAME), manifest_text);
        write(&application.join("主.yx"), "引「包:工具」为 工具；\n");
        graph_cache()
            .lock()
            .expect("graph cache poisoned")
            .remove(&graph_cache_key(&application));
        let error = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "工具",
        )
        .unwrap_err();
        assert!(
            error.message.contains("工具包根在目录发现后被替换"),
            "{error}"
        );

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn native_dependency_resolution_uses_real_name_direct_edge_without_lock_side_effects() {
        let root = temp("native-resolution-direct-edge");
        let application = root.join("application");
        let original = root.join("application-original");
        let dependency = root.join("dependency");
        let manifest_text = "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n别名={包='真实工具',路径='../dependency',版='^1'}\n";
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='真实工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值：数 为 1；\n");
        write(&application.join(MANIFEST_NAME), manifest_text);
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let lock_path = application.join(LOCK_NAME);
        let lock_before = fs::read(&lock_path).unwrap();
        graph_cache()
            .lock()
            .expect("graph cache poisoned")
            .remove(&graph_cache_key(&application));
        let mut opened_roots = TrustedPackageRoots::default();
        opened_roots.insert(&application).unwrap();

        let (resolved, capabilities) = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "真实工具",
        )
        .unwrap();
        assert_eq!(resolved.locked.name, "真实工具");
        assert!(capabilities.roots().matching_root(&resolved.root).is_some());
        assert_eq!(fs::read(&lock_path).unwrap(), lock_before);
        let error = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "别名",
        )
        .unwrap_err();
        assert!(error.message.contains("没有直接声明名为“别名”"), "{error}");

        fs::rename(&application, &original).unwrap();
        write(&application.join(MANIFEST_NAME), manifest_text);
        write(&application.join("主.yx"), "言 2；\n");
        graph_cache()
            .lock()
            .expect("graph cache poisoned")
            .remove(&graph_cache_key(&application));
        let error = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "真实工具",
        )
        .unwrap_err();
        assert!(
            error.message.contains("应用包根在执行开始后被替换"),
            "{error}"
        );
        assert!(!application.join(LOCK_NAME).exists());
        assert_eq!(fs::read(original.join(LOCK_NAME)).unwrap(), lock_before);

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn native_dependency_resolution_binds_edges_to_the_calling_package_root() {
        let root = temp("native-resolution-calling-package");
        let application = root.join("application");
        let middle = root.join("middle");
        let native = root.join("native");
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n中间={包='中间包',路径='../middle',版='^1'}\n",
        );
        write(&application.join("src/主.yx"), "言 1；\n");
        write(
            &middle.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='中间包'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n原生别名={包='真实原生',路径='../native',版='^1'}\n",
        );
        write(&middle.join("src/主.yx"), "公 定 值：数 为 1；\n");
        write(
            &native.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='真实原生'\n版本='1.0.0'\n入口='src/主.yx'\n",
        );
        write(&native.join("src/主.yx"), "公 定 ABI：数 为 2；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let lock_path = application.join(LOCK_NAME);
        let lock_before = fs::read(&lock_path).unwrap();
        let mut opened_roots = TrustedPackageRoots::default();
        opened_roots.insert(&application).unwrap();
        let (middle_dependency, capabilities) = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application,
            "中间",
        )
        .unwrap();
        capabilities.extend(&mut opened_roots).unwrap();

        let (native_dependency, _) = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &middle_dependency.root.join("src"),
            "真实原生",
        )
        .unwrap();
        assert_eq!(native_dependency.locked.name, "真实原生");
        let error = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &application.join("src"),
            "真实原生",
        )
        .unwrap_err();
        assert!(error.message.contains("没有直接声明"), "{error}");
        let error = resolve_native_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            Some(&application),
            &middle_dependency.root.join("src"),
            "原生别名",
        )
        .unwrap_err();
        assert!(error.message.contains("没有直接声明"), "{error}");
        assert_eq!(fs::read(lock_path).unwrap(), lock_before);

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tooling_dependency_resolution_ignores_a_new_nested_manifest() {
        let root = temp("tooling-resolution-nested-manifest");
        let application = root.join("application");
        let nested = application.join("文档");
        let dependency = root.join("dependency");
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言「应用」；\n");
        write(&nested.join("用例.yx"), "引「包:工具」为 工具；\n");
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&dependency.join("主.yx"), "公 定 值：数 为 1；\n");
        let mut opened_roots = TrustedPackageRoots::default();
        opened_roots.insert(&application).unwrap();

        write(
            &nested.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='替换包'\n版本='1.0.0'\n入口='用例.yx'\n[依赖]\n",
        );
        let (resolved, capabilities) = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            None,
            &nested,
            "工具",
        )
        .unwrap();

        assert_eq!(
            read_dependency_entry(&resolved, &capabilities),
            "公 定 值：数 为 1；\n"
        );
        let (reused, reused_capabilities) = resolve_dependency_scoped_with_opened_capabilities(
            &opened_roots,
            None,
            &nested,
            "工具",
        )
        .unwrap();
        assert_eq!(
            read_dependency_entry(&reused, &reused_capabilities),
            "公 定 值：数 为 1；\n"
        );
        assert!(!application.join(LOCK_NAME).exists());
        assert!(!nested.join(LOCK_NAME).exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cached_resolution_hashes_same_length_source_changes_before_reuse() {
        let root = temp("resolution-same-length-change");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let verified = format!("# {marker}\n公 定 值：数 为 1；\n");
        let changed = format!("# {marker}\n公 定 值：数 为 2；\n");
        assert_eq!(verified.len(), changed.len());
        write(&dependency.join("主.yx"), &verified);
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let (resolved, capabilities) =
            resolve_dependency_scoped_with_capabilities(Some(&application), &application, "工具")
                .unwrap();
        write(&dependency.join("主.yx"), &changed);
        let error =
            resolve_dependency_scoped(Some(&application), &application, "工具").unwrap_err();
        assert!(error.message.contains("锁") || error.message.contains("变化"));
        assert_eq!(read_dependency_entry(&resolved, &capabilities), verified);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn graph_cache_revalidates_manifest_lock_and_target_fingerprints() {
        let root = temp("resolution-cache-fingerprints");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(
            &dependency.join("主.yx"),
            &format!("# {marker}\n公 定 值：数 为 1；\n"),
        );
        let manifest_path = application.join(MANIFEST_NAME);
        write(
            &manifest_path,
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(&manifest_path).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let key = graph_cache_key(&manifest.root);
        let initial_manifest_checksum = graph_cache()
            .lock()
            .unwrap()
            .get(&key)
            .unwrap()
            .manifest_checksum
            .clone();

        graph_cache()
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .graph
            .target = "不匹配目标".into();
        let target_error =
            resolve_dependency_scoped(Some(&application), &application, "工具").unwrap_err();
        assert!(target_error.message.contains("目标"));
        ensure_lock(&manifest, false).unwrap();
        assert_eq!(
            graph_cache()
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .graph
                .target,
            current_target()
        );

        write(
            &manifest_path,
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n描述='缓存指纹变化'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        let manifest_error =
            resolve_dependency_scoped(Some(&application), &application, "工具").unwrap_err();
        assert!(manifest_error.message.contains("清单"));
        let current_manifest = load(&manifest_path).unwrap();
        ensure_lock(&current_manifest, false).unwrap();
        assert_ne!(
            graph_cache()
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .manifest_checksum,
            initial_manifest_checksum
        );

        let lock_path = application.join(LOCK_NAME);
        let mut lock = read_lock(&lock_path).unwrap();
        lock.packages[0].checksum = "f".repeat(64);
        fs::write(&lock_path, toml::to_string_pretty(&lock).unwrap()).unwrap();
        let error =
            resolve_dependency_scoped(Some(&application), &application, "工具").unwrap_err();
        assert!(error.message.contains("锁") || error.message.contains("校验"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolution_binds_manifest_structure_and_digest_to_one_snapshot() {
        let root = temp("resolution-manifest-snapshot");
        let manifest_path = root.join(MANIFEST_NAME);
        write(
            &manifest_path,
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(&manifest_path).unwrap();
        let (application_root, application_roots, _) = bind_resolution_manifest(&manifest).unwrap();

        write(
            &manifest_path,
            "[包]\n格式=2\n名称='替换应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let changed_checksum = bound_file_checksum(
            &application_roots,
            &application_root.join(MANIFEST_NAME),
            PackagePathPurpose::ManifestReference,
            MANIFEST_MAX_BYTES,
            "包清单",
        )
        .unwrap();
        let error = resolve_graph_mode_locked_with_checksum(
            &manifest,
            false,
            false,
            true,
            changed_checksum,
            application_root,
            application_roots,
        )
        .unwrap_err();
        assert!(error.message.contains("清单"));
        assert!(error.message.contains("结构") || error.message.contains("变化"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolution_binds_lock_structure_and_digest_to_one_snapshot() {
        let root = temp("resolution-lock-snapshot");
        let manifest_path = root.join(MANIFEST_NAME);
        write(
            &manifest_path,
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let manifest = load(&manifest_path).unwrap();
        let (application_root, application_roots, manifest_checksum) =
            bind_resolution_manifest(&manifest).unwrap();
        let graph = ResolutionGraph {
            root_dependencies: BTreeMap::new(),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::new(),
            target: current_target(),
        };
        let expected = LockFile {
            lock_version: LOCK_FORMAT_VERSION,
            manifest_checksum: manifest_checksum.clone(),
            target: graph.target.clone(),
            generator: package_core_version(),
            root_dependencies: BTreeMap::new(),
            root_dev_dependencies: BTreeMap::new(),
            packages: Vec::new(),
        };
        let mut replaced = expected.clone();
        replaced.generator = "替换生成器".into();
        write_lock(&root.join(LOCK_NAME), &replaced).unwrap();

        let error = freeze_resolution_graph(
            &manifest,
            graph,
            manifest_checksum,
            application_root,
            application_roots,
            Some(&expected),
        )
        .unwrap_err();
        assert!(error.message.contains("锁文件"));
        assert!(error.message.contains("结构"));
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolution_cache_rejects_linked_lock_and_checksum_directories() {
        use std::os::unix::fs::symlink;

        let root = temp("resolution-cache-links");
        let cache = root.join("cache");
        let outside = root.join("outside");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, cache.join(".locks")).unwrap();
        let checksum = "a".repeat(64);
        let lock_error = match acquire_resolution_generation_lock(&cache, &checksum) {
            Ok(_) => panic!("linked resolution cache lock was accepted"),
            Err(error) => error,
        };
        assert!(lock_error.message.contains("链接"));
        fs::remove_file(cache.join(".locks")).unwrap();

        fs::create_dir(cache.join(".locks")).unwrap();
        symlink(&outside, cache.join(".locks").join(&checksum)).unwrap();
        let component_error = match acquire_resolution_generation_lock(&cache, &checksum) {
            Ok(_) => panic!("linked resolution cache lock component was accepted"),
            Err(error) => error,
        };
        assert!(component_error.message.contains("链接"));
        assert!(!outside.join(".yanxu/package.lock").exists());
        fs::remove_file(cache.join(".locks").join(&checksum)).unwrap();

        symlink(&outside, cache.join(&checksum)).unwrap();
        let checksum_error = create_resolution_checksum_root(&cache, &checksum).unwrap_err();
        assert!(checksum_error.message.contains("链接"));
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn reused_resolution_generation_restores_read_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp("resolution-generation-permissions");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(
            &dependency.join("主.yx"),
            &format!("# {marker}\n公 定 值：数 为 1；\n"),
        );
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        let first = ensure_lock_with_dev(&manifest, false).unwrap();
        let first = first.packages.values().next().unwrap();
        fs::set_permissions(&first.entry, fs::Permissions::from_mode(0o600)).unwrap();

        let reused = ensure_lock_with_dev(&manifest, true).unwrap();
        let reused = reused.packages.values().next().unwrap();
        assert_eq!(reused.root, first.root);
        assert_eq!(
            fs::metadata(&reused.entry).unwrap().permissions().mode() & 0o777,
            0o400
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolved_capability_reads_original_generation_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp("resolution-generation-capability");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let verified = format!("# {marker}\n公 定 值：数 为 1；\n");
        write(&dependency.join("主.yx"), &verified);
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        ensure_lock(&manifest, false).unwrap();
        let (resolved, capabilities) =
            resolve_dependency_scoped_with_capabilities(Some(&application), &application, "工具")
                .unwrap();

        let generation_root = resolved.root.clone();
        let generation_parent = generation_root.parent().unwrap();
        fs::set_permissions(generation_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let captured = generation_parent.join("captured-package");
        fs::rename(&generation_root, &captured).unwrap();
        write(&generation_root.join("主.yx"), "公 定 值：数 为 9；\n");
        assert_eq!(read_dependency_entry(&resolved, &capabilities), verified);

        fs::remove_dir_all(&generation_root).unwrap();
        fs::rename(captured, &generation_root).unwrap();
        fs::set_permissions(generation_parent, fs::Permissions::from_mode(0o500)).unwrap();
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn damaged_resolution_generation_is_preserved_while_repair_is_published() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp("resolution-generation-repair");
        let application = root.join("application");
        let dependency = root.join("dependency");
        let marker = root.file_name().unwrap().to_string_lossy();
        write(
            &dependency.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        let verified = format!("# {marker}\n公 定 值：数 为 1；\n");
        let damaged = format!("# {marker}\n公 定 值：数 为 2；\n");
        write(&dependency.join("主.yx"), &verified);
        write(
            &application.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n工具='../dependency'\n",
        );
        write(&application.join("主.yx"), "言 1；\n");
        let manifest = load(application.join(MANIFEST_NAME)).unwrap();
        let first = ensure_lock_with_dev(&manifest, false).unwrap();
        let first = first.packages.values().next().unwrap();
        let first_root = first.root.clone();
        let first_entry = first.entry.clone();
        fs::set_permissions(&first_entry, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&first_entry, &damaged).unwrap();

        let repaired = ensure_lock_with_dev(&manifest, true).unwrap();
        let repaired = repaired.packages.values().next().unwrap();
        assert_ne!(repaired.root, first_root);
        assert_eq!(fs::read_to_string(&first_entry).unwrap(), damaged);
        assert_eq!(fs::read_to_string(&repaired.entry).unwrap(), verified);

        fs::write(&first_entry, &verified).unwrap();
        fs::set_permissions(&first_entry, fs::Permissions::from_mode(0o400)).unwrap();
        fs::remove_dir_all(root).ok();
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
    fn offline_registry_cache_migrates_legacy_content_without_consuming_it() {
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
        let resolved = valid.resolved.unwrap();
        let generation = registry_snapshot_checksum_root(&key, &checksum)
            .join(registry_legacy_generation_id(&checksum));
        assert_eq!(resolved.root, fs::canonicalize(&generation).unwrap());
        assert_ne!(resolved.root, fs::canonicalize(&legacy).unwrap());
        assert_eq!(
            fs::read_to_string(resolved.root.join("主.yx")).unwrap(),
            "公 定 值 为 1；\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&registry_cache).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&resolved.root).unwrap().permissions().mode() & 0o777,
                0o500
            );
            assert_eq!(
                fs::metadata(resolved.root.join("主.yx"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }

        let mut root_permissions = fs::metadata(&resolved.root).unwrap().permissions();
        let mut entry_permissions = fs::metadata(resolved.root.join("主.yx"))
            .unwrap()
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            root_permissions.set_mode(0o700);
            entry_permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        {
            #[allow(clippy::permissions_set_readonly_false)]
            root_permissions.set_readonly(false);
            #[allow(clippy::permissions_set_readonly_false)]
            entry_permissions.set_readonly(false);
        }
        fs::set_permissions(&resolved.root, root_permissions).unwrap();
        fs::set_permissions(resolved.root.join("主.yx"), entry_permissions).unwrap();

        fs::remove_file(legacy.join("主.yx")).unwrap();
        let reused = find_cached_registry_package_locked(&key, &checksum, true)
            .unwrap()
            .resolved
            .unwrap();
        assert_eq!(reused.root, resolved.root);
        assert_eq!(
            fs::read_to_string(reused.root.join("主.yx")).unwrap(),
            "公 定 值 为 1；\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&reused.root).unwrap().permissions().mode() & 0o777,
                0o500
            );
            assert_eq!(
                fs::metadata(reused.root.join("主.yx"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        #[cfg(not(unix))]
        {
            assert!(fs::metadata(&reused.root).unwrap().permissions().readonly());
            assert!(
                fs::metadata(reused.root.join("主.yx"))
                    .unwrap()
                    .permissions()
                    .readonly()
            );
        }
        assert!(legacy.is_dir());
        assert!(legacy.join(MANIFEST_NAME).is_file());
        drop(_cache_lock);
        make_git_fixture_cache_writable(&root);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn legacy_registry_migration_failures_preserve_source_and_hide_candidates() {
        let root = temp("legacy-registry-migration-failure");
        let registry_cache = root.join("cache");
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let legacy = registry_cache.join("缓存包/1.0.0");
        write(
            &legacy.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缓存包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&legacy.join("主.yx"), "迁移前内容\n");
        let checksum = tree_checksum(&legacy).unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "缓存包",
            version: &version,
            requirement: &requirement,
        };
        let _cache_lock = acquire_registry_package_lock(&key).unwrap();
        let generation_id = registry_legacy_generation_id(&checksum);
        for failure in [
            RegistryInstallCheckpoint::BeforeCopyEntry,
            RegistryInstallCheckpoint::BeforePublish,
        ] {
            let error = publish_registry_tree_locked(
                &key,
                &legacy,
                &checksum,
                &generation_id,
                &mut |point, path| {
                    if point == failure {
                        Err(manifest_error(path, None, "模拟旧缓存迁移失败"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert!(error.message.contains("模拟旧缓存迁移失败"));
            assert_eq!(
                fs::read_to_string(legacy.join("主.yx")).unwrap(),
                "迁移前内容\n"
            );
            let checksum_root = registry_snapshot_checksum_root(&key, &checksum);
            assert!(
                !checksum_root.exists()
                    || fs::read_dir(checksum_root).unwrap().all(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with('.'))
            );
        }
        assert!(legacy.is_dir());
        drop(_cache_lock);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_legacy_registry_migration_reuses_one_generation() {
        let root = temp("concurrent-legacy-registry-migration");
        let registry_cache = root.join("cache");
        let legacy = registry_cache.join("并发包/1.0.0");
        write(
            &legacy.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='并发包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&legacy.join("主.yx"), "并发迁移内容\n");
        let checksum = tree_checksum(&legacy).unwrap();
        let threads = (0..8)
            .map(|_| {
                let registry_cache = registry_cache.clone();
                let checksum = checksum.clone();
                std::thread::spawn(move || {
                    let version = Version::new(1, 0, 0);
                    let requirement = VersionReq::parse("^1").unwrap();
                    let key = RegistryPackageKey {
                        registry_cache: &registry_cache,
                        registry: "https://packages.example.invalid/v1",
                        name: "并发包",
                        version: &version,
                        requirement: &requirement,
                    };
                    let _cache_lock = acquire_registry_package_lock(&key).unwrap();
                    find_cached_registry_package_locked(&key, &checksum, true)
                        .unwrap()
                        .resolved
                        .unwrap()
                        .root
                })
            })
            .collect::<Vec<_>>();
        let generations = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(generations.windows(2).all(|pair| pair[0] == pair[1]));
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "并发包",
            version: &version,
            requirement: &requirement,
        };
        let checksum_root = registry_snapshot_checksum_root(&key, &checksum);
        assert_eq!(
            fs::read_dir(checksum_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
                .count(),
            1
        );
        assert_eq!(
            fs::read_to_string(legacy.join("主.yx")).unwrap(),
            "并发迁移内容\n"
        );
        make_git_fixture_cache_writable(&root);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn legacy_registry_migration_rejects_linked_cache_paths() {
        use std::os::unix::fs::symlink;

        let root = temp("legacy-registry-link-rejection");
        let registry_cache = root.join("cache");
        let outside = root.join("outside");
        fs::create_dir_all(&registry_cache).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let version = Version::new(1, 0, 0);
        let requirement = VersionReq::parse("^1").unwrap();
        let key = RegistryPackageKey {
            registry_cache: &registry_cache,
            registry: "https://packages.example.invalid/v1",
            name: "链接包",
            version: &version,
            requirement: &requirement,
        };

        symlink(&outside, registry_cache.join(".locks")).unwrap();
        let lock_error = match acquire_registry_package_lock(&key) {
            Ok(_) => panic!("linked registry cache lock was accepted"),
            Err(error) => error,
        };
        assert!(lock_error.message.contains("链接"));
        assert!(!outside.join(".yanxu/package.lock").exists());
        fs::remove_file(registry_cache.join(".locks")).unwrap();

        let package_root = registry_cache.join("链接包");
        fs::create_dir(&package_root).unwrap();
        symlink(&outside, package_root.join(".snapshots")).unwrap();
        let snapshot_lock = acquire_registry_package_lock(&key).unwrap();
        let lookup = find_cached_registry_package_locked(&key, &"a".repeat(64), false).unwrap();
        assert!(lookup.resolved.is_none());
        assert!(lookup.invalid.unwrap().message.contains("链接"));
        let snapshot_error =
            create_registry_snapshot_checksum_root(&key, &"a".repeat(64)).unwrap_err();
        assert!(snapshot_error.message.contains("链接"));
        drop(snapshot_lock);
        fs::remove_file(package_root.join(".snapshots")).unwrap();

        write(
            &outside.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='链接包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&outside.join("主.yx"), "外部内容\n");
        let checksum = tree_checksum(&outside).unwrap();
        symlink(&outside, registry_legacy_root(&key)).unwrap();
        let _cache_lock = acquire_registry_package_lock(&key).unwrap();
        let lookup = find_cached_registry_package_locked(&key, &checksum, true).unwrap();
        assert!(lookup.resolved.is_none());
        assert!(lookup.invalid.is_some());
        assert!(registry_legacy_root(&key).is_symlink());
        assert_eq!(
            fs::read_to_string(outside.join("主.yx")).unwrap(),
            "外部内容\n"
        );
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
        let entry = first.root.join("主.yx");
        let mut permissions = fs::metadata(&entry).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&entry, permissions).unwrap();
        write(&entry, "损坏内容\n");
        let invalid =
            find_cached_registry_package_locked(&key, &first.locked.checksum, false).unwrap();
        assert!(invalid.resolved.is_none());
        assert!(invalid.invalid.is_some());
        assert!(first.root.is_dir());
        drop(_cache_lock);
        make_git_fixture_cache_writable(&root);
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
        let initial_entry = initial.root.join("主.yx");
        let mut permissions = fs::metadata(&initial_entry).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&initial_entry, permissions).unwrap();
        write(&initial_entry, "已损坏的旧快照\n");
        let damaged = fs::read(&initial_entry).unwrap();

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
        make_git_fixture_cache_writable(&root);
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
        assert_ne!(
            dependencies["工具"].root,
            fs::canonicalize(dependency).unwrap()
        );
        assert_eq!(
            fs::read_to_string(&dependencies["工具"].entry).unwrap(),
            "公 定 值 为 1；\n"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_replaces_an_owned_directory_without_leaving_transaction_artifacts() {
        let root = temp("vendor-replace");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        let old_graph = vendor_fixture_graph(&root, "old");
        let old = vendor_dependencies(&old_graph, &destination).unwrap();
        let old_bytes = vendor_tree_bytes(&destination);
        let new_graph = vendor_fixture_graph(&root, "new");

        let installed = vendor_dependencies(&new_graph, &destination).unwrap();

        assert_ne!(installed, old);
        assert_eq!(
            validate_owned_vendor_directory(&destination).unwrap(),
            installed
        );
        assert_ne!(vendor_tree_bytes(&destination), old_bytes);
        assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_refuses_to_replace_an_unowned_existing_directory() {
        let root = temp("vendor-owned-target");
        let destination = root.join("important-data");
        let sentinel = destination.join("keep.txt");
        write(&sentinel, "must survive\n");
        let graph = ResolutionGraph {
            root_dependencies: BTreeMap::new(),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::new(),
            target: current_target(),
        };

        let error = vendor_dependencies(&graph, &destination).unwrap_err();

        assert!(error.message.contains("拒绝覆盖"), "{error}");
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "must survive\n");
        assert!(vendor_transaction_artifacts(&root, "important-data").is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_build_failure_preserves_the_old_tree_and_cleans_staging() {
        let root = temp("vendor-build-failure");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        let old_graph = vendor_fixture_graph(&root, "old");
        let old = vendor_dependencies(&old_graph, &destination).unwrap();
        let old_bytes = vendor_tree_bytes(&destination);
        let mut broken_graph = vendor_fixture_graph(&root, "broken");
        broken_graph
            .packages
            .values_mut()
            .next()
            .unwrap()
            .locked
            .checksum = "0".repeat(64);

        let error = vendor_dependencies(&broken_graph, &destination).unwrap_err();

        assert!(error.message.contains("辖制包校验不符"), "{error}");
        assert_eq!(validate_owned_vendor_directory(&destination).unwrap(), old);
        assert_eq!(vendor_tree_bytes(&destination), old_bytes);
        assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_refuses_damaged_or_extended_owned_directories() {
        for damage in ["extra", "changed"] {
            let root = temp(&format!("vendor-owned-{damage}"));
            fs::create_dir_all(&root).unwrap();
            let destination = root.join("vendor");
            let old_graph = vendor_fixture_graph(&root, "old");
            let old = vendor_dependencies(&old_graph, &destination).unwrap();
            let package = old.packages.values().next().unwrap();
            if damage == "extra" {
                write(&destination.join("unexpected.txt"), "must survive\n");
            } else {
                write(
                    &destination.join(&package.path).join("主.yx"),
                    "公 定 标记 为「changed」；\n",
                );
            }
            let damaged_bytes = vendor_tree_bytes(&destination);
            let new_graph = vendor_fixture_graph(&root, "new");

            let error = vendor_dependencies(&new_graph, &destination).unwrap_err();

            assert!(error.message.contains("拒绝覆盖"), "{error}");
            assert_eq!(vendor_tree_bytes(&destination), damaged_bytes);
            assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn vendor_refuses_a_non_directory_target() {
        let root = temp("vendor-file-target");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        write(&destination, "must survive\n");
        let graph = vendor_fixture_graph(&root, "new");

        let error = vendor_dependencies(&graph, &destination).unwrap_err();

        assert!(error.message.contains("必须是真实目录"), "{error}");
        assert_eq!(fs::read_to_string(&destination).unwrap(), "must survive\n");
        assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn vendor_refuses_a_link_target_without_touching_its_referent() {
        use std::os::unix::fs::symlink;

        let root = temp("vendor-link-target");
        let referent = root.join("referent");
        let sentinel = referent.join("keep.txt");
        write(&sentinel, "must survive\n");
        let destination = root.join("vendor");
        symlink(&referent, &destination).unwrap();
        let graph = vendor_fixture_graph(&root, "new");

        let error = vendor_dependencies(&graph, &destination).unwrap_err();

        assert!(error.message.contains("必须是真实目录"), "{error}");
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "must survive\n");
        assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_primary_failures_restore_exact_bytes() {
        for failure in [
            VendorInstallCheckpoint::Backup,
            VendorInstallCheckpoint::BackupSync,
            VendorInstallCheckpoint::Publish,
            VendorInstallCheckpoint::PublishValidation,
            VendorInstallCheckpoint::PublishSync,
            VendorInstallCheckpoint::BackupCleanup,
        ] {
            let root = temp(&format!("vendor-rollback-{failure:?}"));
            fs::create_dir_all(&root).unwrap();
            let destination = root.join("vendor");
            let old_graph = vendor_fixture_graph(&root, "old");
            let old = vendor_dependencies(&old_graph, &destination).unwrap();
            let old_bytes = vendor_tree_bytes(&destination);
            let new_graph = vendor_fixture_graph(&root, "new");

            let error =
                vendor_dependencies_with_checkpoint(&new_graph, &destination, |point, path| {
                    if point == failure {
                        Err(manifest_error(path, None, "模拟辖制事务失败"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();

            assert!(error.message.contains("模拟辖制事务失败"), "{error}");
            assert_eq!(vendor_tree_bytes(&destination), old_bytes);
            assert_eq!(validate_owned_vendor_directory(&destination).unwrap(), old);
            assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn vendor_restore_failure_reports_both_errors_and_preserves_recovery_trees() {
        let root = temp("vendor-restore-failure");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        let old_graph = vendor_fixture_graph(&root, "old");
        let old = vendor_dependencies(&old_graph, &destination).unwrap();
        let new_graph = vendor_fixture_graph(&root, "new");

        let error =
            vendor_dependencies_with_checkpoint(
                &new_graph,
                &destination,
                |point, path| match point {
                    VendorInstallCheckpoint::PublishSync => {
                        Err(manifest_error(path, None, "模拟辖制发布同步失败"))
                    }
                    VendorInstallCheckpoint::Restore => {
                        Err(manifest_error(path, None, "模拟旧辖制目录恢复失败"))
                    }
                    _ => Ok(()),
                },
            )
            .unwrap_err();

        assert!(error.message.contains("模拟辖制发布同步失败"), "{error}");
        assert!(error.message.contains("模拟旧辖制目录恢复失败"), "{error}");
        assert!(!destination.exists());
        let artifacts = vendor_transaction_artifacts(&root, "vendor");
        assert_eq!(artifacts.len(), 2);
        let backup = artifacts
            .iter()
            .find(|path| path.to_string_lossy().contains(".backup-"))
            .unwrap();
        let staging = artifacts
            .iter()
            .find(|path| path.to_string_lossy().contains(".staging-"))
            .unwrap();
        assert_eq!(validate_owned_vendor_directory(backup).unwrap(), old);
        assert_ne!(validate_owned_vendor_directory(staging).unwrap(), old);
        for artifact in artifacts {
            assert!(
                error.message.contains(&artifact.display().to_string()),
                "{error}"
            );
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_failures_after_restore_keep_recovery_staging() {
        for (secondary, message) in [
            (
                VendorInstallCheckpoint::RollbackValidation,
                "模拟辖制回滚复验失败",
            ),
            (
                VendorInstallCheckpoint::RollbackSync,
                "模拟辖制回滚同步失败",
            ),
            (
                VendorInstallCheckpoint::RollbackCleanup,
                "模拟辖制回滚清理失败",
            ),
        ] {
            let root = temp(&format!("vendor-secondary-{secondary:?}"));
            fs::create_dir_all(&root).unwrap();
            let destination = root.join("vendor");
            let old_graph = vendor_fixture_graph(&root, "old");
            let old = vendor_dependencies(&old_graph, &destination).unwrap();
            let old_bytes = vendor_tree_bytes(&destination);
            let new_graph = vendor_fixture_graph(&root, "new");

            let error =
                vendor_dependencies_with_checkpoint(&new_graph, &destination, |point, path| {
                    match point {
                        VendorInstallCheckpoint::PublishSync => {
                            Err(manifest_error(path, None, "模拟辖制发布同步失败"))
                        }
                        point if point == secondary => Err(manifest_error(path, None, message)),
                        _ => Ok(()),
                    }
                })
                .unwrap_err();

            assert!(error.message.contains(message), "{error}");
            assert_eq!(vendor_tree_bytes(&destination), old_bytes);
            assert_eq!(validate_owned_vendor_directory(&destination).unwrap(), old);
            let artifacts = vendor_transaction_artifacts(&root, "vendor");
            assert_eq!(artifacts.len(), 1);
            assert!(artifacts[0].to_string_lossy().contains(".staging-"));
            assert!(
                error.message.contains(&artifacts[0].display().to_string()),
                "{error}"
            );
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn vendor_failures_before_restore_preserve_both_valid_trees() {
        for (secondary, message) in [
            (
                VendorInstallCheckpoint::RestoreValidation,
                "模拟旧辖制目录备份复验失败",
            ),
            (
                VendorInstallCheckpoint::RollbackPublished,
                "模拟新辖制目录撤回失败",
            ),
        ] {
            let root = temp(&format!("vendor-preserve-{secondary:?}"));
            fs::create_dir_all(&root).unwrap();
            let destination = root.join("vendor");
            let old_graph = vendor_fixture_graph(&root, "old");
            let old = vendor_dependencies(&old_graph, &destination).unwrap();
            let new_graph = vendor_fixture_graph(&root, "new");

            let error =
                vendor_dependencies_with_checkpoint(&new_graph, &destination, |point, path| {
                    match point {
                        VendorInstallCheckpoint::PublishSync => {
                            Err(manifest_error(path, None, "模拟辖制发布同步失败"))
                        }
                        point if point == secondary => Err(manifest_error(path, None, message)),
                        _ => Ok(()),
                    }
                })
                .unwrap_err();

            assert!(error.message.contains(message), "{error}");
            assert_ne!(validate_owned_vendor_directory(&destination).unwrap(), old);
            let artifacts = vendor_transaction_artifacts(&root, "vendor");
            assert_eq!(artifacts.len(), 1);
            assert!(artifacts[0].to_string_lossy().contains(".backup-"));
            assert_eq!(validate_owned_vendor_directory(&artifacts[0]).unwrap(), old);
            assert!(
                error.message.contains(&artifacts[0].display().to_string()),
                "{error}"
            );
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn vendor_refuses_to_delete_a_backup_changed_during_commit() {
        let root = temp("vendor-backup-changed");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        let old_graph = vendor_fixture_graph(&root, "old");
        let old = vendor_dependencies(&old_graph, &destination).unwrap();
        let new_graph = vendor_fixture_graph(&root, "new");

        let error = vendor_dependencies_with_checkpoint(&new_graph, &destination, |point, path| {
            if point == VendorInstallCheckpoint::BackupCleanup {
                write(&path.join("unexpected.txt"), "must survive\n");
            }
            Ok(())
        })
        .unwrap_err();

        assert_ne!(validate_owned_vendor_directory(&destination).unwrap(), old);
        let artifacts = vendor_transaction_artifacts(&root, "vendor");
        assert_eq!(artifacts.len(), 1);
        let backup = &artifacts[0];
        assert!(backup.to_string_lossy().contains(".backup-"));
        assert_eq!(
            fs::read_to_string(backup.join("unexpected.txt")).unwrap(),
            "must survive\n"
        );
        assert!(
            error.message.contains(&backup.display().to_string()),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vendor_first_install_sync_failure_leaves_no_visible_directory() {
        let root = temp("vendor-first-sync-failure");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("vendor");
        let graph = vendor_fixture_graph(&root, "new");

        let error = vendor_dependencies_with_checkpoint(&graph, &destination, |point, path| {
            if point == VendorInstallCheckpoint::PublishSync {
                Err(manifest_error(path, None, "模拟首次辖制发布同步失败"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert!(
            error.message.contains("模拟首次辖制发布同步失败"),
            "{error}"
        );
        assert!(!destination.exists());
        assert!(vendor_transaction_artifacts(&root, "vendor").is_empty());
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
        let restored_dependency = restored.packages.values().next().unwrap();
        assert!(!restored_dependency.root.starts_with(&vendor));
        assert_eq!(
            fs::read_to_string(&restored_dependency.entry).unwrap(),
            "公 定 值 为 1；\n"
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
    fn module_source_reader_enforces_the_exact_byte_boundary() {
        let root = temp("module-source-byte-limit");
        fs::create_dir_all(&root).unwrap();
        let accepted = root.join("恰好上限.yx");
        let accepted_file = fs::File::create(&accepted).unwrap();
        accepted_file.set_len(MODULE_SOURCE_MAX_BYTES).unwrap();
        drop(accepted_file);

        let accepted = open_external_module_file(&fs::canonicalize(accepted).unwrap()).unwrap();
        let source = read_resolved_module_source_snapshot(accepted).unwrap();
        assert_eq!(source.len() as u64, MODULE_SOURCE_MAX_BYTES);

        let rejected = root.join("超过上限.yx");
        let rejected_file = fs::File::create(&rejected).unwrap();
        rejected_file.set_len(MODULE_SOURCE_MAX_BYTES + 1).unwrap();
        drop(rejected_file);

        let rejected = open_external_module_file(&fs::canonicalize(rejected).unwrap()).unwrap();
        let error = read_resolved_module_source_snapshot(rejected).unwrap_err();
        assert_eq!(error.code(), PACKAGE_MODULE_SOURCE_LIMIT_CODE);
        assert_eq!(
            error.diagnostic_message(),
            format!("模块源码不得超过 {MODULE_SOURCE_MAX_BYTES} 字节")
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn replacing_an_oversized_module_path_cannot_bypass_the_bound_limit() {
        let root = temp("module-source-limit-replacement");
        fs::create_dir_all(&root).unwrap();
        let requested = root.join("模块.yx");
        let original = root.join("原模块.yx");
        let file = fs::File::create(&requested).unwrap();
        file.set_len(MODULE_SOURCE_MAX_BYTES + 1).unwrap();
        drop(file);
        let canonical = fs::canonicalize(&requested).unwrap();
        let resolved = open_external_module_file(&canonical).unwrap();

        fs::rename(&requested, &original).unwrap();
        write(&requested, "言「替换后很小」；\n");

        let error = read_resolved_module_source_snapshot(resolved).unwrap_err();
        assert_eq!(error.code(), PACKAGE_MODULE_SOURCE_LIMIT_CODE);
        assert_eq!(error.path, canonical);
        fs::remove_dir_all(root).ok();
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

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn pack_reads_from_the_open_root_after_an_ordinary_root_replacement() {
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
    fn stable_module_snapshot_rejects_replacement_between_check_and_open() {
        let root = temp("module-snapshot-race");
        let requested = root.join("src/模块.yx");
        write(&requested, "言「可信」；\n");
        let canonical_root = fs::canonicalize(&root).unwrap();
        let canonical = fs::canonicalize(&requested).unwrap();
        let backup = canonical_root.join("src/原模块.yx");
        assert_eq!(
            fs::metadata(&canonical).unwrap().len(),
            "言「替换」；\n".len() as u64
        );

        let error = read_package_file_snapshot_with_hook(
            &canonical_root,
            &canonical,
            ARCHIVE_MAX_FILE_BYTES,
            "模块源码",
            None,
            || {
                fs::rename(&canonical, &backup).map_err(|error| {
                    manifest_error(&canonical, None, format!("不能模拟模块替换：{error}"))
                })?;
                fs::write(&canonical, "言「替换」；\n").map_err(|error| {
                    manifest_error(&canonical, None, format!("不能模拟模块写入：{error}"))
                })?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.message.contains("被替换"), "{error}");

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn opened_snapshot_rejects_same_length_in_place_writes_even_with_restored_mtime() {
        let root = temp("snapshot-in-place-rewrite");
        let path = root.join("resource.bin");
        write(&path, "trusted-bytes");
        let original_modified = fs::metadata(&path).unwrap().modified().unwrap();
        let file = open_regular_file_for_snapshot(&path).unwrap();

        let error =
            read_opened_regular_file_snapshot_with_hook(file, &path, 1024, "资源", None, || {
                fs::write(&path, b"changed-bytes").map_err(|error| {
                    manifest_error(&path, None, format!("不能模拟同长原地写入：{error}"))
                })?;
                let writable = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|error| {
                        manifest_error(&path, None, format!("不能重开测试资源：{error}"))
                    })?;
                writable
                    .set_times(fs::FileTimes::new().set_modified(original_modified))
                    .map_err(|error| {
                        manifest_error(&path, None, format!("不能恢复测试修改时间：{error}"))
                    })?;
                Ok(())
            })
            .unwrap_err();

        assert!(error.message.contains("同长或原地变化"), "{error}");
        fs::remove_dir_all(root).ok();
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

    #[cfg(not(windows))]
    #[test]
    fn external_module_open_rejects_symlink_replacement_before_binding() {
        let root = temp("external-module-symlink-race");
        let module = root.join("模块.yx");
        let original = root.join("原模块.yx");
        let replacement = root.join("替换.yx");
        write(&module, "言「可信」；\n");
        write(&replacement, "言「替换」；\n");
        let canonical = fs::canonicalize(&module).unwrap();

        let error = open_external_module_file_with_hook(&canonical, || {
            fs::rename(&canonical, &original).map_err(|error| {
                manifest_error(&canonical, None, format!("不能模拟模块替换：{error}"))
            })?;
            #[cfg(all(unix, not(target_os = "wasi")))]
            std::os::unix::fs::symlink(Path::new("替换.yx"), &canonical).map_err(|error| {
                manifest_error(&canonical, None, format!("不能模拟模块链接：{error}"))
            })?;
            #[cfg(target_os = "wasi")]
            rustix::fs::symlinkat(Path::new("替换.yx"), rustix::fs::CWD, &canonical).map_err(
                |error| manifest_error(&canonical, None, format!("不能模拟模块链接：{error}")),
            )?;
            Ok(())
        })
        .unwrap_err();
        assert!(
            error.message.contains("被替换")
                || error.message.contains("符号链接")
                || error.message.contains("不能打开模块"),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn external_module_snapshot_rejects_a_final_symlink() {
        let root = temp("external-module-final-symlink");
        let target = root.join("目标.yx");
        let link = root.join("链接.yx");
        write(&target, "言 1；\n");
        #[cfg(all(unix, not(target_os = "wasi")))]
        std::os::unix::fs::symlink(Path::new("目标.yx"), &link).unwrap();
        #[cfg(target_os = "wasi")]
        rustix::fs::symlinkat(Path::new("目标.yx"), rustix::fs::CWD, &link).unwrap();

        let error = read_module_source_snapshot(&link).unwrap_err();
        assert!(
            error.message.contains("符号链接") || error.message.contains("不能预先打开"),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn resolved_module_handle_survives_ordinary_ancestor_replacement() {
        let root = temp("resolved-module-ancestor");
        let source_directory = root.join("src");
        let requested = source_directory.join("模块.yx");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='句柄回归'\n版本='1.0.0'\n入口='src/模块.yx'\n",
        );
        write(&requested, "言「可信」；\n");
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let (resolved, authority) = roots
            .resolve_import_file(&source_directory, &requested, false)
            .unwrap();
        assert!(authority.is_verified());

        let backup = root.join("src-original");
        fs::rename(&source_directory, &backup).unwrap();
        write(&requested, "言「替换」；\n");

        let resolved = resolved.open().unwrap();
        assert_eq!(
            read_resolved_module_source_snapshot(resolved).unwrap(),
            "言「可信」；\n"
        );
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

    #[cfg(all(unix, not(target_os = "wasi")))]
    #[test]
    fn stable_file_snapshot_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = temp("snapshot-fifo");
        let fifo = root.join("resource.pipe");
        write(&fifo, "regular\n");
        let canonical_root = fs::canonicalize(&root).unwrap();
        let canonical = fs::canonicalize(&fifo).unwrap();
        let fifo_name = CString::new(canonical.as_os_str().as_bytes()).unwrap();
        let started = std::time::Instant::now();

        let error = read_package_file_snapshot_with_hook(
            &canonical_root,
            &canonical,
            1024,
            "资源",
            None,
            || {
                fs::remove_file(&canonical).map_err(|error| {
                    manifest_error(&canonical, None, format!("不能模拟删除资源：{error}"))
                })?;
                if unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) } != 0 {
                    return Err(manifest_error(
                        &canonical,
                        None,
                        format!("不能模拟命名管道：{}", io::Error::last_os_error()),
                    ));
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(error.message.contains("被替换"), "{error}");
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
    fn archive_consumer_rejects_portable_case_and_unicode_path_collisions() {
        for (label, first, second) in [
            ("case", "package/src/Foo.yx", "package/src/foo.yx"),
            ("unicode", "package/src/é.yx", "package/src/e\u{301}.yx"),
            (
                "ancestor-case",
                "package/src/Foo/甲.yx",
                "package/src/foo/乙.yx",
            ),
            ("wrapper-case", "Package/额外.yx", "package/其他.yx"),
        ] {
            let root = temp(&format!("archive-portable-collision-{label}"));
            fs::create_dir_all(&root).unwrap();
            let archive = root.join("package.yxp");
            write_archive(
                &archive,
                &[
                    (
                        "package/言序.toml",
                        "[包]\n格式=2\n名称='碰撞'\n版本='1.0.0'\n入口='src/Foo.yx'\n".as_bytes(),
                    ),
                    (first, "言 1；\n".as_bytes()),
                    (second, "言 2；\n".as_bytes()),
                ],
            );
            let error = extract_archive_safely(&archive, &root.join("unpacked")).unwrap_err();
            assert_eq!(
                error.code(),
                crate::path_policy::PACKAGE_PATH_COLLISION_CODE
            );
            fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn portable_tree_checksum_accepts_legacy_windows_paths_and_normalizes_nfc() {
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
    fn nfd_manifest_paths_resolve_after_nfc_yxp_materialization() {
        let root = temp("nfd-manifest-nfc-yxp");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='规范等价路径'\n版本='1.0.0'\n入口='src/e\u{301}.yx'\n[导出]\n默认='src/e\u{301}.yx'\n[资源]\n目录=['assets/e\u{301}']\n",
        );
        write(&root.join("src/e\u{301}.yx"), "言 1；\n");
        write(&root.join("assets/e\u{301}/data.txt"), "resource\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output_root = temp("nfd-manifest-nfc-yxp-output");
        fs::create_dir_all(&output_root).unwrap();
        let archive = output_root.join("package.yxp");
        pack_package(&manifest, &archive).unwrap();
        let unpacked = output_root.join("unpacked");
        extract_archive_safely(&archive, &unpacked).unwrap();
        let unpacked_root = unpacked.join("package");
        let unpacked_manifest = load(unpacked_root.join(MANIFEST_NAME)).unwrap();
        validate_package_root(&unpacked_manifest).unwrap();
        assert!(
            resolve_existing_package_path(
                &unpacked_root,
                &unpacked_manifest.entry,
                PackagePathPurpose::ModuleSource,
            )
            .unwrap()
            .is_file()
        );
        assert!(
            resolve_existing_package_path(
                &unpacked_root,
                &unpacked_manifest.resources[0],
                PackagePathPurpose::ManifestReference,
            )
            .unwrap()
            .is_dir()
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(output_root).unwrap();
    }

    #[test]
    fn manifest_paths_reject_raw_backslashes_and_package_names_require_nfc() {
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

    #[test]
    fn package_root_resource_remains_valid_and_yxp_uses_nfc_paths() {
        let root = temp("root-resource-nfc-yxp");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='根资源'\n版本='1.0.0'\n入口='src/主.yx'\n[资源]\n目录=['.']\n",
        );
        write(&root.join("src/主.yx"), "言 1；\n");
        write(&root.join("assets/e\u{301}.txt"), "accent\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let output_root = temp("root-resource-nfc-output");
        fs::create_dir_all(&output_root).unwrap();
        let archive = output_root.join("package.yxp");
        pack_package(&manifest, &archive).unwrap();
        let decoder = flate2::read::GzDecoder::new(fs::File::open(&archive).unwrap());
        let mut tar = tar::Archive::new(decoder);
        let archive_paths = tar
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert!(
            archive_paths
                .iter()
                .any(|path| path == "package/assets/é.txt")
        );
        assert!(
            archive_paths
                .iter()
                .all(|path| path != "package/assets/e\u{301}.txt")
        );
        let unpacked = output_root.join("unpacked");
        extract_archive_safely(&archive, &unpacked).unwrap();
        assert!(unpacked.join("package/assets/é.txt").is_file());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(output_root).unwrap();
    }

    #[test]
    fn yxp_path_limit_uses_the_final_nfc_archive_name() {
        let root = temp("nfc-path-limit");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='规范路径限额'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&root.join("主.yx"), "言 1；\n");
        let decomposed = "e\u{301}".repeat(40);
        let relative = PathBuf::from(&decomposed).join("data.txt");
        write(&root.join(&relative), "data\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        let portable = portable_package_path(&relative).unwrap();
        let final_archive_path = Path::new("package").join(&portable);
        let final_length = final_archive_path.as_os_str().as_encoded_bytes().len();
        assert!(
            Path::new("package")
                .join(&relative)
                .as_os_str()
                .as_encoded_bytes()
                .len()
                > final_length
        );
        assert_eq!(
            validated_yxp_archive_path(&relative, &root.join(&relative), final_length).unwrap(),
            final_archive_path
        );
        assert!(
            validated_yxp_archive_path(&relative, &root.join(&relative), final_length - 1).is_err()
        );
        let limits = ArchiveLimits {
            path_bytes: final_length,
            ..ARCHIVE_LIMITS
        };
        let output_root = temp("nfc-path-limit-output");
        fs::create_dir_all(&output_root).unwrap();
        let output = output_root.join("package.yxp");

        pack_package_with_limits(&manifest, &output, limits).unwrap();

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(output_root).unwrap();
    }

    #[test]
    fn pack_output_conflicts_use_portable_case_and_unicode_identity() {
        let root = temp("portable-output-conflicts");
        write(
            &root.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='输出身份'\n版本='1.0.0'\n入口='src/Main.yx'\n[导出]\n重音='src/é.yx'\n[资源]\n目录=['Assets']\n",
        );
        write(&root.join("src/Main.yx"), "言 1；\n");
        write(&root.join("src/é.yx"), "言 2；\n");
        write(&root.join("Assets/data.txt"), "data\n");
        let manifest = load(root.join(MANIFEST_NAME)).unwrap();

        let case_error =
            validate_pack_output_conflicts(&manifest, Some(Path::new("src/main.yx"))).unwrap_err();
        assert!(case_error.message.contains("入口"), "{case_error}");
        let unicode_error =
            validate_pack_output_conflicts(&manifest, Some(Path::new("src/e\u{301}.yx")))
                .unwrap_err();
        assert!(unicode_error.message.contains("导出"), "{unicode_error}");
        let resource_error =
            validate_pack_output_conflicts(&manifest, Some(Path::new("assets/package.yxp")))
                .unwrap_err();
        assert!(
            resource_error.message.contains("资源目录"),
            "{resource_error}"
        );
        assert!(
            validate_pack_output_conflicts(&manifest, Some(Path::new("assets-old/package.yxp")))
                .is_ok()
        );
        let mut root_resource = manifest.clone();
        root_resource.resources = vec![PathBuf::from(".")];
        let root_error =
            validate_pack_output_conflicts(&root_resource, Some(Path::new("dist/package.yxp")))
                .unwrap_err();
        assert!(root_error.message.contains("资源目录"), "{root_error}");

        let mut workspace = manifest.clone();
        workspace.workspace_members = vec![PathBuf::from("Workspace")];
        let workspace_error =
            validate_pack_output_conflicts(&workspace, Some(Path::new("workspace/member.yxp")))
                .unwrap_err();
        assert!(
            workspace_error.message.contains("工作区成员"),
            "{workspace_error}"
        );

        let mut application = manifest.clone();
        application.application = Some(ApplicationConfig {
            kind: ApplicationKind::CommandLine,
            name: "输出身份".into(),
            identifier: "dev.yanxu.output-identity".into(),
            version: Version::new(1, 0, 0),
            icon: Some(PathBuf::from("Assets/É.png")),
            company: None,
            minimum_system_version: None,
            window: WindowConfig::default(),
        });
        let icon_error =
            validate_pack_output_conflicts(&application, Some(Path::new("assets/e\u{301}.png")))
                .unwrap_err();
        assert!(icon_error.message.contains("应用图标"), "{icon_error}");

        let mut native = manifest.clone();
        native.native = Some(NativePackage {
            abi_version: 2,
            artifacts: BTreeMap::from([(
                "fixture-target".into(),
                NativeArtifact {
                    abi: 2,
                    target: "fixture-target".into(),
                    path: "Native/é.bin".into(),
                    checksum: "0".repeat(64),
                    size: 1,
                },
            )]),
        });
        let native_error =
            validate_pack_output_conflicts(&native, Some(Path::new("native/e\u{301}.bin")))
                .unwrap_err();
        assert!(native_error.message.contains("原生制品"), "{native_error}");

        fs::remove_dir_all(root).unwrap();
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
        assert_eq!(
            error.code(),
            crate::path_policy::PACKAGE_PATH_COLLISION_CODE
        );
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
    fn gui_permission_cannot_authorize_named_path_or_git_native_packages() {
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
        remove_git_fixture_cache(&git_url);
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
    fn metadata_snapshots_enforce_explicit_size_limits() {
        fn sparse(path: &Path, bytes: u64) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let file = fs::File::create(path).unwrap();
            file.set_len(bytes).unwrap();
        }

        let root = temp("metadata-size-limits");
        let manifest_path = root.join("manifest").join(MANIFEST_NAME);
        sparse(&manifest_path, MANIFEST_MAX_BYTES + 1);
        let manifest_error = load(&manifest_path).unwrap_err();
        assert!(manifest_error.message.contains("包清单不得超过"));

        let lock_path = root.join("lock").join(LOCK_NAME);
        sparse(&lock_path, LOCK_MAX_BYTES + 1);
        let lock_error = read_lock(&lock_path).unwrap_err();
        assert!(lock_error.message.contains("锁文件不得超过"));

        let index_path = root.join("registry/index.json");
        sparse(&index_path, REGISTRY_INDEX_MAX_BYTES + 1);
        let index_error = read_registry_index(&index_path).unwrap_err();
        assert!(index_error.message.contains("索引元数据不得超过"));

        let graph = vendor_fixture_graph(&root, "metadata-limit");
        let locked = graph.packages.values().next().unwrap().locked.clone();
        let vendor_manifest = root.join("vendor/言序-vendor.json");
        sparse(&vendor_manifest, VENDOR_MANIFEST_MAX_BYTES + 1);
        let vendor_error = find_vendored_package(&root.join("application"), &locked).unwrap_err();
        assert!(vendor_error.message.contains("辖制清单不得超过"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn stable_metadata_snapshot_rejects_same_length_path_replacement() {
        let root = temp("metadata-replacement");
        let path = root.join("metadata.json");
        let backup = root.join("metadata-original.json");
        write(&path, "trusted\n");

        let error =
            read_stable_metadata_file_snapshot_with_hook(&path, 1024, "测试元数据", || {
                fs::rename(&path, &backup).map_err(|error| {
                    manifest_error(&path, None, format!("不能模拟元数据替换：{error}"))
                })?;
                fs::write(&path, "changed\n").map_err(|error| {
                    manifest_error(&path, None, format!("不能模拟元数据写入：{error}"))
                })?;
                Ok(())
            })
            .unwrap_err();
        assert!(error.message.contains("读取期间被替换"), "{error}");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(all(unix, not(target_os = "wasi")))]
    #[test]
    fn metadata_fifo_entries_are_rejected_without_blocking() {
        const CHILD_ENV: &str = "YANXU_METADATA_FIFO_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "package::tests::metadata_fifo_entries_are_rejected_without_blocking",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "FIFO 元数据负向测试子进程失败");
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().ok();
                    child.wait().ok();
                    panic!("FIFO 元数据读取超时，普通文件打开可能发生阻塞");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        fn fifo(path: &Path) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        }

        let root = temp("metadata-fifo");
        let manifest_path = root.join("manifest").join(MANIFEST_NAME);
        fifo(&manifest_path);
        assert!(load(&manifest_path).is_err());
        assert!(discover(manifest_path.parent().unwrap()).is_err());

        let lock_path = root.join("lock").join(LOCK_NAME);
        fifo(&lock_path);
        assert!(read_lock(&lock_path).is_err());

        let index_path = root.join("registry/index.json");
        fifo(&index_path);
        assert!(read_registry_index(&index_path).is_err());

        let registry = root.join("registry-source");
        let release_index = registry.join("fixture/index.json");
        fifo(&release_index);
        assert!(
            registry_release_metadata(
                registry.to_str().unwrap(),
                "fixture",
                &Version::new(1, 0, 0),
                true,
            )
            .is_err()
        );

        let graph = vendor_fixture_graph(&root, "metadata-fifo");
        let locked = graph.packages.values().next().unwrap().locked.clone();
        let vendor_manifest = root.join("vendor/言序-vendor.json");
        fifo(&vendor_manifest);
        assert!(find_vendored_package(&root.join("application"), &locked).is_err());
        fs::remove_dir_all(root).ok();
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
        assert!(exported.entry.ends_with("src/子.yx"));
        assert_eq!(
            fs::read_to_string(&exported.entry).unwrap(),
            "公 定 子：数 为 1；\n"
        );
        let transitive =
            resolve_dependency_scoped(Some(&application), &first.join("src"), "乙/工具").unwrap();
        assert!(transitive.entry.ends_with("src/工具.yx"));
        assert_eq!(
            fs::read_to_string(&transitive.entry).unwrap(),
            "公 定 值：数 为 42；\n"
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
        assert!(dependency.entry.ends_with("src/库.yx"));
        assert_eq!(
            fs::read_to_string(&dependency.entry).unwrap(),
            "公 定 值：数 为 42；\n"
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
    fn source_url_policy_rejects_embedded_credentials_without_hiding_safe_sources() {
        for source in [
            "https://example.invalid/group/package.git",
            "ssh://example.invalid/group/package.git",
            "ssh://git@example.invalid/group/package.git",
            "git+ssh://git@example.invalid/group/package.git",
            "git@example.invalid:group/package.git",
            "https://example.invalid/group/package.git?ref=stable&channel=release",
        ] {
            assert!(
                validate_source_url_security(source).is_ok(),
                "safe source was rejected: {source}"
            );
            assert_eq!(safe_source_value_for_display(source), source);
        }
        assert!(secure_git_source(
            "https://example.invalid/group/package.git"
        ));
        assert!(secure_git_source("ssh://example.invalid/group/package.git"));
        assert!(secure_git_source(
            "ssh://git@example.invalid/group/package.git"
        ));
        assert!(secure_git_source(
            "git+ssh://git@example.invalid/group/package.git"
        ));
        assert!(secure_git_source("git@example.invalid:group/package.git"));

        let marker = "never-print-this-value";
        for source in [
            format!("https://user:{marker}@example.invalid/package.git"),
            "https://user@example.invalid/package.git".into(),
            format!("ssh://git:{marker}@example.invalid/package.git"),
            format!("https://example.invalid/package.git#fragment-{marker}"),
            format!("https://example.invalid/package.git?access_token={marker}"),
            format!("https://example.invalid/package.git?%61ccess_%74oken={marker}"),
            format!("git@example.invalid:group/package.git?api-key={marker}"),
        ] {
            assert_eq!(
                validate_source_url_security(&source),
                Err(SOURCE_SECURITY_ERROR),
                "unsafe source was accepted"
            );
            let displayed = safe_source_value_for_display(&source);
            assert!(
                !displayed.contains(marker),
                "source value leaked: {displayed}"
            );
            assert_eq!(displayed, "<已隐藏的不安全来源>");
        }
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
    fn typed_source_policies_keep_safe_transports_and_local_hash_paths() {
        for source in [
            "https://example.invalid/group/package.git",
            "ssh://git@example.invalid/group/package.git",
            "ssh://deploy-user@example.invalid/group/package.git",
            "git@example.invalid:group/package.git",
            "deploy_user@example.invalid:group/package.git",
        ] {
            assert!(validate_git_source_security(source).is_ok(), "{source}");
            assert_eq!(safe_git_source_value_for_display(source), source);
        }
        for source in [
            "http://example.invalid/package.git",
            "ftp://example.invalid/package.git",
            "git://example.invalid/package.git",
            "ssh://user:password@example.invalid/package.git",
            "user:password@example.invalid:group/package.git",
            "git@example.invalid@mirror.invalid:group/package.git",
        ] {
            assert!(validate_git_source_security(source).is_err(), "{source}");
            assert_eq!(
                safe_git_source_value_for_display(source),
                HIDDEN_SOURCE_VALUE
            );
        }

        assert!(validate_registry_source_security("https://packages.example.invalid/v1").is_ok());
        assert!(validate_artifact_source_security("../archives/package.yxp#snapshot").is_ok());
        assert!(
            validate_advisory_source_security("https://security.example.invalid/YXSA-1").is_ok()
        );
        for source in [
            "http://packages.example.invalid/v1",
            "ftp://packages.example.invalid/v1",
            "ssh://git@example.invalid/index",
        ] {
            assert!(
                validate_registry_source_security(source).is_err(),
                "{source}"
            );
        }
        for source in [
            "http://security.example.invalid/YXSA-1",
            "file:///tmp/YXSA-1",
            "../advisories/YXSA-1",
        ] {
            assert!(
                validate_advisory_source_security(source).is_err(),
                "{source}"
            );
        }
        for revision in [
            "+refs/heads/main",
            "refs/heads/main:refs/replace/0123456789abcdef0123456789abcdef01234567",
            "refs/heads/*",
        ] {
            assert_eq!(
                validate_git_revision_security(revision),
                Err(GIT_REVISION_ERROR),
                "Git refspec was accepted: {revision}"
            );
        }

        assert!(validate_local_source_path_text("../dependency#snapshot").is_ok());
        assert!(validate_local_source_path_text("../dependency?ref=stable").is_ok());
        for source in [
            "",
            "git:https://example.invalid/package.git",
            "git@example.invalid:group/package.git",
            "https://example.invalid/package.git",
            "https%3A%2F%2Fuser%3Ahidden%40example.invalid%2Fpackage.git",
            "git%40example.invalid%3Agroup%2Fpackage.git",
            "../dependency?access_token=hidden",
            "../dependency\nnext",
        ] {
            assert!(validate_local_source_path_text(source).is_err(), "{source}");
        }
        assert_eq!(
            safe_local_source_path_for_display(Path::new("../dependency#snapshot")),
            "../dependency#snapshot"
        );
    }

    #[test]
    fn lock_source_dispatch_is_exact_bounded_and_redacted() {
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
            assert_eq!(safe_dependency_source_for_display(source), source);
        }

        let marker = "lock-source-value-must-not-appear";
        for source in [
            "path:".to_owned(),
            format!("path:https://user:{marker}@example.invalid/package.git"),
            format!("path:git@example.invalid:group/{marker}.git"),
            format!("git:plain?authorization_code={marker}"),
            format!("registry:https://packages.example.invalid/v1?x-sig={marker}"),
            format!("gitx:https://example.invalid/{marker}.git"),
            format!("path:../dependency\n{marker}"),
        ] {
            assert!(validate_locked_dependency_source(&source).is_err());
            let displayed = safe_dependency_source_for_display(&source);
            assert!(
                !displayed.contains(marker),
                "lock source leaked: {displayed}"
            );
        }
        assert_eq!(
            safe_dependency_source_for_display("path:https://user:hidden@example.invalid/repo"),
            format!("path:{HIDDEN_SOURCE_VALUE}")
        );

        let unsafe_revision = format!("HEAD?access_token={marker}");
        assert!(validate_git_revision_security(&unsafe_revision).is_err());
        assert!(!safe_git_revision_for_display(&unsafe_revision).contains(marker));
    }

    #[test]
    fn vendor_rejects_nested_network_sources_before_writing() {
        let root = temp("unsafe-vendor-source");
        let destination = root.join("vendor");
        let marker = "vendor-source-value-must-not-appear";
        let dependency = ResolvedDependency {
            locked: LockedPackage {
                id: "fixture@1.0.0".into(),
                name: "fixture".into(),
                version: "1.0.0".into(),
                source: format!("path:https://user:{marker}@example.invalid/package.git"),
                revision: None,
                checksum: "a".repeat(64),
                entry: "main.yx".into(),
                dependencies: BTreeMap::new(),
                exports: BTreeMap::new(),
                target: current_target(),
                native: None,
                minimum_yanxu: None,
            },
            root: root.join("dependency"),
            entry: root.join("dependency/main.yx"),
        };
        let graph = ResolutionGraph {
            root_dependencies: BTreeMap::from([("fixture".into(), "fixture@1.0.0".into())]),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::from([("fixture@1.0.0".into(), dependency)]),
            target: current_target(),
        };
        let error = vendor_dependencies(&graph, &destination)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(marker), "{error}");
        assert!(!destination.exists());
        fs::remove_dir_all(root).ok();
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

    #[cfg(any(unix, windows))]
    fn test_process_is_running(process_id: u32) -> bool {
        #[cfg(unix)]
        {
            let process_id = libc::pid_t::try_from(process_id).unwrap();
            let result = unsafe { libc::kill(process_id, 0) };
            result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

            let process = unsafe { OpenProcess(0x0010_0000, 0, process_id) };
            if process.is_null() {
                return false;
            }
            let status = unsafe { WaitForSingleObject(process, 0) };
            unsafe {
                CloseHandle(process);
            }
            status == WAIT_TIMEOUT
        }
    }

    #[cfg(any(unix, windows))]
    fn publish_test_process_id(root: &Path, name: &str) {
        let process_id = std::process::id();
        let pending = root.join(format!(".{name}.{process_id}.pending"));
        fs::write(&pending, process_id.to_string()).unwrap();
        fs::rename(pending, root.join(name)).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_timeout_reaps_descendants() {
        const ROLE: &str = "YANXU_SUBPROCESS_TIMEOUT_TEST_ROLE";
        const ROOT: &str = "YANXU_SUBPROCESS_TIMEOUT_TEST_ROOT";
        const TEST: &str = "package::tests::subprocess_timeout_reaps_descendants";
        if let Some(role) = std::env::var_os(ROLE) {
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            if role == "leaf" {
                publish_test_process_id(&root, "leaf.pid");
                std::thread::sleep(Duration::from_secs(30));
                return;
            }
            let mut leaf = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(ROLE, "leaf")
                .env(ROOT, &root)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !root.join("leaf.pid").exists() {
                if std::time::Instant::now() >= deadline {
                    leaf.kill().ok();
                    leaf.wait().ok();
                    panic!("后代测试进程未能启动");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_secs(30));
            leaf.kill().ok();
            leaf.wait().ok();
            return;
        }

        let root = temp("subprocess-timeout-tree");
        fs::create_dir_all(&root).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(ROLE, "controller")
            .env(ROOT, &root);
        let error = bounded_command_output(
            &mut command,
            &root,
            "测试进程树超时",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(3),
                stdout_bytes: 64 * 1024,
                stderr_bytes: 64 * 1024,
                disk: None,
                cancellation: None,
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_TIMEOUT"),
            "{error}"
        );
        let process_id = fs::read_to_string(root.join("leaf.pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while test_process_is_running(process_id) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!test_process_is_running(process_id), "后代测试进程仍在运行");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_parent_death_reaps_the_running_tree() {
        const ROLE: &str = "YANXU_SUBPROCESS_PARENT_DEATH_TEST_ROLE";
        const ROOT: &str = "YANXU_SUBPROCESS_PARENT_DEATH_TEST_ROOT";
        const TEST: &str = "package::tests::subprocess_parent_death_reaps_the_running_tree";
        if let Some(role) = std::env::var_os(ROLE) {
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            if role == "leaf" {
                publish_test_process_id(&root, "leaf.pid");
                std::thread::sleep(Duration::from_secs(30));
                return;
            }
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env(ROLE, "leaf")
                .env(ROOT, &root);
            let _ = bounded_command_output(
                &mut command,
                &root,
                "测试父进程取消",
                "测试命令",
                subprocess::CommandBudget {
                    timeout: Duration::from_secs(30),
                    stdout_bytes: 64 * 1024,
                    stderr_bytes: 64 * 1024,
                    disk: None,
                    cancellation: None,
                },
            );
            return;
        }

        let root = temp("subprocess-parent-death");
        fs::create_dir_all(&root).unwrap();
        let mut controller = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(ROLE, "controller")
            .env(ROOT, &root)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !root.join("leaf.pid").exists() {
            if let Some(status) = controller.try_wait().unwrap() {
                panic!("父进程取消测试控制进程提前退出：{status}");
            }
            if std::time::Instant::now() >= deadline {
                controller.kill().ok();
                controller.wait().ok();
                panic!("父进程取消测试子进程未能启动");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let process_id = fs::read_to_string(root.join("leaf.pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        controller.kill().unwrap();
        controller.wait().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while test_process_is_running(process_id) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !test_process_is_running(process_id),
            "父进程退出后测试进程树仍在运行"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_output_is_bounded_while_running() {
        const CHILD: &str = "YANXU_SUBPROCESS_OUTPUT_TEST_CHILD";
        const TEST: &str = "package::tests::subprocess_output_is_bounded_while_running";
        if let Some(stream) = std::env::var_os(CHILD) {
            let bytes = [b'x'; 8 * 1024];
            if stream == "stdout" {
                let mut stdout = io::stdout().lock();
                while stdout.write_all(&bytes).is_ok() {}
            } else {
                let mut stderr = io::stderr().lock();
                while stderr.write_all(&bytes).is_ok() {}
            }
            return;
        }

        #[cfg(unix)]
        let (mut exact, exact_bytes) = {
            let bytes = 128 * 1024;
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg(
                    "dd if=/dev/zero bs=\"$1\" count=1 2>/dev/null; \
                     dd if=/dev/zero bs=\"$2\" count=1 1>&2 2>/dev/null",
                )
                .arg("bounded-stream-fixture")
                .arg(bytes.to_string())
                .arg(bytes.to_string());
            (command, bytes)
        };
        #[cfg(windows)]
        let (mut exact, exact_bytes) = {
            let bytes = 4 * 1024;
            let mut command = Command::new("cmd");
            command.args(["/D", "/Q", "/C"]).arg(format!(
                "for /L %i in (1,1,{bytes}) do @<nul set /p \"=x\" & \
                 for /L %i in (1,1,{bytes}) do @<nul set /p \"=y\" 1>&2"
            ));
            (command, bytes)
        };
        let exact = bounded_command_output(
            &mut exact,
            Path::new("bounded-output"),
            "测试输出预算精确边界",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: exact_bytes,
                stderr_bytes: exact_bytes,
                disk: None,
                cancellation: None,
            },
        )
        .unwrap();
        assert!(exact.status.success());
        assert_eq!(exact.stdout.len(), exact_bytes);

        for (stream, expected) in [("stdout", "标准输出"), ("stderr", "标准错误")] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, stream);
            let started = std::time::Instant::now();
            let error = bounded_command_output(
                &mut command,
                Path::new("bounded-output"),
                "测试输出预算",
                "测试命令",
                subprocess::CommandBudget {
                    timeout: Duration::from_secs(5),
                    stdout_bytes: 1_024,
                    stderr_bytes: 1_024,
                    disk: None,
                    cancellation: None,
                },
            )
            .unwrap_err();
            assert!(
                error.message.contains("PACKAGE_SUBPROCESS_OUTPUT_LIMIT"),
                "{error}"
            );
            assert!(error.message.contains(expected), "{error}");
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_cancellation_stops_and_reaps_the_process() {
        const CHILD: &str = "YANXU_SUBPROCESS_CANCEL_TEST_CHILD";
        const ROOT: &str = "YANXU_SUBPROCESS_CANCEL_TEST_ROOT";
        const TEST: &str = "package::tests::subprocess_cancellation_stops_and_reaps_the_process";
        if std::env::var_os(CHILD).is_some() {
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            publish_test_process_id(&root, "child.pid");
            std::thread::sleep(Duration::from_secs(30));
            return;
        }

        let root = temp("subprocess-cancellation");
        fs::create_dir_all(&root).unwrap();
        let already_cancelled = std::sync::atomic::AtomicBool::new(true);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "1")
            .env(ROOT, &root);
        let error = bounded_command_output(
            &mut command,
            Path::new("pre-cancelled-command"),
            "测试调用前取消",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: 1_024,
                stderr_bytes: 1_024,
                disk: None,
                cancellation: Some(&already_cancelled),
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_CANCELLED"),
            "{error}"
        );
        assert!(!root.join("child.pid").exists());

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "1")
            .env(ROOT, &root);
        let error = bounded_command_output(
            &mut command,
            Path::new("expired-command"),
            "测试调用前超时",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::ZERO,
                stdout_bytes: 1_024,
                stderr_bytes: 1_024,
                disk: None,
                cancellation: None,
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_TIMEOUT"),
            "{error}"
        );
        assert!(!root.join("child.pid").exists());

        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trigger = cancellation.clone();
        let trigger_root = root.clone();
        let trigger = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !trigger_root.join("child.pid").exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            trigger.store(true, Ordering::Release);
        });
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "1")
            .env(ROOT, &root);
        let started = std::time::Instant::now();
        let error = bounded_command_output(
            &mut command,
            Path::new("cancelled-command"),
            "测试取消",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: 1_024,
                stderr_bytes: 1_024,
                disk: None,
                cancellation: Some(cancellation.as_ref()),
            },
        )
        .unwrap_err();
        trigger.join().unwrap();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_CANCELLED"),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        let process_id = fs::read_to_string(root.join("child.pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(
            !test_process_is_running(process_id),
            "取消后的测试进程仍在运行"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_disk_budget_aborts_and_temporary_directory_is_removed() {
        const CHILD: &str = "YANXU_SUBPROCESS_DISK_TEST_CHILD";
        const ROOT: &str = "YANXU_SUBPROCESS_DISK_TEST_ROOT";
        const TEST: &str =
            "package::tests::subprocess_disk_budget_aborts_and_temporary_directory_is_removed";
        if let Some(mode) = std::env::var_os(CHILD) {
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            if mode == "boundary" {
                fs::File::create(root.join("boundary"))
                    .unwrap()
                    .set_len(32 * 1024)
                    .unwrap();
                return;
            }
            let bytes = [b'd'; 8 * 1024];
            for index in 0_u64.. {
                if fs::write(root.join(format!("block-{index}")), bytes).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            return;
        }

        let root = temp("subprocess-disk-budget");
        fs::create_dir_all(&root).unwrap();
        let temporary = RegistryTemporaryDirectory::create(&root, "disk-budget").unwrap();
        let temporary_path = temporary.path().to_path_buf();
        let mut boundary = Command::new(std::env::current_exe().unwrap());
        boundary
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "boundary")
            .env(ROOT, &temporary_path);
        let output = bounded_command_output(
            &mut boundary,
            &temporary_path,
            "测试磁盘预算精确边界",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: 64 * 1024,
                stderr_bytes: 64 * 1024,
                disk: Some(subprocess::DiskBudget {
                    root: &temporary_path,
                    max_bytes: 32 * 1024,
                    max_entries: 32,
                    max_depth: 1,
                }),
                cancellation: None,
            },
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            fs::metadata(temporary_path.join("boundary")).unwrap().len(),
            32 * 1024
        );

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "overflow")
            .env(ROOT, &temporary_path);
        let error = bounded_command_output(
            &mut command,
            &temporary_path,
            "测试磁盘预算",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: 1_024,
                stderr_bytes: 1_024,
                disk: Some(subprocess::DiskBudget {
                    root: &temporary_path,
                    max_bytes: 32 * 1024,
                    max_entries: 32,
                    max_depth: 1,
                }),
                cancellation: None,
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_DISK_LIMIT"),
            "{error}"
        );
        assert!(error.message.contains("字节上限"), "{error}");
        drop(temporary);
        assert!(!temporary_path.exists());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_disk_monitor_rejects_root_replacement() {
        const CHILD: &str = "YANXU_SUBPROCESS_DISK_REPLACE_CHILD";
        const ROOT: &str = "YANXU_SUBPROCESS_DISK_REPLACE_ROOT";
        const MOVED: &str = "YANXU_SUBPROCESS_DISK_REPLACE_MOVED";
        const TEST: &str = "package::tests::subprocess_disk_monitor_rejects_root_replacement";
        if std::env::var_os(CHILD).is_some() {
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            let moved = PathBuf::from(std::env::var_os(MOVED).unwrap());
            fs::rename(&root, &moved).unwrap();
            fs::create_dir(&root).unwrap();
            fs::File::create(moved.join("content"))
                .unwrap()
                .set_len(64 * 1024)
                .unwrap();
            std::thread::sleep(Duration::from_secs(30));
            return;
        }

        let outer = temp("subprocess-disk-root-replacement");
        let root = outer.join("monitored");
        let moved = outer.join("moved");
        fs::create_dir_all(&root).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "1")
            .env(ROOT, &root)
            .env(MOVED, &moved);
        let error = bounded_command_output(
            &mut command,
            &root,
            "测试磁盘根身份",
            "测试命令",
            subprocess::CommandBudget {
                timeout: Duration::from_secs(5),
                stdout_bytes: 64 * 1024,
                stderr_bytes: 64 * 1024,
                disk: Some(subprocess::DiskBudget {
                    root: &root,
                    max_bytes: 1024 * 1024,
                    max_entries: 32,
                    max_depth: 1,
                }),
                cancellation: None,
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("PACKAGE_SUBPROCESS_DISK_LIMIT"),
            "{error}"
        );
        assert!(error.message.contains("特殊文件"), "{error}");
        fs::remove_dir_all(outer).ok();
    }

    #[test]
    fn persisted_git_object_store_enforces_total_byte_budget() {
        let root = temp("git-store-byte-budget");
        fs::create_dir_all(root.join("objects/pack")).unwrap();
        let oversized = fs::File::create(root.join("objects/pack/oversized.pack")).unwrap();
        oversized.set_len(GIT_STORE_MAX_BYTES + 1).unwrap();
        let error = validate_git_store_tree(&root).unwrap_err();
        assert!(
            error.message.contains(&GIT_STORE_MAX_BYTES.to_string()),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn persisted_git_object_store_counts_allocated_blocks() {
        use std::os::unix::fs::MetadataExt as _;

        let root = temp("git-store-allocated-byte-budget");
        let pack = root.join("objects/pack");
        fs::create_dir_all(&pack).unwrap();
        fs::File::create(pack.join("sparse.pack"))
            .unwrap()
            .set_len(GIT_STORE_MAX_BYTES - 1)
            .unwrap();
        let allocated_path = pack.join("allocated.pack");
        let mut allocated = fs::File::create(&allocated_path).unwrap();
        allocated.write_all(b"x").unwrap();
        allocated.sync_all().unwrap();
        let metadata = allocated.metadata().unwrap();
        assert!(metadata.blocks().saturating_mul(512) > metadata.len());

        let error = validate_git_store_tree(&root).unwrap_err();
        assert!(
            error.message.contains(&GIT_STORE_MAX_BYTES.to_string()),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn git_operations_use_separate_hard_deadlines() {
        assert!(GIT_INSPECT_TIMEOUT < GIT_INITIALIZE_TIMEOUT);
        assert!(GIT_INITIALIZE_TIMEOUT < GIT_ARCHIVE_TIMEOUT);
        assert!(GIT_ARCHIVE_TIMEOUT < GIT_FETCH_TIMEOUT);
    }

    #[test]
    fn git_commit_probe_distinguishes_absence_from_repository_failure() {
        let root = temp("git-commit-probe");
        fs::create_dir_all(&root).unwrap();
        run_git_fixture(&root, &["init", "--bare", "--quiet", "valid.git"]);
        let missing = "0000000000000000000000000000000000000000";
        assert!(!git_commit_exists(&root.join("valid.git"), missing).unwrap());

        let broken = root.join("broken.git");
        fs::create_dir(&broken).unwrap();
        let error = git_commit_exists(&broken, missing).unwrap_err();
        assert!(error.message.contains("检查 Git 精确提交失败"), "{error}");
        assert!(error.message.contains("退出码"), "{error}");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn credential_bearing_sources_fail_before_network_cache_or_manifest_writes() {
        let marker = format!(
            "never-print-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let git_url = format!("https://user:{marker}@127.0.0.1:1/package.git");
        let git_cache = cache_root().join("git").join(short_hash(&git_url));
        fs::remove_dir_all(&git_cache).ok();
        let git_error = resolve_git(&git_url, "HEAD", false).unwrap_err();
        let git_diagnostic = git_error.to_string();
        assert!(!git_diagnostic.contains(&marker), "{git_diagnostic}");
        assert!(!git_cache.exists(), "unsafe Git source created cache state");

        let registry = format!("https://127.0.0.1:1/index?api_key={marker}");
        let registry_cache = cache_root().join("registry").join(short_hash(&registry));
        fs::remove_dir_all(&registry_cache).ok();
        let registry_error =
            resolve_registry("fixture", &VersionReq::STAR, &registry, None, None, false)
                .unwrap_err();
        let registry_diagnostic = registry_error.to_string();
        assert!(
            !registry_diagnostic.contains(&marker),
            "{registry_diagnostic}"
        );
        assert!(
            !registry_cache.exists(),
            "unsafe registry source created cache state"
        );

        let root = temp("source-edit-fail-closed");
        let manifest_path = root.join(MANIFEST_NAME);
        write(
            &manifest_path,
            "[包]\n格式=2\n名称='fixture-app'\n版本='1.0.0'\n入口='main.yx'\n",
        );
        write(&root.join("main.yx"), "言 1；\n");
        let before = fs::read(&manifest_path).unwrap();
        let dependency = Dependency::Git {
            url: git_url,
            revision: "HEAD".into(),
            requirement: None,
        };
        let edit_error =
            edit_dependency(&manifest_path, "fixture", None, Some(&dependency), false).unwrap_err();
        let edit_diagnostic = edit_error.to_string();
        assert!(!edit_diagnostic.contains(&marker), "{edit_diagnostic}");
        assert_eq!(fs::read(&manifest_path).unwrap(), before);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn unsafe_manifest_and_lock_sources_fail_closed_without_echoing_values() {
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
        assert!(!manifest_error.contains(&unsafe_url), "{manifest_error}");

        let unsafe_lock = lock_with_source(format!("git:{unsafe_url}"));
        let old_lock_path = root.join("old.lock");
        write(
            &old_lock_path,
            &toml::to_string_pretty(&unsafe_lock).unwrap(),
        );
        let read_error = read_lock(&old_lock_path).unwrap_err().to_string();
        assert!(!read_error.contains(marker), "{read_error}");
        assert!(!read_error.contains(&unsafe_url), "{read_error}");

        let new_lock_path = root.join("new.lock");
        let write_error = write_lock(&new_lock_path, &unsafe_lock)
            .unwrap_err()
            .to_string();
        assert!(!write_error.contains(marker), "{write_error}");
        assert!(!new_lock_path.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn registry_index_rejects_unsafe_artifact_and_advisory_urls_without_echoing_values() {
        let root = temp("unsafe-registry-index-source");
        let checksum = "a".repeat(64);
        let marker = "registry-value-must-not-appear";
        let artifact_url = format!("https://user:{marker}@example.invalid/package.tar.gz");
        let artifact_index = root.join("artifact.json");
        write(
            &artifact_index,
            &serde_json::to_string(&serde_json::json!({
                "versions": [{
                    "version": "1.0.0",
                    "url": artifact_url,
                    "checksum": checksum,
                }]
            }))
            .unwrap(),
        );
        let artifact_error = read_registry_index(&artifact_index)
            .unwrap_err()
            .to_string();
        assert!(!artifact_error.contains(marker), "{artifact_error}");

        let advisory_url = format!("https://security.example.invalid/advisory?token={marker}");
        let advisory_index = root.join("advisory.json");
        write(
            &advisory_index,
            &serde_json::to_string(&serde_json::json!({
                "versions": [{
                    "version": "1.0.0",
                    "url": "https://example.invalid/package.tar.gz",
                    "checksum": checksum,
                    "vulnerabilities": [{
                        "id": "YXSA-2026-0001",
                        "severity": "high",
                        "summary": "fixture advisory",
                        "url": advisory_url,
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
    fn concurrent_git_revisions_publish_distinct_immutable_generations() {
        let root = temp("git-concurrent-generations");
        let repository = root.join("repository");
        write(
            &repository.join(MANIFEST_NAME),
            "[包]\n名='并发Git包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&repository.join("主.yx"), "公 定 答：数 为 1；\n");
        run_git_fixture(&repository, &["init", "--quiet"]);
        run_git_fixture(
            &repository,
            &["config", "user.email", "yanxu@example.invalid"],
        );
        run_git_fixture(&repository, &["config", "user.name", "Yanxu Tests"]);
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "first"]);
        let first_revision = git_fixture_head(&repository);
        write(&repository.join("主.yx"), "公 定 答：数 为 2；\n");
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "second"]);
        let second_revision = git_fixture_head(&repository);
        let url = repository.to_string_lossy().into_owned();

        let threads = (0..8)
            .map(|index| {
                let url = url.clone();
                let revision = if index % 2 == 0 {
                    first_revision.clone()
                } else {
                    second_revision.clone()
                };
                std::thread::spawn(move || {
                    let (root, exact) = resolve_git(&url, &revision, false).unwrap();
                    (revision, exact, root)
                })
            })
            .collect::<Vec<_>>();
        let resolved = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        let first_roots = resolved
            .iter()
            .filter(|(requested, _, _)| requested == &first_revision)
            .map(|(_, exact, root)| {
                assert_eq!(exact, &first_revision);
                assert_eq!(
                    fs::read_to_string(root.join("主.yx")).unwrap(),
                    "公 定 答：数 为 1；\n"
                );
                assert!(!root.join(".git").exists());
                root
            })
            .collect::<Vec<_>>();
        let second_roots = resolved
            .iter()
            .filter(|(requested, _, _)| requested == &second_revision)
            .map(|(_, exact, root)| {
                assert_eq!(exact, &second_revision);
                assert_eq!(
                    fs::read_to_string(root.join("主.yx")).unwrap(),
                    "公 定 答：数 为 2；\n"
                );
                root
            })
            .collect::<Vec<_>>();
        assert!(first_roots.windows(2).all(|roots| roots[0] == roots[1]));
        assert!(second_roots.windows(2).all(|roots| roots[0] == roots[1]));
        assert_ne!(first_roots[0], second_roots[0]);
        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn exact_file_git_revision_remains_available_offline_without_source() {
        let root = temp("git-offline-generation");
        let repository = root.join("repository");
        write(
            &repository.join(MANIFEST_NAME),
            "[包]\n名='离线Git包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&repository.join("主.yx"), "公 定 答：数 为 7；\n");
        run_git_fixture(&repository, &["init", "--quiet"]);
        run_git_fixture(
            &repository,
            &["config", "user.email", "yanxu@example.invalid"],
        );
        run_git_fixture(&repository, &["config", "user.name", "Yanxu Tests"]);
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "offline"]);
        let url = url::Url::from_directory_path(&repository)
            .unwrap()
            .to_string();
        let (online_root, exact) = resolve_git(&url, "HEAD", false).unwrap();
        fs::remove_dir_all(&repository).unwrap();
        let (offline_root, offline_exact) = resolve_git(&url, &exact, true).unwrap();
        assert_eq!(offline_exact, exact);
        assert_eq!(offline_root, online_root);
        assert_eq!(
            fs::read_to_string(offline_root.join("主.yx")).unwrap(),
            "公 定 答：数 为 7；\n"
        );
        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn git_generation_preserves_bounded_long_archive_paths() {
        let root = temp("git-long-archive-path");
        let repository = root.join("repository");
        write(
            &repository.join(MANIFEST_NAME),
            "[包]\n名='长路径Git包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&repository.join("主.yx"), "公 定 答：数 为 12；\n");
        write(
            &repository.join("pax_global_header"),
            "Git 全局扩展头同名资源\n",
        );
        let long_relative = PathBuf::from("甲".repeat(70))
            .join("乙".repeat(70))
            .join("深.yx");
        assert!(long_relative.as_os_str().as_encoded_bytes().len() < ARCHIVE_MAX_PATH_BYTES);
        write(&repository.join(&long_relative), "公 定 深值：数 为 13；\n");
        run_git_fixture(&repository, &["init", "--quiet"]);
        run_git_fixture(
            &repository,
            &["config", "user.email", "yanxu@example.invalid"],
        );
        run_git_fixture(&repository, &["config", "user.name", "Yanxu Tests"]);
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "long-path"]);
        let revision = git_fixture_head(&repository);
        let url = repository.to_string_lossy().into_owned();

        let (generation, exact) = resolve_git(&url, &revision, false).unwrap();
        assert_eq!(exact, revision);
        assert_eq!(
            fs::read_to_string(generation.join(long_relative)).unwrap(),
            "公 定 深值：数 为 13；\n"
        );
        assert_eq!(
            fs::read_to_string(generation.join("pax_global_header")).unwrap(),
            "Git 全局扩展头同名资源\n"
        );

        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn damaged_git_generation_is_preserved_while_repair_is_published() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp("git-generation-repair");
        let repository = root.join("repository");
        write(
            &repository.join(MANIFEST_NAME),
            "[包]\n名='修复Git包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&repository.join("主.yx"), "公 定 答：数 为 8；\n");
        run_git_fixture(&repository, &["init", "--quiet"]);
        run_git_fixture(
            &repository,
            &["config", "user.email", "yanxu@example.invalid"],
        );
        run_git_fixture(&repository, &["config", "user.name", "Yanxu Tests"]);
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "repair"]);
        let exact = git_fixture_head(&repository);
        let url = repository.to_string_lossy();
        let (first_root, _) = resolve_git(&url, &exact, false).unwrap();
        let first_entry = first_root.join("主.yx");
        fs::set_permissions(&first_entry, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&first_entry, "公 定 答：数 为 9；\n").unwrap();

        let (repair_root, _) = resolve_git(&url, &exact, false).unwrap();
        assert_ne!(repair_root, first_root);
        assert_eq!(
            fs::read_to_string(&first_entry).unwrap(),
            "公 定 答：数 为 9；\n"
        );
        assert_eq!(
            fs::read_to_string(repair_root.join("主.yx")).unwrap(),
            "公 定 答：数 为 8；\n"
        );
        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn invalid_git_store_config_is_preserved_while_repair_store_is_published() {
        let root = temp("git-store-config-repair");
        let repository = root.join("repository");
        write(
            &repository.join(MANIFEST_NAME),
            "[包]\n名='配置修复包'\n版='1.0.0'\n入口='主.yx'\n",
        );
        write(&repository.join("主.yx"), "公 定 答：数 为 11；\n");
        run_git_fixture(&repository, &["init", "--quiet"]);
        run_git_fixture(
            &repository,
            &["config", "user.email", "yanxu@example.invalid"],
        );
        run_git_fixture(&repository, &["config", "user.name", "Yanxu Tests"]);
        run_git_fixture(&repository, &["add", "."]);
        run_git_fixture(&repository, &["commit", "--quiet", "-m", "fixture"]);
        let revision = git_fixture_head(&repository);
        let url = repository.to_string_lossy().into_owned();

        let (_, exact) = resolve_git(&url, &revision, false).unwrap();
        assert_eq!(exact, revision);
        let cache = git_cache_layout_root().unwrap();
        let identity = format!("{:x}", Sha256::digest(url.as_bytes()));
        let url_root = cache.join(identity);
        let store = url_root.join("objects.git");
        let replacement = store.join("refs/replace").join(&revision);
        fs::create_dir_all(replacement.parent().unwrap()).unwrap();
        fs::write(&replacement, format!("{revision}\n")).unwrap();
        let reference_error = validate_git_object_store(&store).unwrap_err();
        assert!(reference_error.message.contains("持久引用"));
        fs::remove_dir_all(store.join("refs/replace")).unwrap();

        let config_path = url_root.join("objects.git/config");
        let mut invalid_config = fs::read_to_string(&config_path).unwrap();
        invalid_config.push_str("\n[core]\n\thooksPath = ../../outside-hooks\n");
        fs::write(&config_path, &invalid_config).unwrap();

        let (repaired_root, repaired_exact) = resolve_git(&url, &revision, false).unwrap();
        assert_eq!(repaired_exact, revision);
        assert_eq!(
            fs::read_to_string(repaired_root.join("主.yx")).unwrap(),
            "公 定 答：数 为 11；\n"
        );
        assert_eq!(fs::read_to_string(&config_path).unwrap(), invalid_config);
        let repairs = fs::read_dir(&url_root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("objects-repair-") && name.ends_with(".git")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(repairs.len(), 1);
        validate_git_object_store(&repairs[0]).unwrap();

        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn git_cache_rejects_linked_lock_store_and_generation_paths() {
        use std::os::unix::fs::symlink;

        let root = temp("git-cache-links");
        let cache = root.join("cache");
        let outside = root.join("outside");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, cache.join(".locks")).unwrap();
        let identity = "a".repeat(64);
        let lock_error = match acquire_git_cache_lock(&cache, &identity) {
            Ok(_) => panic!("linked Git cache lock was accepted"),
            Err(error) => error,
        };
        assert!(lock_error.message.contains("链接"));
        assert!(!outside.join(&identity).join(".yanxu/package.lock").exists());
        fs::remove_file(cache.join(".locks")).unwrap();

        let url_root = create_checked_cache_directory(&cache, &identity, "Git 测试缓存").unwrap();
        symlink(&outside, url_root.join("objects.git")).unwrap();
        let store_error = find_git_object_store(&url_root).unwrap_err();
        assert!(store_error.message.contains("链接"));
        fs::remove_file(url_root.join("objects.git")).unwrap();

        let trees =
            create_checked_cache_directory(&url_root, GIT_GENERATION_LAYOUT, "Git 测试树").unwrap();
        let exact = "b".repeat(40);
        symlink(&outside, trees.join(&exact)).unwrap();
        let generation_error = create_git_commit_generation_root(&url_root, &exact).unwrap_err();
        assert!(generation_error.message.contains("链接"));
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
        remove_git_fixture_cache(&url);
        fs::remove_dir_all(root).ok();
    }
}

//! 言序包清单、锁文件与可复现依赖解析。
//!
//! `言序.toml` 可以声明路径、Git 和中央索引依赖；`言序.lock` 固定最终
//! 版本、Git 修订和内容 SHA-256。解析器在使用锁文件时仍会校验缓存内容，
//! 因而损坏或被悄悄改写的依赖不会进入模块执行。

mod archive;

#[cfg(test)]
use archive::{ARCHIVE_LIMITS, extract_archive_with_limits, validate_archive_relative_path};
use archive::{extract_archive_safely, find_manifest_root};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
            Self::Path { path, requirement } => write!(
                formatter,
                "路径 {}{}",
                path.display(),
                requirement
                    .as_ref()
                    .map_or_else(String::new, |version| format!(" ({version})"))
            ),
            Self::Git {
                url,
                revision,
                requirement,
            } => write!(
                formatter,
                "Git {url}#{revision}{}",
                requirement
                    .as_ref()
                    .map_or_else(String::new, |version| format!(" ({version})"))
            ),
            Self::Registry {
                requirement,
                registry,
            } => write!(formatter, "索引 {registry} ({requirement})"),
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
    let mut directory = if start.is_dir() {
        start.to_path_buf()
    } else {
        start
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    loop {
        let candidate = directory.join(MANIFEST_NAME);
        if candidate.is_file() {
            return load(candidate).map(Some);
        }
        if !directory.pop() {
            return Ok(None);
        }
    }
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
    dependency.entry = dependency.root.join(exported);
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
    let lock_path = manifest.root.join(LOCK_NAME);
    let existing = use_existing
        .then(|| read_lock(&lock_path).ok())
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
        gui_allowed: manifest.permissions.graphical_interface_allowed(),
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
    let text = fs::read_to_string(path)
        .map_err(|error| manifest_error(path, None, format!("不能读取锁文件：{error}")))?;
    let lock: LockFile = toml::from_str(&text)
        .map_err(|error| manifest_error(path, None, format!("锁文件格式无效：{error}")))?;
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
        "[包]\n格式 = 2\n名称 = {name:?}\n版本 = \"0.1.0\"\n言序 = \">=1.1.15\"\n入口 = \"src/主.yx\"\n\n[依赖]\n{dependency}\n\n[应用]\n类型 = \"图形\"\n名称 = {name:?}\n标识 = {identifier:?}\n版本 = \"0.1.0\"\n\n[应用.窗口]\n宽 = 800\n高 = 600\n最小宽 = 480\n最小高 = 320\n可缩放 = true\n高分屏 = true\n\n[权限]\n文件 = []\n网络 = []\n本地网络 = false\nTCP监听 = []\nUDP绑定 = []\n环境 = []\n进程 = false\n原生扩展 = false\n图形界面 = true\n剪贴板 = false\n文件对话框 = false\n系统通知 = false\n托盘 = false\n打开外部地址 = false\n全局快捷键 = false\n\n[导出]\n默认 = \"src/主.yx\"\n\n[构建]\n目标 = \"字节码\"\n"
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
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let _project_lock = acquire_project_lock(root)?;
    let original = fs::read_to_string(manifest_path)
        .map_err(|error| manifest_error(manifest_path, None, format!("不能读取以修改：{error}")))?;
    load(manifest_path)?;
    let normalized = normalize_manifest_toml(&original);
    let mut document: toml::Value = toml::from_str(&normalized)
        .map_err(|error| manifest_error(manifest_path, None, error.to_string()))?;
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
        .map_err(|error| manifest_error(manifest_path, None, error.to_string()))?;
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
    let document: toml::Value = toml::from_str(&normalized).map_err(|error| {
        let line = error.span().map(|span| {
            normalized[..span.start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1
        });
        manifest_error(&path, line, format!("TOML 格式无效：{error}"))
    })?;
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
    let entry = PathBuf::from(
        string_alias(package, &["入口", "entry"])
            .ok_or_else(|| manifest_error(&path, None, "【包】缺少字符串“入口”"))?,
    );
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
            let export = PathBuf::from(export);
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
        .map(PathBuf::from)
        .map(|resource| {
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
        .map(PathBuf::from)
        .map(|member| {
            validate_relative_path(&member, "工作区成员")?;
            Ok(member)
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;

    let native = parse_native_package(&document, &path)?;
    let application = parse_application_config(&document, &path, &root)?;
    let mut permissions = crate::permissions::PermissionSet::sandboxed();
    if let Some(table) = table_alias(&document, &["权限", "permissions"]) {
        for permission_path in array_alias(table, &["文件", "file"]).unwrap_or_default() {
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
        return Ok(Dependency::Path {
            path: PathBuf::from(path),
            requirement: None,
        });
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
        return Ok(Dependency::Path {
            path: PathBuf::from(path),
            requirement,
        });
    }
    if let Some(url) = string_alias(table, &["git", "Git"]) {
        return Ok(Dependency::Git {
            url: url.into(),
            revision: string_alias(table, &["修订", "rev", "revision"])
                .unwrap_or("HEAD")
                .into(),
            requirement,
        });
    }
    let requirement = requirement.ok_or_else(|| {
        manifest_error(manifest_path, None, format!("索引依赖“{name}”必须给出“版”"))
    })?;
    Ok(Dependency::Registry {
        requirement,
        registry: string_alias(table, &["源", "registry"])
            .unwrap_or(DEFAULT_REGISTRY)
            .into(),
    })
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
            let relative = PathBuf::from(path);
            validate_relative_path(&relative, "原生制品")?;
            if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(manifest_error(
                    manifest_path,
                    None,
                    format!("原生制品 {os}.{architecture} 的校验和须为 64 位十六进制 SHA-256"),
                ));
            }
            let full_path = manifest_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&relative);
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
        .map(PathBuf::from)
        .map(|icon| {
            validate_relative_path(&icon, "应用图标")?;
            let full_path = root.join(&icon);
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
            let canonical_root = fs::canonicalize(root).map_err(|error| {
                manifest_error(root, None, format!("不能定位包根目录：{error}"))
            })?;
            let canonical_icon = fs::canonicalize(&full_path).map_err(|error| {
                manifest_error(&full_path, None, format!("不能定位应用图标：{error}"))
            })?;
            if !canonical_icon.starts_with(canonical_root) {
                return Err(manifest_error(&full_path, None, "应用图标越出包根目录"));
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
    gui_allowed: bool,
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
            let official_gui_native = native.as_ref().is_some_and(|artifact| {
                self.gui_allowed
                    && artifact.abi == 2
                    && matches!(dependency_manifest.name.as_str(), "yanxu-gui" | "言窗")
            });
            if native.is_some() && !self.native_allowed && !official_gui_native {
                return Err(manifest_error(
                    &manifest.path,
                    None,
                    format!(
                        "依赖“{}”包含原生扩展；顶层【权限】必须显式设置 原生扩展 = true（官方 yanxu-gui ABI v2 后端可改由 图形界面 = true 授权）",
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
            resolved.entry = resolved.root.join(
                resolved
                    .locked
                    .exports
                    .get("默认")
                    .expect("manifest always has default export"),
            );
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
    let path = manifest.root.join(&artifact.path);
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
    if let Some(locked) = locked
        && let Some(root) = find_vendored_package(&manifest.root, locked)?
    {
        let requirement = dependency_requirement(dependency);
        let resolved = lock_local(
            package_name,
            &root,
            &locked.source,
            locked.revision.clone(),
            requirement,
        )?;
        verify_locked(alias, &root, &resolved, Some(locked))?;
        return Ok(resolved);
    }
    match dependency {
        Dependency::Path { path, requirement } => {
            let root = canonical_dependency_root(&manifest.root.join(path))?;
            let resolved = lock_local(
                package_name,
                &root,
                &format!("path:{}", path.display()),
                None,
                requirement.as_ref(),
            )?;
            verify_locked(alias, &root, &resolved, locked)?;
            Ok(resolved)
        }
        Dependency::Git {
            url,
            revision,
            requirement,
        } => {
            let exact_revision = locked.and_then(|locked| locked.revision.as_deref());
            let (root, revision) = resolve_git(url, exact_revision.unwrap_or(revision), offline)?;
            let resolved = lock_local(
                package_name,
                &root,
                &format!("git:{url}"),
                Some(revision),
                requirement.as_ref(),
            )?;
            verify_locked(alias, &root, &resolved, locked)?;
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
            let (root, version) = resolve_registry(
                package_name,
                requirement,
                registry,
                exact,
                locked.map(|locked| locked.checksum.as_str()),
                offline,
            )?;
            let resolved = lock_local(
                package_name,
                &root,
                &format!("registry:{registry}"),
                None,
                Some(requirement),
            )?;
            if resolved.locked.version != version.to_string() {
                return Err(manifest_error(
                    &root,
                    None,
                    "索引目录版本与包清单版本不一致",
                ));
            }
            verify_locked(alias, &root, &resolved, locked)?;
            Ok(resolved)
        }
    }
}

fn verify_locked(
    name: &str,
    root: &Path,
    resolved: &ResolvedDependency,
    locked: Option<&LockedPackage>,
) -> Result<(), ManifestError> {
    if let Some(locked) = locked
        && (locked.name != resolved.locked.name
            || locked.version != resolved.locked.version
            || locked.source != resolved.locked.source
            || locked.revision != resolved.locked.revision
            || locked.checksum != resolved.locked.checksum
            || locked.entry != resolved.locked.entry)
    {
        return Err(manifest_error(
            root,
            None,
            format!(
                "依赖“{name}”与 {LOCK_NAME} 不符（版本、修订或内容校验已改变）；请显式更新锁文件"
            ),
        ));
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
        entry: root.join(dependency_manifest.entry),
        root,
    })
}

fn resolve_git(
    url: &str,
    revision: &str,
    offline: bool,
) -> Result<(PathBuf, String), ManifestError> {
    if !secure_git_source(url) {
        return Err(manifest_error(
            Path::new(url),
            None,
            "远程 Git 依赖须使用 HTTPS 或 SSH",
        ));
    }
    if revision.is_empty()
        || revision.starts_with('-')
        || revision.chars().any(|character| character.is_control())
    {
        return Err(manifest_error(Path::new(url), None, "Git 修订名称不合法"));
    }
    let cache = cache_root().join("git").join(short_hash(url));
    if !cache.join(".git").is_dir() {
        if offline {
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

fn secure_git_source(url: &str) -> bool {
    Path::new(url).exists()
        || url.starts_with("file://")
        || url.starts_with("https://")
        || url.starts_with("ssh://")
        || url.starts_with("git+ssh://")
        || (!url.contains("://")
            && url
                .split_once(':')
                .is_some_and(|(authority, path)| authority.contains('@') && !path.is_empty()))
}

fn resolve_registry(
    name: &str,
    requirement: &VersionReq,
    registry: &str,
    locked: Option<Version>,
    locked_checksum: Option<&str>,
    offline: bool,
) -> Result<(PathBuf, Version), ManifestError> {
    if let Some(registry_path) = local_registry_path(registry) {
        let package_root = registry_path.join(name);
        let version = select_registry_version(&package_root, requirement, locked.as_ref())?;
        return Ok((package_root.join(version.to_string()), version));
    }
    if !registry.starts_with("https://") {
        return Err(manifest_error(
            Path::new(registry),
            None,
            "远程包索引须使用 HTTPS",
        ));
    }
    if offline && locked.is_none() {
        return Err(manifest_error(
            Path::new(registry),
            None,
            format!("离线模式须由锁文件固定索引依赖“{name}”"),
        ));
    }
    let registry_cache = cache_root().join("registry").join(short_hash(registry));
    if let Some(version) = &locked {
        let cached = registry_cache.join(name).join(version.to_string());
        if reusable_registry_cache(&cached, locked_checksum, offline)? {
            return Ok((cached, version.clone()));
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
    let index_path = registry_cache.join(format!("{}-index.json", short_hash(name)));
    download(
        &format!("{}/{name}/index.json", registry.trim_end_matches('/')),
        &index_path,
    )?;
    let index = read_registry_index(&index_path)?;
    let mut candidates = index
        .versions
        .into_iter()
        .filter_map(|release| {
            let version = Version::parse(&release.version).ok()?;
            (requirement.matches(&version)
                && locked.as_ref().is_none_or(|locked| locked == &version))
            .then_some((version, release))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let (version, release) = candidates.pop().ok_or_else(|| {
        manifest_error(
            &index_path,
            None,
            format!("远程索引中没有满足 {requirement} 的“{name}”版本"),
        )
    })?;
    if !valid_sha256(&release.checksum) {
        return Err(manifest_error(
            &index_path,
            None,
            format!("索引版本 {version} 缺少合法的制品 SHA-256"),
        ));
    }
    if !release.url.starts_with("https://") {
        return Err(manifest_error(
            &index_path,
            None,
            format!("索引版本 {version} 的制品地址须使用 HTTPS"),
        ));
    }
    let destination = registry_cache.join(name).join(version.to_string());
    let archive = registry_cache.join(format!("{name}-{version}.tar.gz"));
    download(&release.url, &archive)?;
    let actual_checksum = file_checksum(&archive)?;
    if !actual_checksum.eq_ignore_ascii_case(&release.checksum) {
        return Err(manifest_error(
            &archive,
            None,
            format!(
                "索引制品校验不符：应为 {}，实为 {actual_checksum}",
                release.checksum
            ),
        ));
    }
    let temporary = registry_cache.join(format!("unpack-{}", short_hash(&release.url)));
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|error| {
            manifest_error(&temporary, None, format!("不能清理临时目录：{error}"))
        })?;
    }
    fs::create_dir_all(&temporary)
        .map_err(|error| manifest_error(&temporary, None, format!("不能创建临时目录：{error}")))?;
    let extraction = (|| {
        extract_archive_safely(&archive, &temporary)?;
        let unpacked_root = find_manifest_root(&temporary)?;
        if destination.exists() {
            fs::remove_dir_all(&destination).map_err(|error| {
                manifest_error(&destination, None, format!("不能替换旧缓存：{error}"))
            })?;
        }
        copy_tree(&unpacked_root, &destination)
    })();
    if let Err(error) = extraction {
        fs::remove_dir_all(&temporary).ok();
        fs::remove_file(&archive).ok();
        return Err(error);
    }
    fs::remove_dir_all(&temporary).ok();
    fs::remove_file(&archive).ok();
    Ok((destination, version))
}

#[doc(hidden)]
pub fn registry_release_metadata(
    registry: &str,
    name: &str,
    version: &Version,
    offline: bool,
) -> Result<Option<RegistryReleaseMetadata>, ManifestError> {
    let index_path = if let Some(registry_path) = local_registry_path(registry) {
        registry_path.join(name).join("index.json")
    } else {
        if !registry.starts_with("https://") {
            return Err(manifest_error(
                Path::new(registry),
                None,
                "远程包索引须使用 HTTPS",
            ));
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
    serde_json::from_str(&index_text)
        .map_err(|error| manifest_error(path, None, format!("索引元数据无效：{error}")))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn reusable_registry_cache(
    cached: &Path,
    expected_checksum: Option<&str>,
    offline: bool,
) -> Result<bool, ManifestError> {
    if !cached.exists() {
        return Ok(false);
    }
    let valid = cached.join(MANIFEST_NAME).is_file()
        && load(cached.join(MANIFEST_NAME)).is_ok()
        && expected_checksum
            .is_none_or(|expected| tree_checksum(cached).is_ok_and(|actual| actual == expected));
    if valid {
        return Ok(true);
    }
    if offline {
        return Err(manifest_error(
            cached,
            None,
            "离线索引缓存损坏或与锁文件校验和不一致；请联网重新安装",
        ));
    }
    fs::remove_dir_all(cached)
        .map_err(|error| manifest_error(cached, None, format!("不能清理损坏索引缓存：{error}")))?;
    Ok(false)
}

fn select_registry_version(
    package_root: &Path,
    requirement: &VersionReq,
    locked: Option<&Version>,
) -> Result<Version, ManifestError> {
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

/// 将包源码与锁文件制成确定性 gzip/tar 归档。
pub fn pack_package(
    manifest: &Manifest,
    output: impl AsRef<Path>,
) -> Result<PackageArtifact, ManifestError> {
    let _project_lock = acquire_project_lock(&manifest.root)?;
    let graph = resolve_graph_mode_locked(manifest, false, true, true)?;
    cache_graph(manifest, graph);
    let output = output.as_ref();
    let mut files = Vec::new();
    collect_pack_files(&manifest.root, &manifest.root, &mut files)?;
    files.sort();
    if files.len() > ARCHIVE_MAX_ENTRIES {
        return Err(manifest_error(
            output,
            None,
            format!("打包条目不得超过 {ARCHIVE_MAX_ENTRIES}"),
        ));
    }
    let _expanded = files.iter().try_fold(0_u64, |total, relative| {
        let length = fs::metadata(manifest.root.join(relative))
            .map_err(|error| manifest_error(relative, None, error.to_string()))?
            .len();
        if length > ARCHIVE_MAX_FILE_BYTES {
            return Err(manifest_error(
                relative,
                None,
                format!("单文件不得超过 {ARCHIVE_MAX_FILE_BYTES} 字节"),
            ));
        }
        total
            .checked_add(length)
            .filter(|total| *total <= ARCHIVE_MAX_EXPANDED_BYTES)
            .ok_or_else(|| {
                manifest_error(
                    output,
                    None,
                    format!("打包内容不得超过 {ARCHIVE_MAX_EXPANDED_BYTES} 字节"),
                )
            })
    })?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| manifest_error(parent, None, format!("不能创建输出目录：{error}")))?;
    }
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = output.with_extension(format!(
        "{}.tmp-{}-{sequence}",
        output
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("yxp"),
        std::process::id()
    ));
    let file = fs::File::create(&temporary)
        .map_err(|error| manifest_error(&temporary, None, format!("不能创建归档：{error}")))?;
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    for relative in &files {
        let path = manifest.root.join(relative);
        let bytes = fs::read(&path)
            .map_err(|error| manifest_error(&path, None, format!("不能读取打包内容：{error}")))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                Path::new("package").join(relative),
                bytes.as_slice(),
            )
            .map_err(|error| manifest_error(&path, None, format!("不能写入归档：{error}")))?;
    }
    let encoder = archive
        .into_inner()
        .map_err(|error| manifest_error(&temporary, None, format!("不能结束 tar：{error}")))?;
    let mut file = encoder
        .finish()
        .map_err(|error| manifest_error(&temporary, None, format!("不能结束 gzip：{error}")))?;
    file.flush()
        .map_err(|error| manifest_error(&temporary, None, format!("不能刷新归档：{error}")))?;
    file.sync_all()
        .map_err(|error| manifest_error(&temporary, None, format!("不能同步归档：{error}")))?;
    if output.exists() {
        fs::remove_file(output)
            .map_err(|error| manifest_error(output, None, format!("不能替换旧归档：{error}")))?;
    }
    fs::rename(&temporary, output)
        .map_err(|error| manifest_error(output, None, format!("不能安装归档：{error}")))?;
    let bytes = fs::metadata(output)
        .map_err(|error| manifest_error(output, None, error.to_string()))?
        .len();
    Ok(PackageArtifact {
        path: output.to_path_buf(),
        checksum: file_checksum(output)?,
        bytes,
        entries: files.len(),
    })
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
                || tree_checksum(&canonical)? != locked.checksum
            {
                return Err(manifest_error(&root, None, "辖制包越界或内容校验不符"));
            }
            return Ok(Some(canonical));
        }
    }
    Ok(None)
}

fn collect_pack_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ManifestError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能遍历包：{error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| manifest_error(directory, None, format!("不能读取目录项：{error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".git" | ".yanxu" | ".DS_Store" | "target" | "build" | "vendor")
        ) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| manifest_error(&path, None, error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(manifest_error(&path, None, "包不得包含符号链接"));
        }
        if metadata.is_dir() {
            collect_pack_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(path.strip_prefix(root).expect("walk under root").into());
        } else {
            return Err(manifest_error(&path, None, "包不得包含特殊文件"));
        }
    }
    Ok(())
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
    if name.is_empty()
        || name.starts_with(['.', '-'])
        || name
            .chars()
            .any(|character| !(character.is_alphanumeric() || matches!(character, '_' | '-' | '.')))
    {
        Err(format!("包名“{name}”不规范；仅可用文字、数字、_、-、."))
    } else {
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
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let mut digest = Sha256::new();
    for relative in files {
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        let bytes = fs::read(root.join(&relative)).map_err(|error| {
            manifest_error(root.join(&relative), None, format!("不能校验文件：{error}"))
        })?;
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ManifestError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能遍历依赖：{error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| manifest_error(directory, None, format!("不能读取目录项：{error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".git" | ".yanxu" | ".DS_Store" | "target" | "build" | "vendor" | LOCK_NAME)
        ) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| manifest_error(&path, None, error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(manifest_error(&path, None, "依赖包不得包含符号链接"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(
                path.strip_prefix(root)
                    .expect("walk remains under root")
                    .into(),
            );
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

fn copy_tree(source: &Path, destination: &Path) -> Result<(), ManifestError> {
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
        if file_type.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &destination).map_err(|error| {
                manifest_error(&destination, None, format!("不能写入制品缓存：{error}"))
            })?;
        } else {
            return Err(manifest_error(entry.path(), None, "制品含特殊文件"));
        }
    }
    Ok(())
}

fn run_command(command: &mut Command, path: &Path, action: &str) -> Result<(), ManifestError> {
    let output = command
        .output()
        .map_err(|error| manifest_error(path, None, format!("{action}失败：{error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(manifest_error(
            path,
            None,
            format!(
                "{action}失败：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("yanxu-{name}-{unique}"))
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
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
    fn corrupted_registry_cache_is_rejected_offline_and_removed_online() {
        let cached = temp("corrupted-registry-cache");
        write(
            &cached.join(MANIFEST_NAME),
            "[包]\n格式=2\n名称='缓存包'\n版本='1.0.0'\n入口='主.yx'\n",
        );
        write(&cached.join("主.yx"), "公 定 值 为 1；\n");
        let checksum = tree_checksum(&cached).unwrap();
        assert!(reusable_registry_cache(&cached, Some(&checksum), true).unwrap());

        write(&cached.join("主.yx"), "公 定 值 为 2；\n");
        let error = reusable_registry_cache(&cached, Some(&checksum), true).unwrap_err();
        assert!(error.message.contains("缓存损坏"));
        assert!(cached.exists());
        assert!(!reusable_registry_cache(&cached, Some(&checksum), false).unwrap());
        assert!(!cached.exists());
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
    fn deterministic_pack_and_vendor_restore_work_without_original_dependencies() {
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
        let first_artifact = pack_package(&manifest, &first).unwrap();
        let second_artifact = pack_package(&manifest, &second).unwrap();
        assert_eq!(first_artifact.checksum, second_artifact.checksum);
        assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
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
        assert!(manifest.permissions.check_clipboard().is_err());
        assert!(matches!(
            manifest.dependencies.get("言窗"),
            Some(Dependency::Path { requirement: Some(requirement), .. })
                if requirement.to_string() == "^1.0"
        ));
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
    fn rejects_insecure_remote_sources_before_network_access() {
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

//! 言序包清单、锁文件与可复现依赖解析。
//!
//! `言序.toml` 可以声明路径、Git 和中央索引依赖；`言序.lock` 固定最终
//! 版本、Git 修订和内容 SHA-256。解析器在使用锁文件时仍会校验缓存内容，
//! 因而损坏或被悄悄改写的依赖不会进入模块执行。

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const MANIFEST_NAME: &str = "言序.toml";
pub const LOCK_NAME: &str = "言序.lock";
pub const MANIFEST_FORMAT_VERSION: u32 = 1;
pub const LOCK_FORMAT_VERSION: u32 = 1;
pub const DEFAULT_REGISTRY: &str = "https://packages.yanxu.dev/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub name: String,
    pub version: Version,
    pub entry: PathBuf,
    pub description: Option<String>,
    pub license: Option<String>,
    pub authors: Vec<String>,
    pub dependencies: BTreeMap<String, Dependency>,
    pub permissions: crate::permissions::PermissionSet,
    pub root: PathBuf,
    pub path: PathBuf,
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
    #[serde(rename = "package", default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub checksum: String,
    pub entry: String,
}

#[derive(Debug, Deserialize)]
struct RegistryIndex {
    versions: Vec<RegistryRelease>,
}

#[derive(Debug, Deserialize)]
struct RegistryRelease {
    version: String,
    url: String,
    checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependency {
    pub locked: LockedPackage,
    pub entry: PathBuf,
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
    let manifest = discover(base)?.ok_or_else(|| {
        manifest_error(
            base,
            None,
            format!("引用包“{name}”时未找到 {MANIFEST_NAME}"),
        )
    })?;
    let offline = std::env::var_os("YANXU_OFFLINE").is_some();
    let resolved = ensure_lock(&manifest, offline)?;
    resolved
        .get(name)
        .map(|dependency| dependency.entry.clone())
        .ok_or_else(|| manifest_error(&manifest.path, None, format!("未声明依赖“{name}”")))
}

/// 解析全部依赖并写入或验证 `言序.lock`。
pub fn ensure_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let manifest_checksum = file_checksum(&manifest.path)?;
    let lock_path = manifest.root.join(LOCK_NAME);
    let existing = read_lock(&lock_path).ok().filter(|lock| {
        lock.lock_version == LOCK_FORMAT_VERSION && lock.manifest_checksum == manifest_checksum
    });

    let mut resolved = BTreeMap::new();
    let mut packages = Vec::new();
    for (name, dependency) in &manifest.dependencies {
        let locked = existing
            .as_ref()
            .and_then(|lock| lock.packages.iter().find(|package| package.name == *name));
        let dependency = resolve_one(manifest, name, dependency, locked, offline)?;
        packages.push(dependency.locked.clone());
        resolved.insert(name.clone(), dependency);
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    let lock = LockFile {
        lock_version: LOCK_FORMAT_VERSION,
        manifest_checksum,
        packages,
    };
    if existing.as_ref() != Some(&lock) {
        write_lock(&lock_path, &lock)?;
    }
    Ok(resolved)
}

pub fn update_lock(
    manifest: &Manifest,
    offline: bool,
) -> Result<BTreeMap<String, ResolvedDependency>, ManifestError> {
    let path = manifest.root.join(LOCK_NAME);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| manifest_error(&path, None, format!("不能移除旧锁文件：{error}")))?;
    }
    ensure_lock(manifest, offline)
}

pub fn read_lock(path: impl AsRef<Path>) -> Result<LockFile, ManifestError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .map_err(|error| manifest_error(path, None, format!("不能读取锁文件：{error}")))?;
    let lock: LockFile = toml::from_str(&text)
        .map_err(|error| manifest_error(path, None, format!("锁文件格式无效：{error}")))?;
    if lock.lock_version != LOCK_FORMAT_VERSION {
        return Err(manifest_error(
            path,
            None,
            format!("不支持锁文件版本 {}", lock.lock_version),
        ));
    }
    Ok(lock)
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
    let format_version =
        integer_alias(package, &["格式", "format"]).unwrap_or(MANIFEST_FORMAT_VERSION as i64);
    if format_version != i64::from(MANIFEST_FORMAT_VERSION) {
        return Err(manifest_error(
            &path,
            None,
            format!(
                "不支持包清单格式版本 {format_version}，本运行时仅支持版本 {MANIFEST_FORMAT_VERSION}"
            ),
        ));
    }
    let name = string_alias(package, &["名", "name"])
        .ok_or_else(|| manifest_error(&path, None, "【包】缺少字符串“名”"))?;
    validate_package_name(name).map_err(|message| manifest_error(&path, None, message))?;
    let raw_version = string_alias(package, &["版", "version"])
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

    let mut dependencies = BTreeMap::new();
    if let Some(table) = table_alias(&document, &["依赖", "dependencies"]) {
        for (dependency_name, value) in table {
            validate_package_name(dependency_name)
                .map_err(|message| manifest_error(&path, None, message))?;
            dependencies.insert(
                dependency_name.clone(),
                parse_dependency(value, &path, dependency_name)?,
            );
        }
    }
    let mut permissions = crate::permissions::PermissionSet::sandboxed();
    if let Some(table) = table_alias(&document, &["权限", "permissions"]) {
        for permission_path in array_alias(table, &["文件", "file"]).unwrap_or_default() {
            permissions = permissions.allow_file(root.join(permission_path));
        }
        for host in array_alias(table, &["网络", "network"]).unwrap_or_default() {
            permissions = permissions.allow_network(host);
        }
        for variable in array_alias(table, &["环境", "environment"]).unwrap_or_default() {
            permissions = permissions.allow_environment(variable);
        }
        if bool_alias(table, &["进程", "process"]).unwrap_or(false) {
            permissions = permissions.allow_process();
        }
    }
    Ok(Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        name: name.into(),
        version,
        entry,
        description,
        license,
        authors,
        dependencies,
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
                    return format!("{indentation}[\"{section}\"]");
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
    for key in ["路径", "版", "修订", "源"] {
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

fn resolve_one(
    manifest: &Manifest,
    name: &str,
    dependency: &Dependency,
    locked: Option<&LockedPackage>,
    offline: bool,
) -> Result<ResolvedDependency, ManifestError> {
    match dependency {
        Dependency::Path { path, requirement } => {
            let root = canonical_dependency_root(&manifest.root.join(path))?;
            let resolved = lock_local(
                name,
                &root,
                &format!("path:{}", path.display()),
                None,
                requirement.as_ref(),
            )?;
            verify_locked(name, &root, &resolved, locked)?;
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
                name,
                &root,
                &format!("git:{url}"),
                Some(revision),
                requirement.as_ref(),
            )?;
            verify_locked(name, &root, &resolved, locked)?;
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
            let (root, version) = resolve_registry(name, requirement, registry, exact, offline)?;
            let resolved = lock_local(
                name,
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
            verify_locked(name, &root, &resolved, locked)?;
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
        && locked != &resolved.locked
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
    let checksum = tree_checksum(root)?;
    Ok(ResolvedDependency {
        locked: LockedPackage {
            name: expected_name.into(),
            version: dependency_manifest.version.to_string(),
            source: source.into(),
            revision,
            checksum,
            entry: dependency_manifest.entry.to_string_lossy().into_owned(),
        },
        entry: root.join(dependency_manifest.entry),
    })
}

fn resolve_git(
    url: &str,
    revision: &str,
    offline: bool,
) -> Result<(PathBuf, String), ManifestError> {
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
    run_command(
        Command::new("git")
            .arg("-C")
            .arg(&cache)
            .arg("checkout")
            .arg("--quiet")
            .arg(revision),
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

fn resolve_registry(
    name: &str,
    requirement: &VersionReq,
    registry: &str,
    locked: Option<Version>,
    offline: bool,
) -> Result<(PathBuf, Version), ManifestError> {
    let registry_path = registry
        .strip_prefix("file://")
        .map(PathBuf::from)
        .or_else(|| {
            let path = PathBuf::from(registry);
            path.is_dir().then_some(path)
        });
    if let Some(registry_path) = registry_path {
        let package_root = registry_path.join(name);
        let version = select_registry_version(&package_root, requirement, locked.as_ref())?;
        return Ok((package_root.join(version.to_string()), version));
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
        if cached.join(MANIFEST_NAME).is_file() {
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
    let index_text = fs::read_to_string(&index_path).map_err(|error| {
        manifest_error(&index_path, None, format!("不能读取索引元数据：{error}"))
    })?;
    let index: RegistryIndex = serde_json::from_str(&index_text)
        .map_err(|error| manifest_error(&index_path, None, format!("索引元数据无效：{error}")))?;
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
    let destination = registry_cache.join(name).join(version.to_string());
    let archive = registry_cache.join(format!("{name}-{version}.tar.gz"));
    download(&release.url, &archive)?;
    let actual_checksum = file_checksum(&archive)?;
    if !release.checksum.is_empty() && actual_checksum != release.checksum {
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
    validate_archive_paths(&archive)?;
    run_command(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&temporary),
        &archive,
        "展开索引制品",
    )?;
    let unpacked_root = find_manifest_root(&temporary)?;
    if destination.exists() {
        fs::remove_dir_all(&destination).map_err(|error| {
            manifest_error(&destination, None, format!("不能替换旧缓存：{error}"))
        })?;
    }
    copy_tree(&unpacked_root, &destination)?;
    fs::remove_dir_all(&temporary).ok();
    fs::remove_file(&archive).ok();
    Ok((destination, version))
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
    fs::write(path, text)
        .map_err(|error| manifest_error(path, None, format!("不能写入锁文件：{error}")))
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
    for entry in fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能遍历依赖：{error}")))?
    {
        let entry = entry
            .map_err(|error| manifest_error(directory, None, format!("不能读取目录项：{error}")))?;
        let path = entry.path();
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | "target" | LOCK_NAME)) {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else if path.is_file() {
            files.push(
                path.strip_prefix(root)
                    .expect("walk remains under root")
                    .into(),
            );
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
    run_command(
        Command::new("curl")
            .arg("--fail")
            .arg("--silent")
            .arg("--show-error")
            .arg("--location")
            .arg("--max-time")
            .arg("30")
            .arg("--output")
            .arg(destination)
            .arg(url),
        destination,
        "下载索引资源",
    )
}

fn validate_archive_paths(archive: &Path) -> Result<(), ManifestError> {
    let output = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|error| manifest_error(archive, None, format!("不能检查制品：{error}")))?;
    if !output.status.success() {
        return Err(manifest_error(archive, None, "索引制品不是有效的 tar.gz"));
    }
    for raw in String::from_utf8_lossy(&output.stdout).lines() {
        let path = Path::new(raw);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        {
            return Err(manifest_error(
                archive,
                None,
                format!("索引制品含越界路径“{raw}”"),
            ));
        }
    }
    Ok(())
}

fn find_manifest_root(directory: &Path) -> Result<PathBuf, ManifestError> {
    let mut manifests = Vec::new();
    find_manifests(directory, &mut manifests)?;
    if manifests.len() != 1 {
        return Err(manifest_error(
            directory,
            None,
            format!(
                "索引制品应恰含一个 {MANIFEST_NAME}，实有 {} 个",
                manifests.len()
            ),
        ));
    }
    Ok(manifests
        .pop()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .expect("manifest has parent"))
}

fn find_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) -> Result<(), ManifestError> {
    for entry in fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能检查展开制品：{error}")))?
    {
        let entry = entry
            .map_err(|error| manifest_error(directory, None, format!("不能读取展开项：{error}")))?;
        let path = entry.path();
        if path.is_dir() {
            find_manifests(&path, manifests)?;
        } else if entry.file_name() == MANIFEST_NAME {
            manifests.push(path);
        }
    }
    Ok(())
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
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), &destination).map_err(|error| {
                manifest_error(&destination, None, format!("不能写入制品缓存：{error}"))
            })?;
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
            环境 = ["YANXU_HOME"]
            进程 = true
        "#;
        let manifest = parse(text, path, root).unwrap();
        assert_eq!(manifest.format_version, MANIFEST_FORMAT_VERSION);
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
            "[包]\n格式=2\n名='未来'\n版='1.0.0'\n入口='主.yx'",
            PathBuf::from("言序.toml"),
            PathBuf::from("."),
        )
        .unwrap_err();
        assert!(error.message.contains("不支持包清单格式版本 2"));
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
            "lock_version = 2\nmanifest_checksum = 'none'\npackage = []\n",
        );
        let error = read_lock(&path).unwrap_err();
        assert!(error.message.contains("不支持锁文件版本 2"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn legacy_0_7_project_migrates_locks_and_executes_on_format_one() {
        let root = temp("legacy-0.7");
        write(
            &root.join(MANIFEST_NAME),
            include_str!("../tests/legacy/0.7/言序.toml"),
        );
        let legacy_source = include_str!("../tests/legacy/0.7/主.yx");
        let (migrated, findings) = crate::migration::migrate(legacy_source);
        assert_eq!(findings.len(), 1);
        assert!(migrated.contains("标准:CSV"));
        write(&root.join("主.yx"), &migrated);

        let manifest = load(root.join(MANIFEST_NAME)).unwrap();
        assert_eq!(manifest.format_version, MANIFEST_FORMAT_VERSION);
        assert!(ensure_lock(&manifest, true).unwrap().is_empty());
        let lock = read_lock(root.join(LOCK_NAME)).unwrap();
        assert_eq!(lock.lock_version, LOCK_FORMAT_VERSION);

        let statements =
            crate::parse_named(&migrated, root.join("主.yx").display().to_string()).unwrap();
        let mut interpreter =
            crate::interpreter::Interpreter::silent_with_permissions(manifest.permissions);
        interpreter
            .execute_in_directory(&statements, &root)
            .unwrap();
        assert_eq!(interpreter.output(), ["7"]);
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

        write(&dependency.join("主.yx"), "公 定 答：数 为 43；\n");
        let changed = ensure_lock(&manifest, true).unwrap_err();
        assert!(changed.message.contains("锁文件"));
        fs::remove_dir_all(root).ok();
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
        let (cache, revision) = resolve_git(&url, "HEAD", false).unwrap();
        assert_eq!(revision.len(), 40);
        let (_, offline_revision) = resolve_git(&url, &revision, true).unwrap();
        assert_eq!(revision, offline_revision);
        fs::remove_dir_all(cache).ok();
        fs::remove_dir_all(root).ok();
    }
}

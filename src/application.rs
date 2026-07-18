//! 完整 YXB 应用归档与自包含 VM 制品。

use crate::bytecode::{self, Chunk, Instruction};
use crate::package::{self, Manifest, ResolutionGraph};
use crate::permissions::PermissionSet;
use crate::source::{SourceFile, Span};
use crate::type_model::ModuleId;
use base64::Engine as _;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

pub const YXB_FORMAT_VERSION: u32 = 1;
const YXB_FORMAT_UNSUPPORTED_CODE: &str = "YXB_FORMAT_UNSUPPORTED";
const YXB_BYTECODE_UNSUPPORTED_CODE: &str = "YXB_BYTECODE_UNSUPPORTED";
const YXB_MAGIC: &[u8] = b"YANXU-YXB-1\n";
const YXB_COMPRESSED_MAGIC: &[u8] = b"YANXU-YXB-1Z\n";
const STANDALONE_MAGIC: &[u8; 16] = b"YANXU-APP-v1\0\0\0\0";
pub const YXB_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const YXB_MAX_DECODED_BYTES: u64 = 256 * 1024 * 1024;
pub const YXB_MAX_MODULES: usize = 4_096;
pub const YXB_MAX_MODULE_BYTES: u64 = 32 * 1024 * 1024;
pub const YXB_MAX_INSTRUCTIONS: usize = 1_000_000;
pub const YXB_MAX_FUNCTIONS: usize = 100_000;
pub const YXB_MAX_CLASSES: usize = 16_384;
pub const YXB_MAX_DEBUG_SPANS: usize = 1_000_000;
pub const RESOURCE_MAX_BYTES: u64 = 128 * 1024 * 1024;
pub const RESOURCE_MAX_SINGLE_BYTES: u64 = 16 * 1024 * 1024;
pub const RESOURCE_MAX_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationArchive {
    pub format_version: u32,
    pub bytecode_format: u32,
    pub package: ApplicationPackage,
    pub target: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build_commit: String,
    pub entry_module: String,
    pub modules: BTreeMap<String, ApplicationModule>,
    pub resources: BTreeMap<String, ApplicationResource>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub native_modules: BTreeMap<String, ApplicationNativeModule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationMetadata>,
    /// SPDX expressions or package-declared license identifiers captured at
    /// compile time. Bundle creation never has to rediscover source packages.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub licenses: BTreeMap<String, String>,
    pub permissions: PermissionSummary,
    pub lock_checksum: Option<String>,
    pub content_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationNativeModule {
    pub name: String,
    pub abi: u32,
    pub target: String,
    pub file: String,
    pub checksum: String,
    pub size: u64,
    pub package: String,
    pub package_version: String,
    pub bytes_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationMetadata {
    pub kind: String,
    pub name: String,
    pub identifier: String,
    pub version: String,
    pub icon: Option<String>,
    pub company: Option<String>,
    pub minimum_system_version: Option<String>,
    pub window: ApplicationWindowMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationWindowMetadata {
    pub width: u32,
    pub height: u32,
    pub minimum_width: u32,
    pub minimum_height: u32,
    pub maximum_width: Option<u32>,
    pub maximum_height: Option<u32>,
    pub resizable: bool,
    pub high_dpi: bool,
}

#[derive(Debug, Clone)]
pub struct DecodedNativeModule {
    pub metadata: ApplicationNativeModule,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationModule {
    pub id: String,
    pub display_path: String,
    pub chunk: Chunk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationResource {
    pub path: String,
    pub bytes_base64: String,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSummary {
    pub unrestricted: bool,
    pub files: Vec<String>,
    pub network: Vec<String>,
    #[serde(default)]
    pub local_network: bool,
    pub tcp_listen: Vec<String>,
    pub udp_bind: Vec<String>,
    pub environment: Vec<String>,
    pub process: bool,
    pub native_extensions: bool,
    #[serde(default)]
    pub graphical_interface: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub file_dialog: bool,
    #[serde(default)]
    pub system_notifications: bool,
    #[serde(default)]
    pub tray: bool,
    #[serde(default)]
    pub open_external_url: bool,
    #[serde(default)]
    pub global_shortcuts: bool,
}

impl PermissionSummary {
    fn from_permissions(permissions: &PermissionSet, root: &Path) -> Self {
        Self {
            unrestricted: permissions.is_unrestricted(),
            files: permissions
                .file_roots()
                .iter()
                .map(|path| {
                    path.strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect(),
            network: permissions.network_hosts().map(str::to_owned).collect(),
            local_network: permissions.local_network_allowed(),
            tcp_listen: permissions.tcp_listen_hosts().map(str::to_owned).collect(),
            udp_bind: permissions.udp_bind_hosts().map(str::to_owned).collect(),
            environment: permissions
                .environment_variables()
                .map(str::to_owned)
                .collect(),
            process: permissions.process_allowed(),
            native_extensions: permissions.native_extensions_allowed(),
            graphical_interface: permissions.graphical_interface_allowed(),
            clipboard: permissions.clipboard_allowed(),
            file_dialog: permissions.file_dialog_allowed(),
            system_notifications: permissions.system_notifications_allowed(),
            tray: permissions.tray_allowed(),
            open_external_url: permissions.open_external_url_allowed(),
            global_shortcuts: permissions.global_shortcuts_allowed(),
        }
    }

    pub fn to_permissions(&self, root: &Path) -> PermissionSet {
        if self.unrestricted {
            return PermissionSet::unrestricted();
        }
        let mut permissions = PermissionSet::sandboxed();
        for path in &self.files {
            permissions = permissions.allow_file(root.join(path));
        }
        for host in &self.network {
            permissions = permissions.allow_network(host);
        }
        if self.local_network {
            permissions = permissions.allow_local_network();
        }
        for host in &self.tcp_listen {
            permissions = permissions.allow_tcp_listen(host);
        }
        for host in &self.udp_bind {
            permissions = permissions.allow_udp_bind(host);
        }
        for variable in &self.environment {
            permissions = permissions.allow_environment(variable);
        }
        if self.process {
            permissions = permissions.allow_process();
        }
        if self.native_extensions {
            permissions = permissions.allow_native_extensions();
        }
        if self.graphical_interface {
            permissions = permissions.allow_graphical_interface();
        }
        if self.clipboard {
            permissions = permissions.allow_clipboard();
        }
        if self.file_dialog {
            permissions = permissions.allow_file_dialog();
        }
        if self.system_notifications {
            permissions = permissions.allow_system_notifications();
        }
        if self.tray {
            permissions = permissions.allow_tray();
        }
        if self.open_external_url {
            permissions = permissions.allow_open_external_url();
        }
        if self.global_shortcuts {
            permissions = permissions.allow_global_shortcuts();
        }
        permissions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationError {
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct ArchiveFormatHeader {
    format_version: u64,
    bytecode_format: u64,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "YXB 应用有误：{}", self.message)
    }
}

impl std::error::Error for ApplicationError {}

impl From<package::ManifestError> for ApplicationError {
    fn from(error: package::ManifestError) -> Self {
        package_error(error)
    }
}

pub fn compile_application(
    input: impl AsRef<Path>,
    profile: &str,
) -> Result<ApplicationArchive, ApplicationError> {
    if !matches!(profile, "debug" | "release") {
        return Err(application_error("构建配置只可为 debug 或 release"));
    }
    let input = input.as_ref();
    let manifest = package::discover(input).map_err(package_error)?;
    if let Some(manifest) = manifest {
        validate_runtime_version(&manifest)?;
        return package::with_locked_resolution(&manifest, false, |graph| {
            let entry = fs::canonicalize(manifest.root.join(&manifest.entry)).map_err(|error| {
                application_error(format!(
                    "不能定位入口 {}：{error}",
                    manifest.entry.display()
                ))
            })?;
            let resources = collect_resources(&manifest)?;
            let lock_checksum = checksum_file(&manifest.root.join(package::LOCK_NAME)).ok();
            let summary =
                PermissionSummary::from_permissions(&manifest.permissions, &manifest.root);
            let native_modules = collect_native_modules(&graph)?;
            let application = manifest.application.as_ref().map(application_metadata);
            let licenses = collect_licenses(&manifest, &graph)?;
            compile_resolved_application(
                entry,
                fs::canonicalize(&manifest.root).map_err(io_error)?,
                Some(manifest.root.clone()),
                ApplicationPackage {
                    name: manifest.name.clone(),
                    version: manifest.version.to_string(),
                },
                summary,
                Some(graph),
                resources,
                native_modules,
                application,
                licenses,
                lock_checksum,
                profile,
            )
        });
    }
    let entry = fs::canonicalize(input)
        .map_err(|error| application_error(format!("不能定位文卷 {}：{error}", input.display())))?;
    let root = entry
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let package_info = ApplicationPackage {
        name: entry
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("应用")
            .to_owned(),
        version: "0.0.0".into(),
    };
    compile_resolved_application(
        entry,
        root,
        None,
        package_info,
        PermissionSummary::from_permissions(&PermissionSet::unrestricted(), Path::new(".")),
        None,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        BTreeMap::new(),
        None,
        profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_resolved_application(
    entry: PathBuf,
    root: PathBuf,
    package_root: Option<PathBuf>,
    package_info: ApplicationPackage,
    permissions: PermissionSummary,
    graph: Option<ResolutionGraph>,
    resources: BTreeMap<String, ApplicationResource>,
    native_modules: BTreeMap<String, ApplicationNativeModule>,
    application: Option<ApplicationMetadata>,
    licenses: BTreeMap<String, String>,
    lock_checksum: Option<String>,
    profile: &str,
) -> Result<ApplicationArchive, ApplicationError> {
    let mut compiler = ApplicationCompiler {
        root,
        package_root,
        graph,
        modules: BTreeMap::new(),
        visiting: BTreeSet::new(),
    };
    let entry_module = compiler.logical_id(&entry)?;
    compiler.compile_module(&entry, &entry_module)?;
    let mut archive = ApplicationArchive {
        format_version: YXB_FORMAT_VERSION,
        bytecode_format: bytecode::BYTECODE_FORMAT_VERSION,
        package: package_info,
        target: package::current_target(),
        profile: profile.into(),
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        build_commit: crate::build_info::COMMIT_SHA.into(),
        entry_module,
        modules: compiler.modules,
        resources,
        native_modules,
        application,
        licenses,
        permissions,
        lock_checksum,
        content_checksum: String::new(),
    };
    archive.content_checksum = archive_checksum(&archive)?;
    validate_archive(&archive)?;
    Ok(archive)
}

fn validate_runtime_version(manifest: &Manifest) -> Result<(), ApplicationError> {
    if let Some(requirement) = &manifest.minimum_yanxu {
        let version = semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|error| application_error(error.to_string()))?;
        if !requirement.matches(&version) {
            return Err(application_error(format!(
                "包要求言序 {requirement}，当前为 {version}"
            )));
        }
    }
    Ok(())
}

struct ApplicationCompiler {
    root: PathBuf,
    package_root: Option<PathBuf>,
    graph: Option<ResolutionGraph>,
    modules: BTreeMap<String, ApplicationModule>,
    visiting: BTreeSet<String>,
}

impl ApplicationCompiler {
    fn compile_module(&mut self, path: &Path, id: &str) -> Result<(), ApplicationError> {
        if self.modules.contains_key(id) {
            return Ok(());
        }
        if !self.visiting.insert(id.to_owned()) {
            return Err(application_error(format!("模块循环相引：{id}")));
        }
        let source = fs::read_to_string(path).map_err(|error| {
            application_error(format!("不能读取模块 {}：{error}", path.display()))
        })?;
        let statements = crate::parse_named(&source, self.display_path(path))
            .map_err(|error| application_error(error.to_string()))?;
        crate::type_checker::check_in_directory(&statements, path.parent().unwrap_or(&self.root))
            .map_err(|errors| {
            application_error(
                errors
                    .into_iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        })?;
        let mut chunk =
            bytecode::compile_with_module_id(&statements, ModuleId::archive(id.to_owned()))
                .map_err(|error| application_error(error.to_string()))?;
        self.rewrite_chunk_imports(&mut chunk, path)?;
        compact_debug_sources(&mut chunk);
        self.visiting.remove(id);
        self.modules.insert(
            id.to_owned(),
            ApplicationModule {
                id: id.to_owned(),
                display_path: self.display_path(path),
                chunk,
            },
        );
        Ok(())
    }

    fn rewrite_chunk_imports(
        &mut self,
        chunk: &mut Chunk,
        current_path: &Path,
    ) -> Result<(), ApplicationError> {
        let imports = chunk
            .code
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| match instruction {
                Instruction::Import { path, .. } if !path.starts_with("标准:") => {
                    Some((index, path.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (index, requested) in imports {
            let resolved = self.resolve_import(current_path, &requested)?;
            let id = self.logical_id(&resolved)?;
            self.compile_module(&resolved, &id)?;
            if let Instruction::Import { path, .. } = &mut chunk.code[index] {
                *path = format!("归档:{id}");
            }
        }
        for function in &mut chunk.functions {
            self.rewrite_chunk_imports(&mut function.chunk, current_path)?;
        }
        for class in &mut chunk.classes {
            for method in &mut class.methods {
                self.rewrite_chunk_imports(&mut method.chunk, current_path)?;
            }
        }
        Ok(())
    }

    fn resolve_import(
        &self,
        current_path: &Path,
        requested: &str,
    ) -> Result<PathBuf, ApplicationError> {
        if let Some(name) = requested.strip_prefix("包:") {
            return package::resolve_dependency_scoped(
                self.package_root.as_deref(),
                current_path.parent().unwrap_or_else(|| Path::new(".")),
                name,
            )
            .map(|dependency| dependency.entry)
            .map_err(package_error);
        }
        let path = Path::new(requested);
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            current_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        };
        fs::canonicalize(&joined)
            .map_err(|error| application_error(format!("不能解析模块“{requested}”：{error}")))
    }

    fn logical_id(&self, path: &Path) -> Result<String, ApplicationError> {
        let canonical = fs::canonicalize(path).map_err(io_error)?;
        if canonical.starts_with(&self.root) {
            return Ok(format!(
                "app:{}",
                relative_string(canonical.strip_prefix(&self.root).expect("prefix"))
            ));
        }
        if let Some(graph) = &self.graph
            && let Some((id, dependency)) = graph
                .packages
                .iter()
                .filter(|(_, dependency)| canonical.starts_with(&dependency.root))
                .max_by_key(|(_, dependency)| dependency.root.components().count())
        {
            let relative = canonical.strip_prefix(&dependency.root).expect("prefix");
            return Ok(format!("pkg:{id}:{}", relative_string(relative)));
        }
        Err(application_error(format!(
            "模块 {} 不属于项目或锁定依赖图",
            canonical.display()
        )))
    }

    fn display_path(&self, path: &Path) -> String {
        self.logical_id(path).unwrap_or_else(|_| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
    }
}

fn compact_debug_sources(chunk: &mut Chunk) {
    let mut sources = BTreeMap::new();
    compact_chunk_debug_sources(chunk, &mut sources);
}

fn compact_chunk_debug_sources(
    chunk: &mut Chunk,
    sources: &mut BTreeMap<(String, usize, String), Rc<SourceFile>>,
) {
    for span in &mut chunk.spans {
        compact_span_source(span, sources);
    }
    for function in &mut chunk.functions {
        compact_span_source(&mut function.span, sources);
        compact_chunk_debug_sources(&mut function.chunk, sources);
    }
    for class in &mut chunk.classes {
        for method in &mut class.methods {
            compact_span_source(&mut method.span, sources);
            compact_chunk_debug_sources(&mut method.chunk, sources);
        }
    }
}

fn compact_span_source(
    span: &mut Span,
    sources: &mut BTreeMap<(String, usize, String), Rc<SourceFile>>,
) {
    let name = span.source.name.clone();
    let line = span.line;
    let source_line = span.source.line(line).unwrap_or("").to_owned();
    let key = (name.clone(), line, source_line.clone());
    span.source = sources
        .entry(key)
        .or_insert_with(|| {
            let mut text = "\n".repeat(line.saturating_sub(1));
            text.push_str(&source_line);
            SourceFile::new(name, text)
        })
        .clone();
}

fn collect_resources(
    manifest: &Manifest,
) -> Result<BTreeMap<String, ApplicationResource>, ApplicationError> {
    let canonical_root = fs::canonicalize(&manifest.root).map_err(io_error)?;
    let mut files = Vec::new();
    for resource in &manifest.resources {
        let path = manifest.root.join(resource);
        collect_resource_files(&manifest.root, &path, &mut files)?;
    }
    if let Some(icon) = manifest
        .application
        .as_ref()
        .and_then(|application| application.icon.as_ref())
    {
        collect_resource_files(&manifest.root, &manifest.root.join(icon), &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.len() > RESOURCE_MAX_ENTRIES {
        return Err(application_error(format!(
            "资源条目不得超过 {RESOURCE_MAX_ENTRIES}"
        )));
    }
    let mut total = 0_u64;
    let mut resources = BTreeMap::new();
    for path in files {
        let bytes = fs::read(&path).map_err(io_error)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| application_error("资源总大小溢出"))?;
        if total > RESOURCE_MAX_BYTES {
            return Err(application_error(format!(
                "资源总大小不得超过 {RESOURCE_MAX_BYTES} 字节"
            )));
        }
        let relative = relative_string(
            path.strip_prefix(&canonical_root)
                .map_err(|_| application_error("资源越出包根目录"))?,
        );
        resources.insert(
            relative.clone(),
            ApplicationResource {
                path: relative,
                checksum: format!("{:x}", Sha256::digest(&bytes)),
                bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
        );
    }
    Ok(resources)
}

fn collect_native_modules(
    graph: &ResolutionGraph,
) -> Result<BTreeMap<String, ApplicationNativeModule>, ApplicationError> {
    if graph.target != package::current_target() {
        return Err(application_error(format!(
            "锁定依赖目标 {} 与当前目标 {} 不符",
            graph.target,
            package::current_target()
        )));
    }
    let mut modules = BTreeMap::new();
    let mut total = 0_u64;
    for dependency in graph.packages.values() {
        let Some(artifact) = dependency.locked.native.as_ref() else {
            continue;
        };
        if modules.len() >= package::NATIVE_ARTIFACT_MAX_COUNT {
            return Err(application_error(format!(
                "YXB 原生模块不得超过 {} 个",
                package::NATIVE_ARTIFACT_MAX_COUNT
            )));
        }
        if artifact.target != graph.target || !matches!(artifact.abi, 1 | 2) {
            return Err(application_error(format!(
                "锁定原生制品 {} 的目标或 ABI 无效",
                dependency.locked.name
            )));
        }
        let source = dependency.root.join(&artifact.path);
        let metadata = fs::symlink_metadata(&source).map_err(|error| {
            application_error(format!("不能检查原生制品 {}：{error}", source.display()))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(application_error(format!(
                "原生制品 {} 必须是普通文件，不能是链接或特殊文件",
                source.display()
            )));
        }
        if metadata.len() != artifact.size || metadata.len() > package::NATIVE_ARTIFACT_MAX_BYTES {
            return Err(application_error(format!(
                "原生制品 {} 大小与锁文件不符或超过上限",
                source.display()
            )));
        }
        let bytes = read_limited_file(&source, package::NATIVE_ARTIFACT_MAX_BYTES, "原生制品")?;
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        if checksum != artifact.checksum.to_ascii_lowercase() {
            return Err(application_error(format!(
                "原生制品 {} 摘要与锁文件不符",
                source.display()
            )));
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| application_error("YXB 原生制品总大小溢出"))?;
        if total > package::NATIVE_ARTIFACT_MAX_TOTAL_BYTES {
            return Err(application_error(format!(
                "YXB 原生制品总大小不得超过 {} 字节",
                package::NATIVE_ARTIFACT_MAX_TOTAL_BYTES
            )));
        }
        let file_name = Path::new(&artifact.path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| application_error("原生制品文件名不是 UTF-8"))?;
        let module = ApplicationNativeModule {
            name: dependency.locked.name.clone(),
            abi: artifact.abi,
            target: artifact.target.clone(),
            file: format!("native/{checksum}/{file_name}"),
            checksum,
            size: artifact.size,
            package: dependency.locked.name.clone(),
            package_version: dependency.locked.version.clone(),
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        if modules
            .insert(dependency.locked.name.clone(), module)
            .is_some()
        {
            return Err(application_error(format!(
                "锁定依赖图含多个名为“{}”的原生模块，不能写入 YXB",
                dependency.locked.name
            )));
        }
    }
    Ok(modules)
}

fn collect_licenses(
    manifest: &Manifest,
    graph: &ResolutionGraph,
) -> Result<BTreeMap<String, String>, ApplicationError> {
    let mut licenses = BTreeMap::new();
    if let Some(license) = manifest.license.as_ref() {
        licenses.insert(
            format!("{}@{}", manifest.name, manifest.version),
            license.clone(),
        );
    }
    for dependency in graph.packages.values() {
        let dependency_manifest = package::discover(&dependency.root)
            .map_err(package_error)?
            .ok_or_else(|| application_error("锁定依赖缺少言序清单"))?;
        if let Some(license) = dependency_manifest.license {
            licenses.insert(
                format!(
                    "{}@{}",
                    dependency_manifest.name, dependency_manifest.version
                ),
                license,
            );
        }
    }
    Ok(licenses)
}

fn application_metadata(application: &package::ApplicationConfig) -> ApplicationMetadata {
    ApplicationMetadata {
        kind: application.kind.as_str().into(),
        name: application.name.clone(),
        identifier: application.identifier.clone(),
        version: application.version.to_string(),
        icon: application.icon.as_ref().map(|path| relative_string(path)),
        company: application.company.clone(),
        minimum_system_version: application.minimum_system_version.clone(),
        window: ApplicationWindowMetadata {
            width: application.window.width,
            height: application.window.height,
            minimum_width: application.window.minimum_width,
            minimum_height: application.window.minimum_height,
            maximum_width: application.window.maximum_width,
            maximum_height: application.window.maximum_height,
            resizable: application.window.resizable,
            high_dpi: application.window.high_dpi,
        },
    }
}

fn collect_resource_files(
    root: &Path,
    path: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), ApplicationError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() {
        return Err(application_error(format!(
            "资源不得包含符号链接：{}",
            path.display()
        )));
    }
    if metadata.is_file() {
        let canonical = fs::canonicalize(path).map_err(io_error)?;
        let root = fs::canonicalize(root).map_err(io_error)?;
        if !canonical.starts_with(root) {
            return Err(application_error("资源越出包根目录"));
        }
        output.push(canonical);
        return Ok(());
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(io_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            collect_resource_files(root, &entry.path(), output)?;
        }
        return Ok(());
    }
    Err(application_error(format!(
        "资源只可为普通文件或目录：{}",
        path.display()
    )))
}

pub fn serialize(archive: &ApplicationArchive) -> Result<Vec<u8>, ApplicationError> {
    validate_archive(archive)?;
    let mut bytes = YXB_COMPRESSED_MAGIC.to_vec();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    serde_json::to_writer(&mut encoder, archive)
        .map_err(|error| application_error(format!("不能序列化：{error}")))?;
    bytes.extend(
        encoder
            .finish()
            .map_err(|error| application_error(format!("不能压缩归档：{error}")))?,
    );
    if bytes.len() as u64 > YXB_MAX_FILE_BYTES {
        return Err(application_error(format!(
            "YXB 压缩制品不得超过 {} MiB",
            YXB_MAX_FILE_BYTES / 1024 / 1024
        )));
    }
    Ok(bytes)
}

pub fn deserialize(bytes: &[u8]) -> Result<ApplicationArchive, ApplicationError> {
    deserialize_with_limits(bytes, YXB_MAX_FILE_BYTES, YXB_MAX_DECODED_BYTES)
}

fn deserialize_with_limits(
    bytes: &[u8],
    file_limit: u64,
    decoded_limit: u64,
) -> Result<ApplicationArchive, ApplicationError> {
    if bytes.len() as u64 > file_limit {
        return Err(application_error(format!(
            "YXB 文件不得超过 {} MiB",
            file_limit / 1024 / 1024
        )));
    }
    let payload = if let Some(compressed) = bytes.strip_prefix(YXB_COMPRESSED_MAGIC) {
        let mut decoder = ZlibDecoder::new(compressed);
        let mut payload = Vec::new();
        decoder
            .by_ref()
            .take(decoded_limit + 1)
            .read_to_end(&mut payload)
            .map_err(|error| application_error(format!("归档压缩载荷无效：{error}")))?;
        if payload.len() as u64 > decoded_limit {
            return Err(application_error("YXB 解压后超过大小限制"));
        }
        payload
    } else if let Some(payload) = bytes.strip_prefix(YXB_MAGIC) {
        if payload.len() as u64 > decoded_limit {
            return Err(application_error("YXB JSON 超过大小限制"));
        }
        payload.to_vec()
    } else {
        return Err(application_error("缺少 YXB 文件头"));
    };
    reject_duplicate_json_keys(&payload)?;
    let header: ArchiveFormatHeader = serde_json::from_slice(&payload)
        .map_err(|error| application_error(format!("归档格式头无效：{error}")))?;
    if header.format_version != u64::from(YXB_FORMAT_VERSION) {
        return Err(unsupported_yxb_format(header.format_version));
    }
    if header.bytecode_format != u64::from(bytecode::BYTECODE_FORMAT_VERSION) {
        return Err(unsupported_yxb_bytecode(
            header.format_version,
            header.bytecode_format,
        ));
    }
    let archive: ApplicationArchive = serde_json::from_slice(&payload)
        .map_err(|error| application_error(format!("归档 JSON 无效：{error}")))?;
    validate_archive(&archive)?;
    Ok(archive)
}

fn reject_duplicate_json_keys(payload: &[u8]) -> Result<(), ApplicationError> {
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
        .map_err(|error| application_error(format!("归档 JSON 无效：{error}")))
}

pub fn validate_archive(archive: &ApplicationArchive) -> Result<(), ApplicationError> {
    if archive.format_version != YXB_FORMAT_VERSION {
        return Err(unsupported_yxb_format(u64::from(archive.format_version)));
    }
    if archive.bytecode_format != bytecode::BYTECODE_FORMAT_VERSION {
        return Err(unsupported_yxb_bytecode(
            u64::from(archive.format_version),
            u64::from(archive.bytecode_format),
        ));
    }
    if archive.target.is_empty() || archive.target.len() > 256 {
        return Err(application_error("YXB 目标平台为空或过长"));
    }
    if !matches!(archive.profile.as_str(), "debug" | "release") {
        return Err(application_error("YXB 构建模式只可为 debug 或 release"));
    }
    if archive.runtime_version.len() > 64 || archive.build_commit.len() > 128 {
        return Err(application_error("YXB 构建身份字段过长"));
    }
    if archive.licenses.len() > YXB_MAX_MODULES
        || archive.licenses.iter().any(|(package, license)| {
            package.is_empty()
                || package.len() > 512
                || package.contains(['\0', '\r', '\n'])
                || license.is_empty()
                || license.len() > 512
                || license.contains(['\0', '\r', '\n'])
        })
    {
        return Err(application_error("YXB 许可证索引非法或超过限制"));
    }
    if archive.modules.len() > YXB_MAX_MODULES {
        return Err(application_error(format!(
            "YXB 模块不得超过 {YXB_MAX_MODULES} 个"
        )));
    }
    if !valid_module_id(&archive.entry_module) {
        return Err(application_error("YXB 入口模块 ID 非法"));
    }
    if !archive.modules.contains_key(&archive.entry_module) {
        return Err(application_error("YXB 缺少入口模块"));
    }
    let mut module_ids = BTreeSet::new();
    let mut stats = ArchiveStats::default();
    for (id, module) in &archive.modules {
        if id != &module.id || !valid_module_id(id) || !module_ids.insert(module.id.clone()) {
            return Err(application_error(format!(
                "YXB 模块 ID 非法、重复或与索引不一致：{id}"
            )));
        }
        let mut counter = CountingWriter::default();
        serde_json::to_writer(&mut counter, module)
            .map_err(|error| application_error(format!("不能检查模块大小：{error}")))?;
        if counter.bytes > YXB_MAX_MODULE_BYTES {
            return Err(application_error(format!(
                "YXB 模块 {id} 超过 {} MiB",
                YXB_MAX_MODULE_BYTES / 1024 / 1024
            )));
        }
        if module.chunk.module_id != ModuleId::archive(id.clone()) {
            return Err(application_error(format!(
                "YXB 模块 {id} 的规范模块身份不一致"
            )));
        }
        bytecode::validate_format(&module.chunk)
            .map_err(|error| application_error(error.to_string()))?;
        validate_chunk(&module.chunk, archive, &mut stats)?;
    }
    if stats.instructions > YXB_MAX_INSTRUCTIONS {
        return Err(application_error(format!(
            "YXB 指令总量不得超过 {YXB_MAX_INSTRUCTIONS}"
        )));
    }
    if stats.functions > YXB_MAX_FUNCTIONS {
        return Err(application_error(format!(
            "YXB 函数总量不得超过 {YXB_MAX_FUNCTIONS}"
        )));
    }
    if stats.classes > YXB_MAX_CLASSES {
        return Err(application_error(format!(
            "YXB 类总量不得超过 {YXB_MAX_CLASSES}"
        )));
    }
    if stats.debug_spans > YXB_MAX_DEBUG_SPANS {
        return Err(application_error(format!(
            "YXB 调试位置总量不得超过 {YXB_MAX_DEBUG_SPANS}"
        )));
    }
    validate_resources(archive)?;
    validate_native_modules(archive)?;
    validate_application_metadata(archive)?;
    let actual = archive_checksum(archive)?;
    if archive.content_checksum != actual {
        return Err(application_error(format!(
            "YXB 内容校验不符：记录 {}，实际 {actual}",
            archive.content_checksum
        )));
    }
    Ok(())
}

pub fn decode_native_modules(
    archive: &ApplicationArchive,
) -> Result<Rc<BTreeMap<String, DecodedNativeModule>>, ApplicationError> {
    validate_native_modules(archive).map(Rc::new)
}

fn validate_native_modules(
    archive: &ApplicationArchive,
) -> Result<BTreeMap<String, DecodedNativeModule>, ApplicationError> {
    if archive.native_modules.len() > package::NATIVE_ARTIFACT_MAX_COUNT {
        return Err(application_error(format!(
            "YXB 原生模块不得超过 {} 个",
            package::NATIVE_ARTIFACT_MAX_COUNT
        )));
    }
    let mut total = 0_u64;
    let mut decoded = BTreeMap::new();
    for (package_name, module) in &archive.native_modules {
        if package_name != &module.package
            || package_name != &module.name
            || package_name.is_empty()
            || module.package_version.parse::<semver::Version>().is_err()
            || !matches!(module.abi, 1 | 2)
            || module.target != archive.target
            || module.checksum.len() != 64
            || !module.checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(application_error(format!(
                "YXB 原生模块“{package_name}”的锁定元数据无效"
            )));
        }
        let normalized_file = normalize_resource_key(&module.file)?;
        if normalized_file != module.file || !module.file.starts_with("native/") {
            return Err(application_error(format!(
                "YXB 原生模块“{package_name}”路径非法"
            )));
        }
        let max_encoded = package::NATIVE_ARTIFACT_MAX_BYTES.div_ceil(3) * 4 + 4;
        if module.bytes_base64.len() as u64 > max_encoded {
            return Err(application_error(format!(
                "YXB 原生模块“{package_name}”编码体积超过上限"
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&module.bytes_base64)
            .map_err(|error| {
                application_error(format!("YXB 原生模块“{package_name}”编码无效：{error}"))
            })?;
        if bytes.len() as u64 != module.size || module.size > package::NATIVE_ARTIFACT_MAX_BYTES {
            return Err(application_error(format!(
                "YXB 原生模块“{package_name}”大小不符或超过上限"
            )));
        }
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        if checksum != module.checksum.to_ascii_lowercase() {
            return Err(application_error(format!(
                "YXB 原生模块“{package_name}”摘要不符"
            )));
        }
        total = total
            .checked_add(module.size)
            .ok_or_else(|| application_error("YXB 原生模块总大小溢出"))?;
        if total > package::NATIVE_ARTIFACT_MAX_TOTAL_BYTES {
            return Err(application_error(format!(
                "YXB 原生模块总大小不得超过 {} 字节",
                package::NATIVE_ARTIFACT_MAX_TOTAL_BYTES
            )));
        }
        decoded.insert(
            package_name.clone(),
            DecodedNativeModule {
                metadata: module.clone(),
                bytes,
            },
        );
    }
    Ok(decoded)
}

fn validate_application_metadata(archive: &ApplicationArchive) -> Result<(), ApplicationError> {
    let Some(application) = &archive.application else {
        return Ok(());
    };
    if !matches!(application.kind.as_str(), "图形" | "命令行")
        || application.name.trim().is_empty()
        || application.name.chars().count() > 128
        || application.version.parse::<semver::Version>().is_err()
        || !valid_application_identifier(&application.identifier)
    {
        return Err(application_error(
            "YXB 应用元数据中的类型、名称、标识或版本无效",
        ));
    }
    let window = &application.window;
    if !valid_dimension(window.width)
        || !valid_dimension(window.height)
        || !valid_dimension(window.minimum_width)
        || !valid_dimension(window.minimum_height)
        || window
            .maximum_width
            .is_some_and(|value| !valid_dimension(value))
        || window
            .maximum_height
            .is_some_and(|value| !valid_dimension(value))
        || window.minimum_width > window.width
        || window.minimum_height > window.height
        || window
            .maximum_width
            .is_some_and(|value| value < window.width)
        || window
            .maximum_height
            .is_some_and(|value| value < window.height)
    {
        return Err(application_error("YXB 应用窗口尺寸无效"));
    }
    if application.kind == "图形" && !archive.permissions.graphical_interface {
        return Err(application_error("YXB 图形应用未申请图形界面权限"));
    }
    if let Some(icon) = &application.icon {
        let normalized = normalize_resource_key(icon)?;
        if normalized != *icon || !archive.resources.contains_key(icon) {
            return Err(application_error("YXB 应用图标未作为包内资源携带"));
        }
    }
    Ok(())
}

fn valid_dimension(value: u32) -> bool {
    (1..=16_384).contains(&value)
}

fn valid_application_identifier(identifier: &str) -> bool {
    if identifier.len() > 255 || !identifier.is_ascii() {
        return false;
    }
    let labels = identifier.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Default)]
struct ArchiveStats {
    instructions: usize,
    functions: usize,
    classes: usize,
    debug_spans: usize,
}

fn validate_chunk(
    chunk: &Chunk,
    archive: &ApplicationArchive,
    stats: &mut ArchiveStats,
) -> Result<(), ApplicationError> {
    if chunk.format_version != bytecode::BYTECODE_FORMAT_VERSION {
        return Err(application_error(format!(
            "模块内字节码格式 {} 与运行时 {} 不兼容",
            chunk.format_version,
            bytecode::BYTECODE_FORMAT_VERSION
        )));
    }
    stats.instructions = stats
        .instructions
        .checked_add(chunk.code.len())
        .ok_or_else(|| application_error("YXB 指令总量溢出"))?;
    stats.debug_spans = stats
        .debug_spans
        .checked_add(chunk.spans.len())
        .ok_or_else(|| application_error("YXB 调试位置总量溢出"))?;
    if chunk.code.len() != chunk.spans.len() {
        return Err(application_error("YXB 指令与调试位置数量不一致"));
    }
    for instruction in &chunk.code {
        if let Instruction::Import { path, .. } = instruction {
            if let Some(id) = path.strip_prefix("归档:") {
                if !valid_module_id(id) || !archive.modules.contains_key(id) {
                    return Err(application_error(format!(
                        "YXB 归档导入指向不存在或非法模块：{id}"
                    )));
                }
            } else if !path.starts_with("标准:") {
                return Err(application_error(format!(
                    "YXB 归档只可导入内部模块或标准库：{path}"
                )));
            }
        }
    }
    stats.functions = stats
        .functions
        .checked_add(chunk.functions.len())
        .ok_or_else(|| application_error("YXB 函数总量溢出"))?;
    stats.classes = stats
        .classes
        .checked_add(chunk.classes.len())
        .ok_or_else(|| application_error("YXB 类总量溢出"))?;
    stats.debug_spans = stats
        .debug_spans
        .checked_add(chunk.functions.len())
        .and_then(|count| {
            count.checked_add(
                chunk
                    .classes
                    .iter()
                    .map(|class| class.methods.len())
                    .sum::<usize>(),
            )
        })
        .ok_or_else(|| application_error("YXB 调试位置总量溢出"))?;
    for function in &chunk.functions {
        validate_chunk(&function.chunk, archive, stats)?;
    }
    for class in &chunk.classes {
        stats.functions = stats
            .functions
            .checked_add(class.methods.len())
            .ok_or_else(|| application_error("YXB 函数总量溢出"))?;
        for method in &class.methods {
            validate_chunk(&method.chunk, archive, stats)?;
        }
    }
    Ok(())
}

fn valid_module_id(id: &str) -> bool {
    if id.is_empty()
        || id.len() > 1_024
        || id.contains(['\\', '\0'])
        || !(id.starts_with("app:") || id.starts_with("pkg:"))
    {
        return false;
    }
    let path = id.rsplit_once(':').map_or(id, |(_, path)| path);
    !path.is_empty()
        && !Path::new(path).is_absolute()
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn archive_checksum(archive: &ApplicationArchive) -> Result<String, ApplicationError> {
    let mut unsigned = archive.clone();
    unsigned.content_checksum.clear();
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, &unsigned)
        .map_err(|error| application_error(format!("不能计算归档校验：{error}")))?;
    Ok(format!("{:x}", writer.0.finalize()))
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CountingWriter {
    bytes: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("serialized size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn write_archive(
    archive: &ApplicationArchive,
    output: impl AsRef<Path>,
) -> Result<(), ApplicationError> {
    let bytes = serialize(archive)?;
    let output = output.as_ref();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    fs::write(output, bytes).map_err(io_error)
}

pub fn read_archive(path: impl AsRef<Path>) -> Result<ApplicationArchive, ApplicationError> {
    let bytes = read_limited_file(path.as_ref(), YXB_MAX_FILE_BYTES, "YXB 文件")?;
    deserialize(&bytes)
}

pub fn write_standalone(
    runtime: impl AsRef<Path>,
    archive: &ApplicationArchive,
    output: impl AsRef<Path>,
) -> Result<(), ApplicationError> {
    let runtime = runtime.as_ref();
    let mut bytes = fs::read(runtime).map_err(io_error)?;
    let application = serialize(archive)?;
    bytes.extend_from_slice(&application);
    bytes.extend_from_slice(&(application.len() as u64).to_le_bytes());
    bytes.extend_from_slice(STANDALONE_MAGIC);
    let output = output.as_ref();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    fs::write(output, bytes).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(runtime)
            .map_err(io_error)?
            .permissions()
            .mode();
        fs::set_permissions(output, fs::Permissions::from_mode(mode)).map_err(io_error)?;
    }
    Ok(())
}

pub fn read_embedded(
    path: impl AsRef<Path>,
) -> Result<Option<ApplicationArchive>, ApplicationError> {
    let mut file = fs::File::open(path.as_ref()).map_err(io_error)?;
    let footer = STANDALONE_MAGIC.len() + std::mem::size_of::<u64>();
    let file_length = file.metadata().map_err(io_error)?.len();
    if file_length < footer as u64 {
        return Ok(None);
    }
    file.seek(SeekFrom::End(-(footer as i64)))
        .map_err(io_error)?;
    let mut length_bytes = [0_u8; 8];
    file.read_exact(&mut length_bytes).map_err(io_error)?;
    let mut magic = [0_u8; STANDALONE_MAGIC.len()];
    file.read_exact(&mut magic).map_err(io_error)?;
    if &magic != STANDALONE_MAGIC {
        return Ok(None);
    }
    let length = u64::from_le_bytes(length_bytes);
    let payload_end = file_length - footer as u64;
    if length > payload_end || length > YXB_MAX_FILE_BYTES {
        return Err(application_error("独立制品中的 YXB 长度越界"));
    }
    file.seek(SeekFrom::Start(payload_end - length))
        .map_err(io_error)?;
    let mut bytes = vec![0_u8; length as usize];
    file.read_exact(&mut bytes).map_err(io_error)?;
    deserialize(&bytes).map(Some)
}

pub fn decode_resources(
    archive: &ApplicationArchive,
) -> Result<Rc<BTreeMap<String, Vec<u8>>>, ApplicationError> {
    validate_resources(archive).map(Rc::new)
}

fn validate_resources(
    archive: &ApplicationArchive,
) -> Result<BTreeMap<String, Vec<u8>>, ApplicationError> {
    if archive.resources.len() > RESOURCE_MAX_ENTRIES {
        return Err(application_error(format!(
            "YXB 资源不得超过 {RESOURCE_MAX_ENTRIES} 项"
        )));
    }
    let max_encoded = RESOURCE_MAX_SINGLE_BYTES.div_ceil(3) * 4 + 4;
    let mut total = 0_u64;
    let mut paths = BTreeSet::new();
    let mut decoded = BTreeMap::new();
    for (path, resource) in &archive.resources {
        let normalized = normalize_resource_key(path)?;
        if normalized != *path || resource.path != *path || !paths.insert(resource.path.clone()) {
            return Err(application_error(format!(
                "资源路径非法、重复或与索引不一致：{path}"
            )));
        }
        if resource.bytes_base64.len() as u64 > max_encoded {
            return Err(application_error(format!(
                "资源 {path} 的编码体积超过单项限制"
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&resource.bytes_base64)
            .map_err(|error| application_error(format!("资源 {path} 编码无效：{error}")))?;
        if bytes.len() as u64 > RESOURCE_MAX_SINGLE_BYTES {
            return Err(application_error(format!(
                "资源 {path} 解码后超过 {} MiB",
                RESOURCE_MAX_SINGLE_BYTES / 1024 / 1024
            )));
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| application_error("资源总大小溢出"))?;
        if total > RESOURCE_MAX_BYTES {
            return Err(application_error(format!(
                "资源总大小不得超过 {} MiB",
                RESOURCE_MAX_BYTES / 1024 / 1024
            )));
        }
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        if resource.checksum.len() != 64
            || !resource
                .checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || checksum != resource.checksum.to_ascii_lowercase()
        {
            return Err(application_error(format!("资源 {path} 校验不符")));
        }
        decoded.insert(path.clone(), bytes);
    }
    Ok(decoded)
}

fn read_limited_file(path: &Path, limit: u64, kind: &str) -> Result<Vec<u8>, ApplicationError> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(application_error(format!("{kind}不是普通文件")));
    }
    if metadata.len() > limit {
        return Err(application_error(format!(
            "{kind}不得超过 {} MiB",
            limit / 1024 / 1024
        )));
    }
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > limit {
        return Err(application_error(format!("{kind}读取过程中超过大小限制")));
    }
    Ok(bytes)
}

pub fn resolve_declared_resource(
    package_root: Option<&Path>,
    requested: &str,
) -> Result<PathBuf, ApplicationError> {
    let root = package_root.ok_or_else(|| application_error("当前程序不属于包，不能读取包资源"))?;
    let manifest = package::discover(root)
        .map_err(package_error)?
        .ok_or_else(|| application_error("未找到包清单"))?;
    let relative = Path::new(requested);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(application_error("资源路径须为包内非空相对路径"));
    }
    let root = fs::canonicalize(&manifest.root).map_err(io_error)?;
    let path = fs::canonicalize(manifest.root.join(relative)).map_err(io_error)?;
    if !path.starts_with(&root) {
        return Err(application_error("资源路径越出包根"));
    }
    let declared = manifest.resources.iter().any(|resource| {
        fs::canonicalize(manifest.root.join(resource))
            .is_ok_and(|resource| path == resource || path.starts_with(resource))
    });
    if !declared {
        return Err(application_error(format!(
            "资源“{requested}”未在【资源】中声明"
        )));
    }
    Ok(path)
}

pub fn normalize_resource_key(requested: &str) -> Result<String, ApplicationError> {
    if requested.contains(['\\', '\0']) {
        return Err(application_error("资源路径须使用正斜杠且不得包含空字符"));
    }
    let path = Path::new(requested);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(application_error("资源路径须为包内非空相对路径"));
    }
    Ok(relative_string(path))
}

fn checksum_file(path: &Path) -> Result<String, ApplicationError> {
    fs::read(path)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(io_error)
}

fn relative_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn package_error(error: package::ManifestError) -> ApplicationError {
    application_error(error.to_string())
}

fn io_error(error: std::io::Error) -> ApplicationError {
    application_error(error.to_string())
}

fn application_error(message: impl Into<String>) -> ApplicationError {
    ApplicationError {
        message: message.into(),
    }
}

fn unsupported_yxb_format(detected: u64) -> ApplicationError {
    application_error(format!(
        "[{YXB_FORMAT_UNSUPPORTED_CODE}] 检测到 YXB 格式 {detected}；当前支持 YXB 格式 {YXB_FORMAT_VERSION}；安全自动迁移：否。请使用支持该制品的言序导出源码，再执行：yanxu compile <源码或项目> -o <新制品.yxb> --release"
    ))
}

fn unsupported_yxb_bytecode(yxb_format: u64, bytecode_format: u64) -> ApplicationError {
    application_error(format!(
        "[{YXB_BYTECODE_UNSUPPORTED_CODE}] 检测到 YXB 格式 {yxb_format}、字节码格式 {bytecode_format}；当前支持 YXB 格式 {YXB_FORMAT_VERSION}、字节码格式 {}；安全自动迁移：否。格式 {bytecode_format} 不含当前运行时要求的完整模块与类型身份，请从原源码或项目重新构建：yanxu compile <源码或项目> -o <新制品.yxb> --release",
        bytecode::BYTECODE_FORMAT_VERSION
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "yanxu-{label}-{}-{sequence}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn compile_test_application(source: &str, permissions: &str) -> (PathBuf, ApplicationArchive) {
        let root = temporary_root("application-security");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join(package::MANIFEST_NAME),
            format!(
                "[包]\n格式=2\n名称='安全应用'\n版本='0.1.0'\n言序='>=1.1.5'\n入口='src/主.yx'\n[权限]\n{permissions}\n[导出]\n默认='src/主.yx'\n"
            ),
        )
        .unwrap();
        fs::write(root.join("src/主.yx"), source).unwrap();
        let archive = compile_application(&root, "release").unwrap();
        (root, archive)
    }

    #[test]
    fn yxb_is_deterministic_and_rejects_tampering() {
        let root = temporary_root("yxb");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("assets")).unwrap();
        fs::write(
            root.join(package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='0.1.0'\n言序='>=1.1.5'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[资源]\n目录=['assets']\n",
        )
        .unwrap();
        fs::write(
            root.join("src/模块.yx"),
            "公 定 答：数 为 42；\n公 定 最大安全整数：数 为 9007199254740991；\n公 类 项目 则 终\n",
        )
        .unwrap();
        fs::write(
            root.join("src/主.yx"),
            "引「模块.yx」为 模块；引「标准:资源」为 资源；\n言 模块.答；言 模块.最大安全整数；言 长度（资源.读取字节（「assets/图.bin」））；言 资源.目录（「assets」）；\n",
        )
        .unwrap();
        fs::write(root.join("assets/图.bin"), [0, 255, 128]).unwrap();
        let first = compile_application(&root, "release").unwrap();
        let second = compile_application(&root, "release").unwrap();
        let bytes = serialize(&first).unwrap();
        assert_eq!(bytes, serialize(&second).unwrap());
        assert!(bytes.starts_with(YXB_COMPRESSED_MAGIC));
        assert!(bytes.len() < serde_json::to_vec(&first).unwrap().len());
        assert_eq!(first.modules.len(), 2);
        assert_eq!(first.resources.len(), 1);
        for (id, module) in &first.modules {
            assert_eq!(module.chunk.module_id, ModuleId::archive(id.clone()));
        }
        let module = &first.modules["app:src/模块.yx"];
        assert_eq!(
            module.chunk.classes[0].type_id.module,
            module.chunk.module_id
        );
        assert!(
            !serde_json::to_string(module)
                .unwrap()
                .contains(&root.display().to_string())
        );
        let decoded = deserialize(&bytes).unwrap();
        assert_eq!(decoded.content_checksum, first.content_checksum);
        let mut legacy = YXB_MAGIC.to_vec();
        legacy.extend(serde_json::to_vec(&first).unwrap());
        assert_eq!(
            deserialize(&legacy).unwrap().content_checksum,
            first.content_checksum
        );
        fs::remove_dir_all(&root).unwrap();
        let mut vm = crate::vm::Vm::silent();
        vm.execute_application(&decoded).unwrap();
        assert_eq!(
            vm.take_output(),
            vec!["42", "9007199254740991", "3", "【图.bin】"]
        );
        let mut tampered = decoded;
        tampered.package.name = "篡改".into();
        assert!(serialize(&tampered).is_err());
    }

    #[test]
    fn yxb_native_modules_reject_tampering_target_paths_and_count_attacks() {
        let (root, mut archive) = compile_test_application("言 1；\n", "图形界面=true");
        let bytes = b"locked native bytes";
        let checksum = format!("{:x}", Sha256::digest(bytes));
        let module = ApplicationNativeModule {
            name: "yanxu-gui".into(),
            abi: 2,
            target: archive.target.clone(),
            file: format!("native/{checksum}/backend.bin"),
            checksum,
            size: bytes.len() as u64,
            package: "yanxu-gui".into(),
            package_version: "0.1.0".into(),
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        archive
            .native_modules
            .insert("yanxu-gui".into(), module.clone());
        archive.content_checksum = archive_checksum(&archive).unwrap();
        assert_eq!(decode_native_modules(&archive).unwrap().len(), 1);
        let serialized = serialize(&archive).unwrap();
        let decoded = deserialize(&serialized).unwrap();
        assert_eq!(decoded.native_modules, archive.native_modules);

        let mut tampered = archive.clone();
        let mut altered_bytes = bytes.to_vec();
        altered_bytes[0] ^= 1;
        tampered
            .native_modules
            .get_mut("yanxu-gui")
            .unwrap()
            .bytes_base64 = base64::engine::general_purpose::STANDARD.encode(altered_bytes);
        tampered.content_checksum = archive_checksum(&tampered).unwrap();
        assert!(
            validate_archive(&tampered)
                .unwrap_err()
                .message
                .contains("摘要")
        );

        let mut wrong_target = archive.clone();
        let mismatched_target = if archive.target == "x86_64-pc-windows-msvc" {
            "aarch64-pc-windows-msvc"
        } else {
            "x86_64-pc-windows-msvc"
        };
        wrong_target
            .native_modules
            .get_mut("yanxu-gui")
            .unwrap()
            .target = mismatched_target.into();
        wrong_target.content_checksum = archive_checksum(&wrong_target).unwrap();
        assert!(
            validate_archive(&wrong_target)
                .unwrap_err()
                .message
                .contains("锁定元数据")
        );

        let mut traversal = archive.clone();
        traversal.native_modules.get_mut("yanxu-gui").unwrap().file = "native/../escape".into();
        traversal.content_checksum = archive_checksum(&traversal).unwrap();
        assert!(
            validate_archive(&traversal)
                .unwrap_err()
                .message
                .contains("路径")
        );

        let mut excessive = archive;
        excessive.native_modules.clear();
        for index in 0..=package::NATIVE_ARTIFACT_MAX_COUNT {
            let name = format!("module-{index}");
            let mut item = module.clone();
            item.name = name.clone();
            item.package = name.clone();
            excessive.native_modules.insert(name, item);
        }
        excessive.content_checksum = archive_checksum(&excessive).unwrap();
        assert!(
            validate_archive(&excessive)
                .unwrap_err()
                .message
                .contains("不得超过")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn yxb_permissions_are_bounded_by_the_host_even_after_rechecksumming() {
        let (root, archive) = compile_test_application(
            "引「标准:环境」为 环境；言 环境.读取（「PATH」）；\n",
            "环境=['PATH']",
        );

        let mut denied = crate::vm::Vm::silent_with_permissions(PermissionSet::sandboxed());
        let error = denied.execute_application(&archive).unwrap_err();
        assert!(error.to_string().contains("未获环境权限"));

        let mut allowed = crate::vm::Vm::silent_with_permissions(
            PermissionSet::sandboxed().allow_environment("PATH"),
        );
        allowed.execute_application(&archive).unwrap();

        let mut tampered = archive;
        tampered.permissions.unrestricted = true;
        tampered.content_checksum = archive_checksum(&tampered).unwrap();
        let mut still_denied = crate::vm::Vm::silent_with_permissions(PermissionSet::sandboxed());
        let error = still_denied.execute_application(&tampered).unwrap_err();
        assert!(error.to_string().contains("未获环境权限"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn yxb_execution_obeys_the_host_byte_value_limit() {
        let (root, archive) =
            compile_test_application("引「标准:字节」为 字节；字节.从文字（「123456」）；\n", "");
        let mut vm = crate::vm::Vm::silent();
        vm.set_host_resource_limits(crate::budget::HostResourceLimits::new(5, 5, 4).unwrap());
        let error = vm.execute_application(&archive).unwrap_err();
        assert!(error.to_string().contains("BYTES_LIMIT"), "{error}");
        assert!(error.to_string().contains("宿主 5 字节上限"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn yxb_rejects_invalid_structure_resources_and_imports() {
        let (root, archive) =
            compile_test_application("引「标准:环境」为 环境；言 1；\n", "环境=[]");

        let mut missing_entry = archive.clone();
        missing_entry.entry_module = "app:缺失.yx".into();
        missing_entry.content_checksum = archive_checksum(&missing_entry).unwrap();
        assert!(
            validate_archive(&missing_entry)
                .unwrap_err()
                .message
                .contains("缺少入口模块")
        );

        let mut invalid_id = archive.clone();
        let module = invalid_id.modules.values().next().unwrap().clone();
        invalid_id.modules.insert("app:../越界.yx".into(), module);
        assert!(
            validate_archive(&invalid_id)
                .unwrap_err()
                .message
                .contains("模块 ID 非法")
        );

        let mut external_import = archive.clone();
        let import = external_import
            .modules
            .values_mut()
            .flat_map(|module| module.chunk.code.iter_mut())
            .find(|instruction| matches!(instruction, Instruction::Import { .. }))
            .unwrap();
        if let Instruction::Import { path, .. } = import {
            *path = "相对模块.yx".into();
        }
        external_import.content_checksum = archive_checksum(&external_import).unwrap();
        assert!(
            validate_archive(&external_import)
                .unwrap_err()
                .message
                .contains("只可导入内部模块或标准库")
        );

        let mut invalid_resource = archive;
        invalid_resource.resources.insert(
            "../越界.bin".into(),
            ApplicationResource {
                path: "../越界.bin".into(),
                bytes_base64: String::new(),
                checksum: format!("{:x}", Sha256::digest([])),
            },
        );
        invalid_resource.content_checksum = archive_checksum(&invalid_resource).unwrap();
        assert!(
            validate_archive(&invalid_resource)
                .unwrap_err()
                .message
                .contains("资源路径")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn yxb_rejects_malformed_duplicate_truncated_and_oversized_inputs() {
        let mut malformed = YXB_MAGIC.to_vec();
        malformed.extend_from_slice(b"{");
        assert!(deserialize(&malformed).is_err());

        let mut duplicate = YXB_MAGIC.to_vec();
        duplicate.extend_from_slice(b"{\"format_version\":1,\"format_version\":1}");
        assert!(
            deserialize(&duplicate)
                .unwrap_err()
                .message
                .contains("重复")
        );

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&vec![b'x'; 4_096]).unwrap();
        let mut bomb = YXB_COMPRESSED_MAGIC.to_vec();
        bomb.extend(encoder.finish().unwrap());
        assert!(
            deserialize_with_limits(&bomb, 1024 * 1024, 1024)
                .unwrap_err()
                .message
                .contains("解压后超过")
        );

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"{}").unwrap();
        let mut truncated = YXB_COMPRESSED_MAGIC.to_vec();
        let mut compressed = encoder.finish().unwrap();
        compressed.truncate(compressed.len().saturating_sub(3));
        truncated.extend(compressed);
        assert!(deserialize(&truncated).is_err());

        let mut invalid_stream = YXB_COMPRESSED_MAGIC.to_vec();
        invalid_stream.extend_from_slice(b"not-a-zlib-stream");
        assert!(deserialize(&invalid_stream).is_err());

        let path = temporary_root("oversized.yxb");
        let file = fs::File::create(&path).unwrap();
        file.set_len(YXB_MAX_FILE_BYTES + 1).unwrap();
        assert!(
            read_archive(&path)
                .unwrap_err()
                .message
                .contains("不得超过")
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn yxb_rejects_excessive_module_and_resource_counts() {
        let (root, archive) = compile_test_application("言 1；\n", "环境=[]");
        let template = archive.modules.values().next().unwrap().clone();
        let mut modules = archive.clone();
        for index in 0..=YXB_MAX_MODULES {
            let id = format!("app:generated/{index}.yx");
            let mut module = template.clone();
            module.id.clone_from(&id);
            modules.modules.insert(id, module);
        }
        assert!(
            validate_archive(&modules)
                .unwrap_err()
                .message
                .contains("模块不得超过")
        );

        let mut resources = archive;
        for index in 0..=RESOURCE_MAX_ENTRIES {
            let path = format!("generated/{index}.bin");
            resources.resources.insert(
                path.clone(),
                ApplicationResource {
                    path,
                    bytes_base64: String::new(),
                    checksum: format!("{:x}", Sha256::digest([])),
                },
            );
        }
        assert!(
            validate_archive(&resources)
                .unwrap_err()
                .message
                .contains("资源不得超过")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_uncompressed_yxb_without_build_identity_remains_compatible() {
        let (root, mut archive) = compile_test_application("言 1；\n", "环境=[]");
        archive.runtime_version.clear();
        archive.build_commit.clear();
        archive.content_checksum = archive_checksum(&archive).unwrap();
        let mut legacy = YXB_MAGIC.to_vec();
        legacy.extend(serde_json::to_vec(&archive).unwrap());
        let decoded = deserialize(&legacy).unwrap();
        assert!(decoded.runtime_version.is_empty());
        assert!(decoded.build_commit.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_bytecode_fixture_reports_exact_rebuild_guidance() {
        let legacy = include_bytes!("../tests/fixtures/yxb/legacy-v1-bytecode.yxb");
        let error = deserialize(legacy).unwrap_err();
        for expected in [
            YXB_BYTECODE_UNSUPPORTED_CODE,
            "检测到 YXB 格式 1、字节码格式 1",
            "当前支持 YXB 格式 1、字节码格式 2",
            "安全自动迁移：否",
            "yanxu compile <源码或项目> -o <新制品.yxb> --release",
        ] {
            assert!(error.message.contains(expected), "{error}");
        }

        let source = include_str!("../tests/fixtures/yxb/legacy-v1-source.yx");
        let (root, current) = compile_test_application(source, "");
        let current_bytes = serialize(&current).unwrap();
        let decoded = deserialize(&current_bytes).unwrap();
        let mut vm = crate::vm::Vm::silent();
        vm.execute_application(&decoded).unwrap();
        assert_eq!(vm.take_output(), ["格式一"]);

        let mut corrupt = current_bytes;
        let last = corrupt.last_mut().unwrap();
        *last ^= 0xff;
        assert!(deserialize(&corrupt).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

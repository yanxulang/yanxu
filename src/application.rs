//! 完整 YXB 应用归档与自包含 VM 制品。

use crate::bytecode::{self, Chunk, Instruction};
use crate::package::{self, Manifest, ResolutionGraph};
use crate::permissions::PermissionSet;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

pub const YXB_FORMAT_VERSION: u32 = 1;
const YXB_MAGIC: &[u8] = b"YANXU-YXB-1\n";
const STANDALONE_MAGIC: &[u8; 16] = b"YANXU-APP-v1\0\0\0\0";
const RESOURCE_MAX_BYTES: u64 = 128 * 1024 * 1024;
const RESOURCE_MAX_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationArchive {
    pub format_version: u32,
    pub bytecode_format: u32,
    pub package: ApplicationPackage,
    pub target: String,
    pub profile: String,
    pub entry_module: String,
    pub modules: BTreeMap<String, ApplicationModule>,
    pub resources: BTreeMap<String, ApplicationResource>,
    pub permissions: PermissionSummary,
    pub lock_checksum: Option<String>,
    pub content_checksum: String,
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
    pub tcp_listen: Vec<String>,
    pub udp_bind: Vec<String>,
    pub environment: Vec<String>,
    pub process: bool,
    pub native_extensions: bool,
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
            tcp_listen: permissions.tcp_listen_hosts().map(str::to_owned).collect(),
            udp_bind: permissions.udp_bind_hosts().map(str::to_owned).collect(),
            environment: permissions
                .environment_variables()
                .map(str::to_owned)
                .collect(),
            process: permissions.process_allowed(),
            native_extensions: permissions.native_extensions_allowed(),
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
        permissions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationError {
    pub message: String,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "YXB 应用有误：{}", self.message)
    }
}

impl std::error::Error for ApplicationError {}

pub fn compile_application(
    input: impl AsRef<Path>,
    profile: &str,
) -> Result<ApplicationArchive, ApplicationError> {
    if !matches!(profile, "debug" | "release") {
        return Err(application_error("构建配置只可为 debug 或 release"));
    }
    let input = input.as_ref();
    let manifest = package::discover(input).map_err(package_error)?;
    let (entry, root, package_root, package_info, permissions, graph, resources, lock_checksum) =
        if let Some(manifest) = manifest {
            validate_runtime_version(&manifest)?;
            let graph = package::ensure_lock_with_dev(&manifest, false).map_err(package_error)?;
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
            (
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
                lock_checksum,
            )
        } else {
            let entry = fs::canonicalize(input).map_err(|error| {
                application_error(format!("不能定位文卷 {}：{error}", input.display()))
            })?;
            let root = entry
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            (
                entry.clone(),
                root,
                None,
                ApplicationPackage {
                    name: entry
                        .file_stem()
                        .and_then(|name| name.to_str())
                        .unwrap_or("应用")
                        .to_owned(),
                    version: "0.0.0".into(),
                },
                PermissionSummary::from_permissions(&PermissionSet::unrestricted(), Path::new(".")),
                None,
                BTreeMap::new(),
                None,
            )
        };
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
        entry_module,
        modules: compiler.modules,
        resources,
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
            bytecode::compile(&statements).map_err(|error| application_error(error.to_string()))?;
        self.rewrite_chunk_imports(&mut chunk, path)?;
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

fn collect_resources(
    manifest: &Manifest,
) -> Result<BTreeMap<String, ApplicationResource>, ApplicationError> {
    let canonical_root = fs::canonicalize(&manifest.root).map_err(io_error)?;
    let mut files = Vec::new();
    for resource in &manifest.resources {
        let path = manifest.root.join(resource);
        collect_resource_files(&manifest.root, &path, &mut files)?;
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
    let mut bytes = YXB_MAGIC.to_vec();
    bytes.extend(
        serde_json::to_vec(archive)
            .map_err(|error| application_error(format!("不能序列化：{error}")))?,
    );
    Ok(bytes)
}

pub fn deserialize(bytes: &[u8]) -> Result<ApplicationArchive, ApplicationError> {
    let payload = bytes
        .strip_prefix(YXB_MAGIC)
        .ok_or_else(|| application_error("缺少 YXB 文件头"))?;
    let archive: ApplicationArchive = serde_json::from_slice(payload)
        .map_err(|error| application_error(format!("归档 JSON 无效：{error}")))?;
    validate_archive(&archive)?;
    Ok(archive)
}

fn validate_archive(archive: &ApplicationArchive) -> Result<(), ApplicationError> {
    if archive.format_version != YXB_FORMAT_VERSION {
        return Err(application_error(format!(
            "不支持 YXB 格式 {}，当前仅支持 {YXB_FORMAT_VERSION}",
            archive.format_version
        )));
    }
    if archive.bytecode_format != bytecode::BYTECODE_FORMAT_VERSION {
        return Err(application_error(format!(
            "YXB 字节码格式 {} 与运行时 {} 不兼容",
            archive.bytecode_format,
            bytecode::BYTECODE_FORMAT_VERSION
        )));
    }
    if !archive.modules.contains_key(&archive.entry_module) {
        return Err(application_error("YXB 缺少入口模块"));
    }
    let actual = archive_checksum(archive)?;
    if archive.content_checksum != actual {
        return Err(application_error(format!(
            "YXB 内容校验不符：记录 {}，实际 {actual}",
            archive.content_checksum
        )));
    }
    Ok(())
}

fn archive_checksum(archive: &ApplicationArchive) -> Result<String, ApplicationError> {
    let mut unsigned = archive.clone();
    unsigned.content_checksum.clear();
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| application_error(format!("不能计算归档校验：{error}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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
    let bytes = fs::read(path.as_ref()).map_err(io_error)?;
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
    if length > payload_end || length > RESOURCE_MAX_BYTES * 4 {
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
    archive
        .resources
        .iter()
        .map(|(path, resource)| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&resource.bytes_base64)
                .map_err(|error| application_error(format!("资源 {path} 编码无效：{error}")))?;
            let checksum = format!("{:x}", Sha256::digest(&bytes));
            if checksum != resource.checksum {
                return Err(application_error(format!("资源 {path} 校验不符")));
            }
            Ok((path.clone(), bytes))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(Rc::new)
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
    let path = Path::new(requested);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yxb_is_deterministic_and_rejects_tampering() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-yxb-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("assets")).unwrap();
        fs::write(
            root.join(package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='0.1.0'\n言序='>=1.1.5'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[资源]\n目录=['assets']\n",
        )
        .unwrap();
        fs::write(root.join("src/模块.yx"), "公 定 答：数 为 42；\n").unwrap();
        fs::write(
            root.join("src/主.yx"),
            "引「模块.yx」为 模块；引「标准:资源」为 资源；\n言 模块.答；言 长度（资源.读取字节（「assets/图.bin」））；言 资源.目录（「assets」）；\n",
        )
        .unwrap();
        fs::write(root.join("assets/图.bin"), [0, 255, 128]).unwrap();
        let first = compile_application(&root, "release").unwrap();
        let second = compile_application(&root, "release").unwrap();
        let bytes = serialize(&first).unwrap();
        assert_eq!(bytes, serialize(&second).unwrap());
        assert_eq!(first.modules.len(), 2);
        assert_eq!(first.resources.len(), 1);
        let decoded = deserialize(&bytes).unwrap();
        assert_eq!(decoded.content_checksum, first.content_checksum);
        fs::remove_dir_all(&root).unwrap();
        let mut vm = crate::vm::Vm::silent();
        vm.execute_application(&decoded).unwrap();
        assert_eq!(vm.take_output(), vec!["42", "3", "【图.bin】"]);
        let mut tampered = decoded;
        tampered.package.name = "篡改".into();
        assert!(serialize(&tampered).is_err());
    }
}

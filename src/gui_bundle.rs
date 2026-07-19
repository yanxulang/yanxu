//! Cross-platform desktop application bundles built from validated YXB archives.
//!
//! A bundle is deliberately self-contained: the executable carries the YXB,
//! while the same archive, resources, native artifacts and license index are
//! also materialized for inspection, signing and platform tooling. All output
//! is assembled in a sibling staging directory and atomically installed.

use crate::application::{self, ApplicationArchive, ApplicationMetadata};
use editpe::constants::IMAGE_SUBSYSTEM_WINDOWS_GUI;
use editpe::types::{VersionU16, VersionU32};
use editpe::{Image as PeImage, VersionInfo, VersionStringTable};
use image::imageops::FilterType;
use image::{DynamicImage, GenericImageView, ImageFormat, Rgba, RgbaImage};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const BUNDLE_FORMAT_VERSION: u32 = 1;
const MAX_RUNTIME_BYTES: u64 = 512 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError {
    pub message: String,
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "应用 Bundle 有误：{}", self.message)
    }
}

impl std::error::Error for BundleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundlePlatform {
    Macos,
    Windows,
    Linux,
}

impl BundlePlatform {
    fn from_target(target: &str) -> Result<Self, BundleError> {
        if target.ends_with("-apple-darwin") {
            Ok(Self::Macos)
        } else if target.contains("-pc-windows-") {
            Ok(Self::Windows)
        } else if target.contains("-unknown-linux-") {
            Ok(Self::Linux)
        } else {
            Err(bundle_error(format!("不支持 Bundle 目标平台 {target}")))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFile {
    pub role: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningPlan {
    pub state: String,
    pub platform: BundlePlatform,
    pub targets: Vec<String>,
    pub required_order: Vec<String>,
    pub mutable_after_signing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub format_version: u32,
    pub bundle_identifier: String,
    pub application_name: String,
    pub application_version: String,
    pub target: String,
    pub profile: String,
    pub runtime_version: String,
    pub build_commit: String,
    pub yxb_checksum: String,
    pub executable: String,
    pub log_directory: String,
    pub dll_search_policy: String,
    pub files: BTreeMap<String, BundleFile>,
    pub licenses: BTreeMap<String, String>,
    pub signing: SigningPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleReport {
    pub output: PathBuf,
    pub manifest: PathBuf,
    pub manifest_sha256: String,
    pub files: usize,
}

pub fn default_output(archive: &ApplicationArchive) -> Result<PathBuf, BundleError> {
    let metadata = graphical_metadata(archive)?;
    let name = safe_file_name(&metadata.name);
    let suffix = match BundlePlatform::from_target(&archive.target)? {
        BundlePlatform::Macos => ".app",
        BundlePlatform::Windows => "-windows",
        BundlePlatform::Linux => ".AppDir",
    };
    Ok(PathBuf::from(format!("{name}{suffix}")))
}

pub fn build_bundle(
    runtime: impl AsRef<Path>,
    archive: &ApplicationArchive,
    output: impl AsRef<Path>,
) -> Result<BundleReport, BundleError> {
    application::validate_archive(archive).map_err(application_error)?;
    let metadata = graphical_metadata(archive)?.clone();
    let platform = BundlePlatform::from_target(&archive.target)?;
    let runtime = runtime.as_ref();
    let runtime_bytes = read_runtime(runtime)?;
    validate_runtime_target(&runtime_bytes, &archive.target, platform)?;

    let output = absolute_output(output.as_ref())?;
    let parent = output
        .parent()
        .ok_or_else(|| bundle_error("Bundle 输出缺少父目录"))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    reject_symlink(parent)?;
    let staging = sibling_path(&output, "staging");
    let backup = sibling_path(&output, "backup");
    if staging.exists() || backup.exists() {
        return Err(bundle_error("Bundle 随机暂存路径发生冲突，请重试"));
    }
    fs::create_dir(&staging).map_err(io_error)?;

    let build_result = (|| {
        let yxb = application::serialize(archive).map_err(application_error)?;
        let resources = application::decode_resources(archive).map_err(application_error)?;
        let native_modules =
            application::decode_native_modules(archive).map_err(application_error)?;
        let icon = load_application_icon(&metadata, &resources)?;
        let mut writer = BundleWriter::new(&staging);
        let layout = match platform {
            BundlePlatform::Macos => build_macos(
                &mut writer,
                runtime,
                archive,
                &metadata,
                &yxb,
                &resources,
                &native_modules,
                &icon,
            )?,
            BundlePlatform::Windows => build_windows(
                &mut writer,
                &runtime_bytes,
                archive,
                &metadata,
                &yxb,
                &resources,
                &native_modules,
                &icon,
            )?,
            BundlePlatform::Linux => build_linux(
                &mut writer,
                runtime,
                archive,
                &metadata,
                &yxb,
                &resources,
                &native_modules,
                &icon,
            )?,
        };
        let notice = license_notice(archive);
        let license_path = layout
            .license_path
            .to_str()
            .ok_or_else(|| bundle_error("Bundle 许可证路径不是 UTF-8"))?;
        writer.write(license_path, notice.as_bytes(), "licenses")?;
        let manifest = BundleManifest {
            format_version: BUNDLE_FORMAT_VERSION,
            bundle_identifier: metadata.identifier.clone(),
            application_name: metadata.name.clone(),
            application_version: metadata.version.clone(),
            target: archive.target.clone(),
            profile: archive.profile.clone(),
            runtime_version: archive.runtime_version.clone(),
            build_commit: archive.build_commit.clone(),
            yxb_checksum: archive.content_checksum.clone(),
            executable: layout.executable.clone(),
            log_directory: platform_log_directory(platform, &metadata.identifier),
            dll_search_policy: if platform == BundlePlatform::Windows {
                "absolute-content-addressed-native-paths; LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32".into()
            } else {
                "absolute-content-addressed-native-paths".into()
            },
            files: writer.files.clone(),
            licenses: archive.licenses.clone(),
            signing: signing_plan(platform, &layout.executable),
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| bundle_error(format!("不能生成 Bundle 清单：{error}")))?;
        writer.write_untracked(&layout.manifest_path, &manifest_bytes)?;
        let manifest_sha256 = sha256(&manifest_bytes);
        verify_bundle(&staging)?;
        Ok::<_, BundleError>((layout.manifest_path, manifest_sha256, writer.files.len()))
    })();

    let (manifest_path, manifest_sha256, files) = match build_result {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };

    if output.exists() {
        reject_symlink(&output)?;
        fs::rename(&output, &backup).map_err(io_error)?;
    }
    if let Err(error) = fs::rename(&staging, &output) {
        if backup.exists() {
            let _ = fs::rename(&backup, &output);
        }
        return Err(io_error(error));
    }
    if backup.exists() {
        fs::remove_dir_all(&backup).map_err(io_error)?;
    }
    let manifest = output.join(manifest_path);
    verify_bundle(&output)?;
    Ok(BundleReport {
        output,
        manifest,
        manifest_sha256,
        files,
    })
}

pub fn verify_bundle(root: impl AsRef<Path>) -> Result<BundleManifest, BundleError> {
    let root = root.as_ref();
    reject_symlink(root)?;
    let candidates = [
        Path::new("Contents/Resources/bundle-manifest.json"),
        Path::new("bundle-manifest.json"),
        Path::new("usr/lib/yanxu/bundle-manifest.json"),
    ];
    let mut manifests = Vec::new();
    for candidate in candidates {
        match fs::symlink_metadata(root.join(candidate)) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(bundle_error("Bundle 清单必须是普通文件且不能是符号链接"));
            }
            Ok(_) => manifests.push(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    if manifests.len() != 1 {
        return Err(bundle_error("Bundle 必须且只能含一份标准清单"));
    }
    let manifest_bytes = fs::read(root.join(manifests[0])).map_err(io_error)?;
    if manifest_bytes.len() > 8 * 1024 * 1024 {
        return Err(bundle_error("Bundle 清单超过大小限制"));
    }
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| bundle_error(format!("Bundle 清单 JSON 无效：{error}")))?;
    if manifest.format_version != BUNDLE_FORMAT_VERSION || manifest.files.len() > 16_384 {
        return Err(bundle_error("Bundle 清单版本或文件数无效"));
    }
    for (relative, expected) in &manifest.files {
        let relative = normalized_relative(relative)?;
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(bundle_error(format!(
                "Bundle 文件不是普通文件：{}",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(io_error)?;
        if bytes.len() as u64 != expected.size || sha256(&bytes) != expected.sha256 {
            return Err(bundle_error(format!(
                "Bundle 文件摘要或大小不符：{}",
                path.display()
            )));
        }
    }
    if !manifest.files.contains_key(&manifest.executable) {
        return Err(bundle_error("Bundle 清单中的可执行文件未进入摘要索引"));
    }
    Ok(manifest)
}

/// If `executable` belongs to a standard Yanxu Bundle, verify the complete
/// outer manifest before any embedded YXB or native module is loaded.
/// Standalone executables outside a Bundle return `Ok(None)`.
pub fn verify_executable_bundle(
    executable: impl AsRef<Path>,
) -> Result<Option<BundleManifest>, BundleError> {
    let executable = executable.as_ref();
    let Some(parent) = executable.parent() else {
        return Ok(None);
    };
    let mut candidates = vec![parent.to_path_buf()];
    if parent.file_name().is_some_and(|name| name == "MacOS")
        && parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "Contents")
        && let Some(root) = parent.parent().and_then(Path::parent)
    {
        candidates.push(root.to_path_buf());
    }
    if parent.file_name().is_some_and(|name| name == "bin")
        && parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "usr")
        && let Some(root) = parent.parent().and_then(Path::parent)
    {
        candidates.push(root.to_path_buf());
    }
    candidates.sort();
    candidates.dedup();
    let roots = candidates
        .into_iter()
        .filter(|root| {
            [
                "Contents/Resources/bundle-manifest.json",
                "bundle-manifest.json",
                "usr/lib/yanxu/bundle-manifest.json",
            ]
            .iter()
            .any(|relative| path_is_present(&root.join(relative)))
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok(None);
    }
    if roots.len() != 1 {
        return Err(bundle_error("可执行文件同时匹配多个 Bundle 根目录"));
    }
    let root = &roots[0];
    let manifest = verify_bundle(root)?;
    let relative = executable
        .strip_prefix(root)
        .map_err(|_| bundle_error("Bundle 可执行文件不在清单根目录内"))?;
    if normalized_relative_path(relative)?
        != normalized_relative_path(Path::new(&manifest.executable))?
    {
        return Err(bundle_error("当前可执行文件与 Bundle 清单入口不一致"));
    }
    Ok(Some(manifest))
}

fn path_is_present(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

struct Layout {
    executable: String,
    manifest_path: PathBuf,
    license_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
fn build_macos(
    writer: &mut BundleWriter<'_>,
    runtime: &Path,
    archive: &ApplicationArchive,
    metadata: &ApplicationMetadata,
    yxb: &[u8],
    resources: &BTreeMap<String, Vec<u8>>,
    native_modules: &BTreeMap<String, application::DecodedNativeModule>,
    icon: &DynamicImage,
) -> Result<Layout, BundleError> {
    let executable_name = executable_name(metadata, false);
    let executable = format!("Contents/MacOS/{executable_name}");
    writer.standalone(runtime, archive, &executable, "runtime")?;
    writer.write("Contents/Resources/application.yxb", yxb, "yxb")?;
    write_resources(writer, "Contents/Resources/resources", resources)?;
    write_native_modules(writer, "Contents/Frameworks", native_modules)?;
    writer.write(
        "Contents/Resources/AppIcon.icns",
        &encode_icns(icon)?,
        "application-icon",
    )?;
    writer.write(
        "Contents/Info.plist",
        macos_info_plist(
            metadata,
            &executable_name,
            archive.permissions.unrestricted || archive.permissions.local_network,
        )
        .as_bytes(),
        "platform-metadata",
    )?;
    Ok(Layout {
        executable,
        manifest_path: "Contents/Resources/bundle-manifest.json".into(),
        license_path: "Contents/Resources/licenses/NOTICE.txt".into(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_windows(
    writer: &mut BundleWriter<'_>,
    runtime_bytes: &[u8],
    archive: &ApplicationArchive,
    metadata: &ApplicationMetadata,
    yxb: &[u8],
    resources: &BTreeMap<String, Vec<u8>>,
    native_modules: &BTreeMap<String, application::DecodedNativeModule>,
    icon: &DynamicImage,
) -> Result<Layout, BundleError> {
    let executable = format!("{}.exe", executable_name(metadata, true));
    let manifest = windows_manifest(metadata);
    let mut image = PeImage::parse(runtime_bytes.to_vec())
        .map_err(|error| bundle_error(format!("Windows PE 运行时无效：{error}")))?;
    let mut pe_resources = image.resource_directory().cloned().unwrap_or_default();
    pe_resources
        .set_main_icon(icon.clone())
        .map_err(|error| bundle_error(format!("不能嵌入 Windows 图标：{error}")))?;
    pe_resources
        .set_manifest(&manifest)
        .map_err(|error| bundle_error(format!("不能嵌入 Windows DPI 清单：{error}")))?;
    pe_resources
        .set_version_info(&windows_version_info(metadata)?)
        .map_err(|error| bundle_error(format!("不能嵌入 Windows 版本信息：{error}")))?;
    image
        .set_resource_directory(pe_resources)
        .map_err(|error| bundle_error(format!("不能重建 Windows 资源目录：{error}")))?;
    image.set_subsystem(IMAGE_SUBSYSTEM_WINDOWS_GUI);
    let prepared_runtime = writer.root.join(".yanxu-prepared-runtime.exe");
    image
        .write_file(&prepared_runtime)
        .map_err(|error| bundle_error(format!("不能写入 Windows 运行时：{error}")))?;
    let standalone_result = writer.standalone(&prepared_runtime, archive, &executable, "runtime");
    let _ = fs::remove_file(&prepared_runtime);
    standalone_result?;
    writer.write("application.yxb", yxb, "yxb")?;
    write_resources(writer, "resources", resources)?;
    write_native_modules(writer, "native", native_modules)?;
    let ico = encode_ico(icon)?;
    writer.write("application.ico", &ico, "application-icon")?;
    // The XML is embedded in the PE; a copy remains inspectable for signing QA.
    writer.write(
        &format!("{executable}.manifest"),
        manifest.as_bytes(),
        "platform-metadata",
    )?;
    Ok(Layout {
        executable,
        manifest_path: "bundle-manifest.json".into(),
        license_path: "licenses/NOTICE.txt".into(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_linux(
    writer: &mut BundleWriter<'_>,
    runtime: &Path,
    archive: &ApplicationArchive,
    metadata: &ApplicationMetadata,
    yxb: &[u8],
    resources: &BTreeMap<String, Vec<u8>>,
    native_modules: &BTreeMap<String, application::DecodedNativeModule>,
    icon: &DynamicImage,
) -> Result<Layout, BundleError> {
    let executable = "AppRun".to_string();
    writer.standalone(runtime, archive, &executable, "runtime")?;
    writer.write("usr/lib/yanxu/application.yxb", yxb, "yxb")?;
    write_resources(writer, "usr/lib/yanxu/resources", resources)?;
    write_native_modules(writer, "usr/lib/yanxu/native", native_modules)?;
    let icon_name = metadata.identifier.to_ascii_lowercase();
    for size in [16_u32, 32, 48, 64, 128, 256, 512] {
        let resized = icon.resize_exact(size, size, FilterType::Lanczos3);
        let png = encode_image(&resized, ImageFormat::Png)?;
        writer.write(
            &format!("usr/share/icons/hicolor/{size}x{size}/apps/{icon_name}.png"),
            &png,
            "application-icon",
        )?;
    }
    let desktop = linux_desktop_entry(metadata, &icon_name);
    let desktop_path = format!("usr/share/applications/{icon_name}.desktop");
    writer.write(&desktop_path, desktop.as_bytes(), "platform-metadata")?;
    writer.write(
        &format!("{icon_name}.desktop"),
        desktop.as_bytes(),
        "platform-metadata",
    )?;
    Ok(Layout {
        executable,
        manifest_path: "usr/lib/yanxu/bundle-manifest.json".into(),
        license_path: "usr/lib/yanxu/licenses/NOTICE.txt".into(),
    })
}

struct BundleWriter<'a> {
    root: &'a Path,
    files: BTreeMap<String, BundleFile>,
}

impl<'a> BundleWriter<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            files: BTreeMap::new(),
        }
    }

    fn write(&mut self, relative: &str, bytes: &[u8], role: &str) -> Result<(), BundleError> {
        self.write_untracked(relative, bytes)?;
        self.record(relative, role)
    }

    fn write_untracked(&self, relative: impl AsRef<Path>, bytes: &[u8]) -> Result<(), BundleError> {
        let relative = normalized_relative_path(relative.as_ref())?;
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }

    fn standalone(
        &mut self,
        runtime: &Path,
        archive: &ApplicationArchive,
        relative: &str,
        role: &str,
    ) -> Result<(), BundleError> {
        let relative_path = normalized_relative(relative)?;
        let path = self.root.join(&relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        application::write_standalone(runtime, archive, &path).map_err(application_error)?;
        self.record(&relative_path, role)
    }

    fn record(&mut self, relative: &str, role: &str) -> Result<(), BundleError> {
        let relative = normalized_relative(relative)?;
        let bytes = fs::read(self.root.join(&relative)).map_err(io_error)?;
        let record = BundleFile {
            role: role.into(),
            sha256: sha256(&bytes),
            size: bytes.len() as u64,
        };
        if self.files.insert(relative.clone(), record).is_some() {
            return Err(bundle_error(format!("Bundle 文件路径重复：{relative}")));
        }
        Ok(())
    }
}

fn write_resources(
    writer: &mut BundleWriter<'_>,
    prefix: &str,
    resources: &BTreeMap<String, Vec<u8>>,
) -> Result<(), BundleError> {
    for (relative, bytes) in resources {
        let relative = normalized_relative(relative)?;
        writer.write(
            &format!("{prefix}/{relative}"),
            bytes,
            "application-resource",
        )?;
    }
    Ok(())
}

fn write_native_modules(
    writer: &mut BundleWriter<'_>,
    prefix: &str,
    modules: &BTreeMap<String, application::DecodedNativeModule>,
) -> Result<(), BundleError> {
    for module in modules.values() {
        let file_name = Path::new(&module.metadata.file)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| bundle_error("原生模块文件名无效"))?;
        writer.write(
            &format!("{prefix}/{}/{file_name}", module.metadata.checksum),
            &module.bytes,
            "native-module",
        )?;
    }
    Ok(())
}

fn graphical_metadata(archive: &ApplicationArchive) -> Result<&ApplicationMetadata, BundleError> {
    let metadata = archive
        .application
        .as_ref()
        .ok_or_else(|| bundle_error("--bundle 要求清单含 [应用] 元数据"))?;
    if metadata.kind != "图形" {
        return Err(bundle_error("--bundle 当前只构建“图形”应用"));
    }
    Ok(metadata)
}

fn read_runtime(path: &Path) -> Result<Vec<u8>, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(bundle_error("运行时必须是普通文件，不能是符号链接"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_RUNTIME_BYTES {
        return Err(bundle_error(format!(
            "运行时为空或超过 {} MiB",
            MAX_RUNTIME_BYTES / 1024 / 1024
        )));
    }
    fs::read(path).map_err(io_error)
}

fn validate_runtime_target(
    bytes: &[u8],
    target: &str,
    platform: BundlePlatform,
) -> Result<(), BundleError> {
    let architecture = target
        .split('-')
        .next()
        .ok_or_else(|| bundle_error("目标三元组缺少架构"))?;
    let valid = match platform {
        BundlePlatform::Windows => pe_machine(bytes).is_some_and(|machine| {
            matches!(
                (architecture, machine),
                ("x86_64", 0x8664) | ("aarch64", 0xaa64)
            )
        }),
        BundlePlatform::Linux => {
            bytes.starts_with(b"\x7fELF")
                && bytes.get(4) == Some(&2)
                && bytes.get(5) == Some(&1)
                && bytes.get(18..20).is_some_and(|machine| {
                    let machine = u16::from_le_bytes([machine[0], machine[1]]);
                    matches!((architecture, machine), ("x86_64", 62) | ("aarch64", 183))
                })
        }
        BundlePlatform::Macos => macho_has_architecture(bytes, architecture),
    };
    if !valid {
        return Err(bundle_error(format!(
            "运行时二进制格式或架构与目标 {target} 不符"
        )));
    }
    Ok(())
}

fn pe_machine(bytes: &[u8]) -> Option<u16> {
    if !bytes.starts_with(b"MZ") || bytes.len() < 0x40 {
        return None;
    }
    let offset = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if bytes.get(offset..offset + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = bytes.get(offset + 4..offset + 6)?;
    Some(u16::from_le_bytes([machine[0], machine[1]]))
}

fn macho_has_architecture(bytes: &[u8], architecture: &str) -> bool {
    let expected = match architecture {
        "x86_64" => 0x0100_0007_u32,
        "aarch64" => 0x0100_000c_u32,
        _ => return false,
    };
    if bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return bytes
            .get(4..8)
            .is_some_and(|value| u32::from_le_bytes(value.try_into().unwrap()) == expected);
    }
    if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        let is_64 = bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf]);
        let count = bytes
            .get(4..8)
            .map(|value| u32::from_be_bytes(value.try_into().unwrap()) as usize)
            .unwrap_or(0);
        if count > 64 {
            return false;
        }
        let entry_size = if is_64 { 32 } else { 20 };
        return (0..count).any(|index| {
            let offset = 8 + index * entry_size;
            bytes
                .get(offset..offset + 4)
                .is_some_and(|value| u32::from_be_bytes(value.try_into().unwrap()) == expected)
        });
    }
    false
}

fn load_application_icon(
    metadata: &ApplicationMetadata,
    resources: &BTreeMap<String, Vec<u8>>,
) -> Result<DynamicImage, BundleError> {
    let image = if let Some(path) = metadata.icon.as_ref() {
        let bytes = resources
            .get(path)
            .ok_or_else(|| bundle_error(format!("应用图标资源不存在：{path}")))?;
        image::load_from_memory(bytes)
            .map_err(|error| bundle_error(format!("不能解码应用图标 {path}：{error}")))?
    } else {
        default_icon()
    };
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return Err(bundle_error("应用图标尺寸无效或超过 8192 像素"));
    }
    Ok(square_icon(&image, 1024))
}

fn square_icon(image: &DynamicImage, size: u32) -> DynamicImage {
    let (width, height) = image.dimensions();
    let scale = size as f32 / width.max(height) as f32;
    let resized = image.resize_exact(
        (width as f32 * scale).round().max(1.0) as u32,
        (height as f32 * scale).round().max(1.0) as u32,
        FilterType::Lanczos3,
    );
    let mut canvas = RgbaImage::from_pixel(size, size, Rgba([0, 0, 0, 0]));
    image::imageops::overlay(
        &mut canvas,
        &resized,
        ((size - resized.width()) / 2) as i64,
        ((size - resized.height()) / 2) as i64,
    );
    DynamicImage::ImageRgba8(canvas)
}

fn default_icon() -> DynamicImage {
    let size = 512_u32;
    let mut image = RgbaImage::new(size, size);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        let blend = ((x + y) as f32 / (size * 2) as f32 * 48.0) as u8;
        *pixel = Rgba([35 + blend / 2, 82 + blend, 190 + blend / 2, 255]);
    }
    for y in 104_u32..408 {
        for x in 0_u32..34 {
            let left = 145 + x + (y.saturating_sub(256) / 4);
            let right = 333 + x - (y.saturating_sub(256) / 4);
            if left < size {
                image.put_pixel(left, y, Rgba([255, 255, 255, 245]));
            }
            if right < size {
                image.put_pixel(right, y, Rgba([255, 255, 255, 245]));
            }
        }
    }
    DynamicImage::ImageRgba8(image)
}

fn encode_image(image: &DynamicImage, format: ImageFormat) -> Result<Vec<u8>, BundleError> {
    let mut cursor = Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, format)
        .map_err(|error| bundle_error(format!("不能编码应用图标：{error}")))?;
    Ok(cursor.into_inner())
}

fn encode_ico(icon: &DynamicImage) -> Result<Vec<u8>, BundleError> {
    encode_image(
        &icon.resize_exact(256, 256, FilterType::Lanczos3),
        ImageFormat::Ico,
    )
}

fn encode_icns(icon: &DynamicImage) -> Result<Vec<u8>, BundleError> {
    let mut chunks = Vec::new();
    for (kind, size) in [
        (b"ic07", 128),
        (b"ic08", 256),
        (b"ic09", 512),
        (b"ic10", 1024),
    ] {
        let png = encode_image(
            &icon.resize_exact(size, size, FilterType::Lanczos3),
            ImageFormat::Png,
        )?;
        chunks.extend_from_slice(kind);
        chunks.extend_from_slice(&((png.len() + 8) as u32).to_be_bytes());
        chunks.extend_from_slice(&png);
    }
    let mut icns = b"icns".to_vec();
    icns.extend_from_slice(&((chunks.len() + 8) as u32).to_be_bytes());
    icns.extend_from_slice(&chunks);
    Ok(icns)
}

fn macos_info_plist(
    metadata: &ApplicationMetadata,
    executable: &str,
    local_network: bool,
) -> String {
    let minimum = metadata.minimum_system_version.as_deref().unwrap_or("11.0");
    let local_network_usage = if local_network {
        "<key>NSLocalNetworkUsageDescription</key><string>用于连接您配置的本地网络服务。</string>\n"
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
<key>CFBundleDisplayName</key><string>{name}</string>
<key>CFBundleExecutable</key><string>{executable}</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleIdentifier</key><string>{identifier}</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>{name}</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleVersion</key><string>{version}</string>
<key>LSMinimumSystemVersion</key><string>{minimum}</string>
<key>NSHighResolutionCapable</key><true/>
{local_network_usage}<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSSupportsAutomaticGraphicsSwitching</key><true/>
</dict></plist>
"#,
        name = xml_escape(&metadata.name),
        executable = xml_escape(executable),
        identifier = xml_escape(&metadata.identifier),
        version = xml_escape(&metadata.version),
        minimum = xml_escape(minimum),
        local_network_usage = local_network_usage,
    )
}

fn windows_manifest(metadata: &ApplicationMetadata) -> String {
    let dpi_aware = if metadata.window.high_dpi {
        "true/pm"
    } else {
        "false"
    };
    let dpi_awareness = if metadata.window.high_dpi {
        "PerMonitorV2,PerMonitor"
    } else {
        "unaware"
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="{identifier}" version="{version}" processorArchitecture="*" type="win32"/>
  <description>{name}</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/></application></compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>
    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">{dpi_aware}</dpiAware>
    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">{dpi_awareness}</dpiAwareness>
    <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
  </windowsSettings></application>
</assembly>
"#,
        identifier = xml_escape(&metadata.identifier),
        version = windows_manifest_version(&metadata.version),
        name = xml_escape(&metadata.name),
    )
}

fn windows_version_info(metadata: &ApplicationMetadata) -> Result<VersionInfo, BundleError> {
    let version = Version::parse(&metadata.version)
        .map_err(|error| bundle_error(format!("Windows 应用版本无效：{error}")))?;
    if version.major > u16::MAX as u64
        || version.minor > u16::MAX as u64
        || version.patch > u16::MAX as u64
    {
        return Err(bundle_error("Windows 版本号分量不得超过 65535"));
    }
    let packed = VersionU32 {
        major: ((version.major as u32) << 16) | version.minor as u32,
        minor: (version.patch as u32) << 16,
    };
    let mut info = VersionInfo::default();
    info.info.file_version = packed;
    info.info.product_version = packed;
    let mut strings = VersionStringTable {
        key: "040904B0".into(),
        ..Default::default()
    };
    strings
        .strings
        .insert("ProductName".into(), metadata.name.clone());
    strings
        .strings
        .insert("FileDescription".into(), metadata.name.clone());
    strings
        .strings
        .insert("FileVersion".into(), metadata.version.clone());
    strings
        .strings
        .insert("ProductVersion".into(), metadata.version.clone());
    strings.strings.insert(
        "CompanyName".into(),
        metadata.company.clone().unwrap_or_default(),
    );
    strings.strings.insert(
        "OriginalFilename".into(),
        format!("{}.exe", executable_name(metadata, true)),
    );
    info.strings.push(strings);
    info.vars.push(VersionU16 {
        major: 0x0409,
        minor: 0x04b0,
    });
    Ok(info)
}

fn windows_manifest_version(version: &str) -> String {
    Version::parse(version).map_or_else(
        |_| "1.0.0.0".into(),
        |version| {
            format!(
                "{}.{}.{}.0",
                version.major.min(u16::MAX as u64),
                version.minor.min(u16::MAX as u64),
                version.patch.min(u16::MAX as u64)
            )
        },
    )
}

fn linux_desktop_entry(metadata: &ApplicationMetadata, icon_name: &str) -> String {
    let comment = metadata.company.as_deref().unwrap_or("言序图形应用");
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName={}\nComment={}\nExec=AppRun %U\nIcon={}\nTerminal=false\nCategories=Utility;\nStartupNotify=true\nStartupWMClass={}\n",
        desktop_escape(&metadata.name),
        desktop_escape(comment),
        desktop_escape(icon_name),
        desktop_escape(&metadata.identifier),
    )
}

fn signing_plan(platform: BundlePlatform, executable: &str) -> SigningPlan {
    match platform {
        BundlePlatform::Macos => SigningPlan {
            state: "unsigned".into(),
            platform,
            targets: vec!["Contents/Frameworks".into(), executable.into(), ".".into()],
            required_order: vec![
                "sign embedded native modules".into(),
                "sign main executable".into(),
                "sign outer .app".into(),
                "notarize and staple outer .app".into(),
            ],
            mutable_after_signing: vec![
                executable.into(),
                "Contents/Frameworks".into(),
                ".".into(),
            ],
        },
        BundlePlatform::Windows => SigningPlan {
            state: "unsigned".into(),
            platform,
            targets: vec![executable.into()],
            required_order: vec![
                "Authenticode-sign executable after final Bundle verification".into(),
            ],
            mutable_after_signing: vec![executable.into()],
        },
        BundlePlatform::Linux => SigningPlan {
            state: "unsigned".into(),
            platform,
            targets: vec![".".into()],
            required_order: vec![
                "create detached distribution signature after packaging AppDir".into(),
            ],
            mutable_after_signing: Vec::new(),
        },
    }
}

fn platform_log_directory(platform: BundlePlatform, identifier: &str) -> String {
    match platform {
        BundlePlatform::Macos => format!("~/Library/Logs/{identifier}"),
        BundlePlatform::Windows => format!("%LOCALAPPDATA%\\{identifier}\\Logs"),
        BundlePlatform::Linux => format!("$XDG_STATE_HOME/{identifier}/logs"),
    }
}

fn license_notice(archive: &ApplicationArchive) -> String {
    let mut notice = format!(
        "{} {}\n\nBundled by Yanxu {}.\nThe Yanxu runtime is distributed under MIT.\n",
        archive.package.name,
        archive.package.version,
        if archive.runtime_version.is_empty() {
            env!("CARGO_PKG_VERSION")
        } else {
            &archive.runtime_version
        }
    );
    if !archive.licenses.is_empty() {
        notice.push_str("\nPackage-declared license expressions:\n");
        for (package, license) in &archive.licenses {
            notice.push_str(&format!("- {package}: {license}\n"));
        }
    }
    notice
}

fn executable_name(metadata: &ApplicationMetadata, ascii_only: bool) -> String {
    let last = metadata
        .identifier
        .rsplit('.')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("yanxu-app");
    if ascii_only {
        let value = last
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>();
        if value.is_empty() {
            "yanxu-app".into()
        } else {
            value
        }
    } else {
        safe_file_name(last)
    }
}

fn safe_file_name(value: &str) -> String {
    let result = value
        .chars()
        .map(|character| {
            if matches!(character, '/' | '\\' | '\0' | ':' | '\r' | '\n') {
                '-'
            } else {
                character
            }
        })
        .collect::<String>();
    let trimmed = result.trim_matches([' ', '.']);
    if trimmed.is_empty() {
        "言序应用".into()
    } else {
        trimmed.chars().take(128).collect()
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn desktop_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "")
}

fn normalized_relative(value: &str) -> Result<String, BundleError> {
    let path = normalized_relative_path(Path::new(value))?;
    Ok(path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn normalized_relative_path(path: &Path) -> Result<PathBuf, BundleError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(bundle_error("Bundle 文件路径必须是非空相对路径"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) if part != "." && part != ".." => normalized.push(part),
            _ => return Err(bundle_error("Bundle 文件路径含非法分量")),
        }
    }
    if normalized.as_os_str().is_empty() || normalized.as_os_str().len() > 4096 {
        return Err(bundle_error("Bundle 文件路径为空或过长"));
    }
    Ok(normalized)
}

fn absolute_output(output: &Path) -> Result<PathBuf, BundleError> {
    if output.as_os_str().is_empty() {
        return Err(bundle_error("Bundle 输出路径为空"));
    }
    if output.is_absolute() {
        Ok(output.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(output))
            .map_err(io_error)
    }
}

fn sibling_path(output: &Path, purpose: &str) -> PathBuf {
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle");
    output.with_file_name(format!(
        ".{name}.yanxu-{purpose}-{}-{sequence}",
        std::process::id()
    ))
}

fn reject_symlink(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() {
        return Err(bundle_error(format!(
            "Bundle 路径不能是符号链接：{}",
            path.display()
        )));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn application_error(error: application::ApplicationError) -> BundleError {
    bundle_error(error.to_string())
}

fn io_error(error: std::io::Error) -> BundleError {
    bundle_error(error.to_string())
}

fn bundle_error(message: impl Into<String>) -> BundleError {
    BundleError {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "yanxu-bundle-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn target_binary_validation_is_architecture_specific() {
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert!(
            validate_runtime_target(&elf, "x86_64-unknown-linux-gnu", BundlePlatform::Linux)
                .is_ok()
        );
        assert!(
            validate_runtime_target(&elf, "aarch64-unknown-linux-gnu", BundlePlatform::Linux)
                .is_err()
        );
    }

    #[test]
    fn paths_cannot_escape_bundle_root() {
        assert!(normalized_relative("resources/icon.png").is_ok());
        assert!(normalized_relative("../escape").is_err());
        assert!(normalized_relative("/absolute").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn executable_bundle_rejects_even_a_broken_manifest_symlink() {
        use std::os::unix::fs::symlink;

        let root = temporary_root("manifest-symlink");
        let executable = root.join("Contents/MacOS/app");
        let manifest = root.join("Contents/Resources/bundle-manifest.json");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&executable, b"runtime").unwrap();
        symlink(root.join("missing-manifest.json"), &manifest).unwrap();
        assert!(verify_executable_bundle(&executable).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn icon_encoders_emit_real_container_headers() {
        let icon = default_icon();
        assert!(encode_ico(&icon).unwrap().starts_with(&[0, 0, 1, 0]));
        assert!(encode_icns(&icon).unwrap().starts_with(b"icns"));
    }

    #[test]
    fn macos_plist_declares_local_network_usage_only_when_granted() {
        let metadata = ApplicationMetadata {
            kind: "图形".into(),
            name: "网络应用".into(),
            identifier: "dev.yanxu.network-test".into(),
            version: "1.0.0".into(),
            icon: None,
            company: None,
            minimum_system_version: None,
            window: application::ApplicationWindowMetadata {
                width: 800,
                height: 600,
                minimum_width: 480,
                minimum_height: 320,
                maximum_width: None,
                maximum_height: None,
                resizable: true,
                high_dpi: true,
            },
        };
        assert!(
            macos_info_plist(&metadata, "网络应用", true)
                .contains("NSLocalNetworkUsageDescription")
        );
        assert!(
            !macos_info_plist(&metadata, "网络应用", false)
                .contains("NSLocalNetworkUsageDescription")
        );
    }

    #[test]
    fn current_platform_bundle_is_source_free_verified_and_tamper_evident() {
        let root = temporary_root("e2e");
        let project = root.join("project");
        let dependency = root.join("native-backend");
        let runtime = std::env::current_exe().unwrap();
        let native_path = dependency.join("native/backend.bin");
        fs::create_dir_all(dependency.join("src")).unwrap();
        fs::create_dir_all(native_path.parent().unwrap()).unwrap();
        fs::write(&native_path, b"test-only locked native artifact bytes").unwrap();
        let native_bytes = fs::read(&native_path).unwrap();
        let target = crate::package::current_target();
        let os = if target.ends_with("-apple-darwin") {
            "macos"
        } else if target.contains("-pc-windows-") {
            "windows"
        } else {
            "linux"
        };
        let architecture = if target.starts_with("aarch64-") {
            "arm64"
        } else {
            "x64"
        };
        fs::write(
            dependency.join(crate::package::MANIFEST_NAME),
            format!(
                "[包]\n格式=2\n名称='bundle-native-test'\n版本='0.1.0'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[原生]\nABI=2\n[原生.{os}.{architecture}]\n文件='native/backend.bin'\n校验和='{}'\n大小={}\n",
                sha256(&native_bytes),
                native_bytes.len()
            ),
        )
        .unwrap();
        fs::write(dependency.join("src/主.yx"), "公 定 值：数 为 1；\n").unwrap();
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(
            project.join(crate::package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='Bundle测试'\n版本='1.2.3'\n许可='MIT'\n入口='src/主.yx'\n[依赖]\n后端={包='bundle-native-test',路径='../native-backend',版='^0.1'}\n[应用]\n类型='图形'\n名称='Bundle测试'\n标识='dev.yanxu.bundle-test'\n版本='1.2.3'\n[权限]\n图形界面=true\n原生扩展=true\n",
        )
        .unwrap();
        fs::write(project.join("src/主.yx"), "言 「Bundle 已运行」；\n").unwrap();
        let archive = application::compile_application(&project, "release").unwrap();
        assert_eq!(archive.native_modules.len(), 1);
        let output = root.join(default_output(&archive).unwrap().file_name().unwrap());
        let report = build_bundle(&runtime, &archive, &output).unwrap();
        let manifest = verify_bundle(&report.output).unwrap();
        assert!(
            verify_executable_bundle(output.join(&manifest.executable))
                .unwrap()
                .is_some()
        );
        assert_eq!(manifest.yxb_checksum, archive.content_checksum);
        assert_eq!(manifest.licenses["Bundle测试@1.2.3"], "MIT");
        assert!(
            manifest
                .files
                .values()
                .any(|file| file.role == "native-module")
        );

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&dependency).unwrap();
        let embedded = application::read_embedded(output.join(&manifest.executable))
            .unwrap()
            .unwrap();
        let mut vm = crate::vm::Vm::silent();
        vm.execute_application(&embedded).unwrap();
        assert_eq!(vm.take_output(), vec!["Bundle 已运行"]);

        let yxb_path = output.join("Contents/Resources/application.yxb");
        let yxb_path = if yxb_path.exists() {
            yxb_path
        } else {
            let candidate = output.join("application.yxb");
            if candidate.exists() {
                candidate
            } else {
                output.join("usr/lib/yanxu/application.yxb")
            }
        };
        let original_yxb = fs::read(&yxb_path).unwrap();
        fs::write(&yxb_path, b"tampered").unwrap();
        assert!(verify_bundle(&output).is_err());
        fs::write(&yxb_path, original_yxb).unwrap();
        verify_bundle(&output).unwrap();

        let native_relative = manifest
            .files
            .iter()
            .find_map(|(path, file)| (file.role == "native-module").then_some(path))
            .unwrap();
        fs::write(output.join(native_relative), b"tampered native module").unwrap();
        assert!(verify_bundle(&output).is_err());
        assert!(verify_executable_bundle(output.join(&manifest.executable)).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}

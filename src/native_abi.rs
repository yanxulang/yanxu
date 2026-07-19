//! 稳定原生扩展 ABI v1 与安全动态库装载器。
//!
//! ABI 只跨越固定宽度整数、指针、长度和 UTF-8 JSON，不把 Rust 布局暴露给
//! 第三方。动态库只有在平台、SHA-256 与`原生扩展`权限全部通过后才会打开。

use crate::package::NativeArtifact;
use crate::permissions::PermissionSet;
use serde_json::Value;
#[cfg(not(target_family = "wasm"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_family = "wasm"))]
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fmt;
#[cfg(not(target_family = "wasm"))]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(not(target_family = "wasm"))]
use std::path::PathBuf;
use std::ptr;
#[cfg(not(target_family = "wasm"))]
use std::rc::Rc;

pub const NATIVE_ABI_VERSION: u32 = 1;
pub const NATIVE_OK: i32 = 0;
pub const NATIVE_OUTPUT_JSON: u32 = 1;
pub const NATIVE_OUTPUT_RESOURCE: u32 = 2;
const NATIVE_MAX_DESCRIPTORS: usize = 1_024;
const NATIVE_MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_MAX_LIBRARY_BYTES: u64 = 256 * 1024 * 1024;
const NATIVE_MAX_NAME_BYTES: usize = 1_024;
const NATIVE_MAX_ERROR_CODE_BYTES: usize = 256;
const NATIVE_MAX_ERROR_MESSAGE_BYTES: usize = 64 * 1024;

/// Opens an already verified library with a dependency search policy that does
/// not consult the process current directory on Windows. The DLL's own private
/// content-addressed directory and trusted system/application locations remain
/// available for legitimate dependencies.
#[cfg(all(not(target_family = "wasm"), target_os = "windows"))]
pub(crate) unsafe fn load_dynamic_library_safely(
    path: &Path,
) -> Result<libloading::Library, libloading::Error> {
    use libloading::os::windows::{
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    };
    let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    // SAFETY: The caller owns the verified path and accepts module initialization.
    unsafe { libloading::os::windows::Library::load_with_flags(path, flags) }
        .map(libloading::Library::from)
}

#[cfg(all(not(target_family = "wasm"), not(target_os = "windows")))]
pub(crate) unsafe fn load_dynamic_library_safely(
    path: &Path,
) -> Result<libloading::Library, libloading::Error> {
    // SAFETY: The caller owns the verified path and accepts module initialization.
    unsafe { libloading::Library::new(path) }
}

pub type NativeFreeBytes = unsafe extern "C" fn(*mut u8, usize);
pub type NativeDropResource = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeErrorV1 {
    pub code: *const u8,
    pub code_length: usize,
    pub message: *const u8,
    pub message_length: usize,
}

impl Default for YanxuNativeErrorV1 {
    fn default() -> Self {
        Self {
            code: ptr::null(),
            code_length: 0,
            message: ptr::null(),
            message_length: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeOutputV1 {
    pub kind: u32,
    pub json: *mut u8,
    pub json_length: usize,
    pub resource: *mut c_void,
    pub resource_type: *const u8,
    pub resource_type_length: usize,
    pub drop_resource: Option<NativeDropResource>,
}

impl Default for YanxuNativeOutputV1 {
    fn default() -> Self {
        Self {
            kind: 0,
            json: ptr::null_mut(),
            json_length: 0,
            resource: ptr::null_mut(),
            resource_type: ptr::null(),
            resource_type_length: 0,
            drop_resource: None,
        }
    }
}

pub type NativeInvokeCallback = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut YanxuNativeOutputV1,
    *mut YanxuNativeErrorV1,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeCallbackV1 {
    pub abi_version: u32,
    pub struct_size: usize,
    pub context: *mut c_void,
    pub invoke: Option<NativeInvokeCallback>,
}

pub type NativeFunctionPointer = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const YanxuNativeCallbackV1,
    *mut YanxuNativeOutputV1,
    *mut YanxuNativeErrorV1,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeFunctionV1 {
    pub name: *const u8,
    pub name_length: usize,
    pub context: *mut c_void,
    pub call: Option<NativeFunctionPointer>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeConstantV1 {
    pub name: *const u8,
    pub name_length: usize,
    pub value_json: *const u8,
    pub value_json_length: usize,
}

#[repr(C)]
pub struct YanxuNativeModuleV1 {
    pub abi_version: u32,
    pub struct_size: usize,
    pub name: *const u8,
    pub name_length: usize,
    pub functions: *const YanxuNativeFunctionV1,
    pub function_count: usize,
    pub constants: *const YanxuNativeConstantV1,
    pub constant_count: usize,
    pub resource_types: *const *const u8,
    pub resource_type_lengths: *const usize,
    pub resource_type_count: usize,
    pub free_bytes: Option<NativeFreeBytes>,
    pub capabilities: u64,
}

#[repr(C)]
#[cfg(not(target_family = "wasm"))]
struct YanxuNativeModuleHeaderV1 {
    abi_version: u32,
    struct_size: usize,
}

#[cfg(not(target_family = "wasm"))]
type NativeModuleEntry = unsafe extern "C" fn() -> *const YanxuNativeModuleV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "原生扩展有误：[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for NativeError {}

#[cfg(not(target_family = "wasm"))]
struct NativeInner {
    library: Option<libloading::Library>,
    _staged: StagedLibrary,
    name: String,
    capabilities: u64,
    functions: BTreeMap<String, YanxuNativeFunctionV1>,
    constants: BTreeMap<String, Value>,
    resource_types: Vec<String>,
    free_bytes: NativeFreeBytes,
}

#[cfg(not(target_family = "wasm"))]
impl Drop for NativeInner {
    fn drop(&mut self) {
        // Windows 不允许删除仍被装载的 DLL；须先显式卸载，再由 StagedLibrary 清理。
        drop(self.library.take());
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) struct StagedLibrary {
    pub(crate) root: PathBuf,
    pub(crate) path: PathBuf,
    file: Option<std::fs::File>,
}

#[cfg(not(target_family = "wasm"))]
impl Drop for StagedLibrary {
    fn drop(&mut self) {
        drop(self.file.take());
        make_staged_tree_writable(&self.root);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn stage_verified_library(
    bytes: &[u8],
    checksum: &str,
) -> Result<StagedLibrary, NativeError> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| native_error("NATIVE_IO", format!("不能创建安全随机暂存名：{error}")))?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("yanxu-native-v1-{}-{nonce}", std::process::id()));
    create_private_staging_directory(&root)
        .map_err(|error| native_error("NATIVE_IO", format!("不能创建原生暂存目录：{error}")))?;
    let content_directory = root.join(checksum);
    let path = content_directory.join(format!("extension{}", std::env::consts::DLL_SUFFIX));
    let mut staged = StagedLibrary {
        root,
        path,
        file: None,
    };
    let result = (|| {
        create_private_staging_directory(&content_directory)
            .map_err(|error| native_error("NATIVE_IO", format!("不能创建内容寻址目录：{error}")))?;
        let mut output = create_private_staging_file(&staged.path)
            .map_err(|error| native_error("NATIVE_IO", format!("不能暂存原生制品：{error}")))?;
        output
            .write_all(bytes)
            .and_then(|_| output.sync_all())
            .map_err(|error| native_error("NATIVE_IO", format!("不能写入原生暂存制品：{error}")))?;
        let mut held = hold_staged_file(output)?;
        let metadata = held
            .metadata()
            .map_err(|error| native_error("NATIVE_IO", format!("不能检查原生暂存制品：{error}")))?;
        if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
            return Err(native_error(
                "NATIVE_IO",
                "原生暂存制品不是预期大小的普通文件",
            ));
        }
        let mut staged_bytes = Vec::with_capacity(bytes.len());
        held.read_to_end(&mut staged_bytes)
            .map_err(|error| native_error("NATIVE_IO", format!("不能复核原生暂存制品：{error}")))?;
        let staged_checksum = format!("{:x}", Sha256::digest(staged_bytes));
        if staged_checksum != checksum {
            return Err(native_error(
                "NATIVE_CHECKSUM",
                format!("原生暂存制品摘要改变：预期 {checksum}，实际 {staged_checksum}"),
            ));
        }
        held.seek(SeekFrom::Start(0))
            .map_err(|error| native_error("NATIVE_IO", format!("不能复位原生暂存制品：{error}")))?;
        staged.file = Some(held);
        set_staged_read_only(&content_directory, true)?;
        set_staged_read_only(&staged.root, true)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(staged),
        Err(error) => {
            drop(staged);
            Err(error)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn create_private_staging_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    std::fs::DirBuilder::new().create(path)
}

#[cfg(not(target_family = "wasm"))]
fn create_private_staging_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(target_family = "wasm"))]
fn set_open_staged_file_read_only(file: &std::fs::File) -> Result<(), NativeError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| native_error("NATIVE_IO", error.to_string()))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o400);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .map_err(|error| native_error("NATIVE_IO", format!("不能锁定原生暂存制品：{error}")))
}

#[cfg(not(target_family = "wasm"))]
fn hold_staged_file(file: std::fs::File) -> Result<std::fs::File, NativeError> {
    set_open_staged_file_read_only(&file)?;
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let intermediate = reopen_staged_file(&file, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        drop(file);
        let mut held = reopen_staged_file(&intermediate, FILE_SHARE_READ)?;
        drop(intermediate);
        held.seek(SeekFrom::Start(0))
            .map_err(|error| native_error("NATIVE_IO", format!("不能复位原生暂存制品：{error}")))?;
        Ok(held)
    }
    #[cfg(not(windows))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| native_error("NATIVE_IO", format!("不能复位原生暂存制品：{error}")))?;
        Ok(file)
    }
}

#[cfg(windows)]
fn reopen_staged_file(file: &std::fs::File, share_mode: u32) -> Result<std::fs::File, NativeError> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, ReOpenFile};

    // SAFETY: `file` owns a live Windows file handle. A successful result is a new owned handle.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle() as HANDLE,
            FILE_GENERIC_READ,
            share_mode,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(native_error(
            "NATIVE_IO",
            format!(
                "不能重新打开原生暂存制品：{}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: ReOpenFile returned a distinct live handle whose ownership transfers to File.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

#[cfg(not(target_family = "wasm"))]
fn absolute_native_artifact_path(path: &Path) -> Result<PathBuf, NativeError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|error| native_error("NATIVE_IO", format!("不能定位当前目录：{error}")))
}

#[cfg(not(target_family = "wasm"))]
fn open_native_artifact(path: &Path) -> Result<crate::package::ResolvedPackageFile, NativeError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut roots = crate::package::TrustedPackageRoots::new();
    roots
        .insert(parent)
        .map_err(|error| native_error("NATIVE_IO", format!("不能建立原生制品目录句柄：{error}")))?;
    roots
        .resolve_existing_file(path, crate::package::PackagePathPurpose::ManifestReference)
        .map_err(|error| native_error("NATIVE_IO", format!("不能安全打开原生制品：{error}")))?
        .ok_or_else(|| native_error("NATIVE_IO", "原生制品不属于已打开的父目录"))
}

#[cfg(not(target_family = "wasm"))]
fn set_staged_read_only(
    path: &Path,
    #[cfg_attr(not(unix), allow(unused_variables))] directory: bool,
) -> Result<(), NativeError> {
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| native_error("NATIVE_IO", error.to_string()))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(if directory { 0o500 } else { 0o400 });
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| native_error("NATIVE_IO", format!("不能锁定原生暂存制品：{error}")))
}

#[cfg(not(target_family = "wasm"))]
fn make_staged_tree_writable(path: &Path) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    let mut permissions = metadata.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(if metadata.is_dir() { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    {
        // Windows 没有 PermissionsExt；清除只读属性是删除已卸载 DLL 暂存树的
        // 唯一标准库接口，不会在 Unix 上扩大写权限。
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
    }
    let _ = std::fs::set_permissions(path, permissions);
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_staged_tree_writable(&entry.path());
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Clone)]
pub struct NativeExtension {
    inner: Rc<NativeInner>,
}

#[cfg(target_family = "wasm")]
#[derive(Clone)]
pub struct NativeExtension;

pub enum NativeCallResult {
    Json(Value),
    Resource(NativeResource),
}

pub struct NativeResource {
    #[cfg(not(target_family = "wasm"))]
    _owner: Rc<NativeInner>,
    raw: *mut c_void,
    drop_resource: NativeDropResource,
    type_name: String,
}

#[cfg(not(target_family = "wasm"))]
struct NativeOutputGuard {
    output: YanxuNativeOutputV1,
    free_bytes: NativeFreeBytes,
    owns_json: bool,
}

#[cfg(not(target_family = "wasm"))]
impl NativeOutputGuard {
    fn new(output: YanxuNativeOutputV1, free_bytes: NativeFreeBytes) -> Self {
        let owns_json =
            output.kind == NATIVE_OUTPUT_JSON || !output.json.is_null() || output.json_length != 0;
        Self {
            output,
            free_bytes,
            owns_json,
        }
    }

    fn take_resource(&mut self) -> Option<(*mut c_void, NativeDropResource)> {
        let drop_resource = self.output.drop_resource?;
        if self.output.resource.is_null() {
            return None;
        }
        let raw = std::mem::replace(&mut self.output.resource, ptr::null_mut());
        self.output.drop_resource = None;
        Some((raw, drop_resource))
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for NativeOutputGuard {
    fn drop(&mut self) {
        if !self.output.resource.is_null()
            && let Some(drop_resource) = self.output.drop_resource
        {
            // SAFETY: The extension paired this owned resource with its destructor.
            unsafe { drop_resource(self.output.resource) };
            self.output.resource = ptr::null_mut();
        }
        if self.owns_json {
            // SAFETY: ABI v1 transfers JSON output ownership to the host even for malformed
            // pointer/length pairs; the module-provided release function must accept them.
            unsafe { (self.free_bytes)(self.output.json, self.output.json_length) };
            self.owns_json = false;
            self.output.json = ptr::null_mut();
            self.output.json_length = 0;
        }
    }
}

impl NativeResource {
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    pub fn as_raw(&self) -> *mut c_void {
        self.raw
    }
}

impl Drop for NativeResource {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: The extension returned this resource together with its destructor, and
            // NativeResource owns it exactly once while retaining the library owner.
            unsafe { (self.drop_resource)(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

impl NativeExtension {
    #[cfg(not(target_family = "wasm"))]
    pub fn load_verified(
        path: impl AsRef<Path>,
        artifact: &NativeArtifact,
        permissions: &PermissionSet,
        expected_name: &str,
    ) -> Result<Self, NativeError> {
        let requested_path = path.as_ref();
        if artifact.abi != NATIVE_ABI_VERSION {
            return Err(native_error(
                "NATIVE_ABI",
                format!("锁定制品 ABI {} 不是 ABI v1", artifact.abi),
            ));
        }
        let path = absolute_native_artifact_path(requested_path)?;
        permissions
            .check_native_extension(&path)
            .map_err(|error| native_error("NATIVE_PERMISSION", error.to_string()))?;
        if artifact.target != crate::package::current_target() {
            return Err(native_error(
                "NATIVE_TARGET",
                format!(
                    "制品目标 {} 与当前目标 {} 不符",
                    artifact.target,
                    crate::package::current_target()
                ),
            ));
        }
        if artifact.checksum.len() != 64
            || !artifact
                .checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(native_error(
                "NATIVE_CHECKSUM",
                "原生制品须声明 64 位十六进制 SHA-256",
            ));
        }
        if artifact.size > NATIVE_MAX_LIBRARY_BYTES {
            return Err(native_error("NATIVE_LIMIT", "原生制品不得超过 256 MiB"));
        }
        let source = open_native_artifact(&path)?;
        let opened_metadata = source.metadata().map_err(|error| {
            native_error("NATIVE_IO", format!("不能检查已打开的原生制品：{error}"))
        })?;
        if !opened_metadata.is_file() {
            return Err(native_error("NATIVE_IO", "已打开的原生制品不是普通文件"));
        }
        if opened_metadata.len() != artifact.size
            || opened_metadata.len() > NATIVE_MAX_LIBRARY_BYTES
        {
            return Err(native_error(
                "NATIVE_LIMIT",
                format!(
                    "原生制品大小不符或超限：锁定 {}，实际 {}",
                    artifact.size,
                    opened_metadata.len()
                ),
            ));
        }
        let bytes = crate::package::read_resolved_regular_file_snapshot(
            source,
            NATIVE_MAX_LIBRARY_BYTES,
            "原生制品",
        )
        .map_err(|error| native_error("NATIVE_IO", error.to_string()))?;
        if bytes.len() as u64 > NATIVE_MAX_LIBRARY_BYTES {
            return Err(native_error(
                "NATIVE_LIMIT",
                "原生制品读取过程中超过 256 MiB",
            ));
        }
        if bytes.len() as u64 != artifact.size {
            return Err(native_error(
                "NATIVE_LIMIT",
                format!(
                    "原生制品大小不符或超限：锁定 {}，实际 {}",
                    artifact.size,
                    bytes.len()
                ),
            ));
        }
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        let expected_checksum = artifact.checksum.to_ascii_lowercase();
        if checksum != expected_checksum {
            return Err(native_error(
                "NATIVE_CHECKSUM",
                format!("制品校验不符：声明 {}，实际 {checksum}", artifact.checksum),
            ));
        }
        let staged = stage_verified_library(&bytes, &checksum)?;
        // SAFETY: The private staged path contains the already-verified bytes, is read-only, and
        // remains owned until after the library is unloaded. Descriptor fields are validated.
        unsafe { Self::load(staged, expected_name) }
    }

    #[cfg(target_family = "wasm")]
    pub fn load_verified(
        _path: impl AsRef<Path>,
        _artifact: &NativeArtifact,
        _permissions: &PermissionSet,
        _expected_name: &str,
    ) -> Result<Self, NativeError> {
        Err(native_error(
            "NATIVE_UNSUPPORTED",
            "WASI 禁止装载宿主动态库",
        ))
    }

    #[cfg(not(target_family = "wasm"))]
    unsafe fn load(staged: StagedLibrary, expected_name: &str) -> Result<Self, NativeError> {
        let path = staged.path.as_path();
        // SAFETY: The caller has completed security gates; Library remains owned by NativeInner.
        let library = unsafe { load_dynamic_library_safely(path) }.map_err(|error| {
            native_error(
                "NATIVE_LOAD",
                format!("不能打开 {}：{error}", path.display()),
            )
        })?;
        // SAFETY: We request the ABI-mandated symbol and copy only the function pointer.
        let entry: NativeModuleEntry = unsafe {
            *library
                .get::<NativeModuleEntry>(b"yanxu_native_module_v1\0")
                .map_err(|error| {
                    native_error("NATIVE_SYMBOL", format!("缺少 ABI v1 入口：{error}"))
                })?
        };
        // SAFETY: ABI entry contract promises a stable descriptor; validation checks every field.
        let descriptor = unsafe { entry() };
        let validated = unsafe { validate_descriptor(descriptor, expected_name) }?;
        Ok(Self {
            inner: Rc::new(NativeInner {
                library: Some(library),
                _staged: staged,
                name: validated.name,
                capabilities: validated.capabilities,
                functions: validated.functions,
                constants: validated.constants,
                resource_types: validated.resource_types,
                free_bytes: validated.free_bytes,
            }),
        })
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    #[cfg(target_family = "wasm")]
    pub fn name(&self) -> &str {
        ""
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn capabilities(&self) -> u64 {
        self.inner.capabilities
    }

    #[cfg(target_family = "wasm")]
    pub fn capabilities(&self) -> u64 {
        0
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn constants(&self) -> &BTreeMap<String, Value> {
        &self.inner.constants
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn resource_types(&self) -> &[String] {
        &self.inner.resource_types
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn call_json(
        &self,
        name: &str,
        arguments: &Value,
    ) -> Result<NativeCallResult, NativeError> {
        self.call_json_with_callback(name, arguments, None)
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn call_json_with_callback(
        &self,
        name: &str,
        arguments: &Value,
        callback: Option<&YanxuNativeCallbackV1>,
    ) -> Result<NativeCallResult, NativeError> {
        let function = self.inner.functions.get(name).ok_or_else(|| {
            native_error(
                "NATIVE_FUNCTION",
                format!("模块“{}”未注册函数“{name}”", self.inner.name),
            )
        })?;
        let arguments = serde_json::to_vec(arguments)
            .map_err(|error| native_error("NATIVE_JSON", error.to_string()))?;
        if arguments.len() > NATIVE_MAX_JSON_BYTES {
            return Err(native_error("NATIVE_LIMIT", "原生调用参数超过 16 MiB"));
        }
        let mut output = YanxuNativeOutputV1::default();
        let mut native_failure = YanxuNativeErrorV1::default();
        let call = function
            .call
            .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "原生函数指针为空"))?;
        // SAFETY: Descriptor was validated, argument bytes remain alive for the call, and output
        // structs are writable for the duration of the call.
        let status = unsafe {
            call(
                function.context,
                arguments.as_ptr(),
                arguments.len(),
                callback.map_or(ptr::null(), |callback| callback),
                &mut output,
                &mut native_failure,
            )
        };
        let mut output = NativeOutputGuard::new(output, self.inner.free_bytes);
        if status != NATIVE_OK {
            return Err(unsafe { copy_native_error(native_failure) });
        }
        match output.output.kind {
            NATIVE_OUTPUT_JSON => {
                let bytes = unsafe {
                    copy_required_bytes(
                        output.output.json,
                        output.output.json_length,
                        "原生 JSON 输出",
                    )
                }?;
                if bytes.len() > NATIVE_MAX_JSON_BYTES {
                    return Err(native_error("NATIVE_LIMIT", "原生调用结果超过 16 MiB"));
                }
                serde_json::from_slice(&bytes)
                    .map(NativeCallResult::Json)
                    .map_err(|error| native_error("NATIVE_JSON", error.to_string()))
            }
            NATIVE_OUTPUT_RESOURCE => {
                if output.output.resource.is_null() || output.output.drop_resource.is_none() {
                    return Err(native_error(
                        "NATIVE_RESOURCE",
                        "不透明资源缺少指针或析构函数",
                    ));
                }
                let type_name = unsafe {
                    copy_utf8(
                        output.output.resource_type,
                        output.output.resource_type_length,
                        "资源类型",
                    )
                }?;
                if !self.inner.resource_types.contains(&type_name) {
                    return Err(native_error(
                        "NATIVE_RESOURCE",
                        format!("未注册资源类型“{type_name}”"),
                    ));
                }
                let (raw, drop_resource) = output
                    .take_resource()
                    .ok_or_else(|| native_error("NATIVE_RESOURCE", "不透明资源所有权无效"))?;
                Ok(NativeCallResult::Resource(NativeResource {
                    _owner: self.inner.clone(),
                    raw,
                    drop_resource,
                    type_name,
                }))
            }
            kind => Err(native_error(
                "NATIVE_OUTPUT",
                format!("未知原生输出种类 {kind}"),
            )),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
struct ValidatedDescriptor {
    name: String,
    capabilities: u64,
    functions: BTreeMap<String, YanxuNativeFunctionV1>,
    constants: BTreeMap<String, Value>,
    resource_types: Vec<String>,
    free_bytes: NativeFreeBytes,
}

#[cfg(not(target_family = "wasm"))]
unsafe fn validate_descriptor(
    descriptor: *const YanxuNativeModuleV1,
    expected_name: &str,
) -> Result<ValidatedDescriptor, NativeError> {
    let header = unsafe { descriptor.cast::<YanxuNativeModuleHeaderV1>().as_ref() }
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "模块描述符为空"))?;
    if header.abi_version != NATIVE_ABI_VERSION {
        return Err(native_error(
            "NATIVE_ABI",
            format!(
                "扩展 ABI {} 与运行时 ABI {NATIVE_ABI_VERSION} 不兼容",
                header.abi_version
            ),
        ));
    }
    let expected_struct_size = std::mem::size_of::<YanxuNativeModuleV1>();
    if header.struct_size != expected_struct_size {
        return Err(native_error(
            "NATIVE_ABI",
            format!(
                "模块描述符尺寸 {} 与 ABI v1 要求的 {expected_struct_size} 不符",
                header.struct_size
            ),
        ));
    }
    let descriptor = unsafe { descriptor.as_ref() }
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "模块描述符为空"))?;
    let name = unsafe { copy_utf8(descriptor.name, descriptor.name_length, "模块名") }?;
    if name != expected_name {
        return Err(native_error(
            "NATIVE_NAME",
            format!("扩展声明“{name}”，清单要求“{expected_name}”"),
        ));
    }
    let free_bytes = descriptor
        .free_bytes
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "模块未提供输出释放函数"))?;
    ensure_descriptor_count(descriptor.function_count, "函数")?;
    ensure_descriptor_count(descriptor.constant_count, "常量")?;
    ensure_descriptor_count(descriptor.resource_type_count, "资源类型")?;
    let functions = unsafe {
        pointer_slice(
            descriptor.functions,
            descriptor.function_count,
            "函数描述符",
        )
    }?;
    let constants = unsafe {
        pointer_slice(
            descriptor.constants,
            descriptor.constant_count,
            "常量描述符",
        )
    }?;
    let resource_types = unsafe {
        pointer_slice(
            descriptor.resource_types,
            descriptor.resource_type_count,
            "资源类型指针",
        )
    }?;
    let resource_lengths = unsafe {
        pointer_slice(
            descriptor.resource_type_lengths,
            descriptor.resource_type_count,
            "资源类型长度",
        )
    }?;
    let mut function_map = BTreeMap::new();
    for function in functions {
        let name = unsafe { copy_utf8(function.name, function.name_length, "函数名") }?;
        if function.call.is_none() || function_map.insert(name.clone(), *function).is_some() {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("函数“{name}”为空或重复"),
            ));
        }
    }
    let mut constant_map = BTreeMap::new();
    for constant in constants {
        let name = unsafe { copy_utf8(constant.name, constant.name_length, "常量名") }?;
        let value = unsafe {
            copy_required_bytes(constant.value_json, constant.value_json_length, "常量 JSON")
        }?;
        let value = serde_json::from_slice(&value)
            .map_err(|error| native_error("NATIVE_JSON", format!("常量“{name}”：{error}")))?;
        if constant_map.insert(name.clone(), value).is_some() {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("常量“{name}”重复"),
            ));
        }
    }
    let mut resource_names = Vec::new();
    for (pointer, length) in resource_types.iter().zip(resource_lengths) {
        let name = unsafe { copy_utf8(*pointer, *length, "资源类型") }?;
        if resource_names.contains(&name) {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("资源类型“{name}”重复"),
            ));
        }
        resource_names.push(name);
    }
    Ok(ValidatedDescriptor {
        name,
        capabilities: descriptor.capabilities,
        functions: function_map,
        constants: constant_map,
        resource_types: resource_names,
        free_bytes,
    })
}

#[cfg(not(target_family = "wasm"))]
fn ensure_descriptor_count(count: usize, kind: &str) -> Result<(), NativeError> {
    if count > NATIVE_MAX_DESCRIPTORS {
        Err(native_error(
            "NATIVE_LIMIT",
            format!("{kind}描述符不得超过 {NATIVE_MAX_DESCRIPTORS}"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
unsafe fn pointer_slice<'a, T>(
    pointer: *const T,
    length: usize,
    kind: &str,
) -> Result<&'a [T], NativeError> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(native_error(
            "NATIVE_DESCRIPTOR",
            format!("{kind}指针为空但长度非零"),
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_required_bytes(
    pointer: *const u8,
    length: usize,
    kind: &str,
) -> Result<Vec<u8>, NativeError> {
    if length > NATIVE_MAX_JSON_BYTES {
        return Err(native_error("NATIVE_LIMIT", format!("{kind}超过 16 MiB")));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(native_error(
            "NATIVE_DESCRIPTOR",
            format!("{kind}指针为空但长度非零"),
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_utf8(pointer: *const u8, length: usize, kind: &str) -> Result<String, NativeError> {
    unsafe { copy_utf8_bounded(pointer, length, kind, NATIVE_MAX_NAME_BYTES) }
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_utf8_bounded(
    pointer: *const u8,
    length: usize,
    kind: &str,
    limit: usize,
) -> Result<String, NativeError> {
    if length > limit {
        return Err(native_error(
            "NATIVE_LIMIT",
            format!("{kind}不得超过 {limit} 字节"),
        ));
    }
    let bytes = unsafe { copy_required_bytes(pointer, length, kind) }?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| native_error("NATIVE_UTF8", format!("{kind}不是 UTF-8：{error}")))?;
    if text.is_empty() {
        return Err(native_error("NATIVE_DESCRIPTOR", format!("{kind}不可为空")));
    }
    Ok(text.into())
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_native_error(error: YanxuNativeErrorV1) -> NativeError {
    let code = unsafe {
        copy_utf8_bounded(
            error.code,
            error.code_length,
            "错误码",
            NATIVE_MAX_ERROR_CODE_BYTES,
        )
    }
    .unwrap_or_else(|_| "NATIVE_FAILURE".into());
    let message = unsafe {
        copy_utf8_bounded(
            error.message,
            error.message_length,
            "错误消息",
            NATIVE_MAX_ERROR_MESSAGE_BYTES,
        )
    }
    .unwrap_or_else(|_| "原生函数返回失败但未提供有效错误".into());
    native_error(code, message)
}

pub(crate) fn native_error(code: impl Into<String>, message: impl Into<String>) -> NativeError {
    NativeError {
        code: code.into(),
        message: message.into(),
    }
}

pub fn capabilities() -> Value {
    serde_json::json!({
        "abi_version": NATIVE_ABI_VERSION,
        "value_transport": "utf8-json",
        "functions": true,
        "constants": true,
        "opaque_resources": true,
        "structured_errors": true,
        "callbacks": true,
        "wasi_dynamic_loading": false,
        "max_descriptors": NATIVE_MAX_DESCRIPTORS,
        "max_json_bytes": NATIVE_MAX_JSON_BYTES,
        "max_library_bytes": NATIVE_MAX_LIBRARY_BYTES,
        "max_name_bytes": NATIVE_MAX_NAME_BYTES,
        "max_error_code_bytes": NATIVE_MAX_ERROR_CODE_BYTES,
        "max_error_message_bytes": NATIVE_MAX_ERROR_MESSAGE_BYTES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_family = "wasm"))]
    static FREE_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    #[cfg(not(target_family = "wasm"))]
    static DROP_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[cfg(not(target_family = "wasm"))]
    unsafe extern "C" fn release(bytes: *mut u8, length: usize) {
        if !bytes.is_null() {
            drop(unsafe { Vec::from_raw_parts(bytes, length, length) });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    unsafe extern "C" fn counted_release(bytes: *mut u8, _length: usize) {
        FREE_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !bytes.is_null() {
            drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(bytes, 3)) });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    unsafe extern "C" fn counted_drop(resource: *mut c_void) {
        DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !resource.is_null() {
            drop(unsafe { Box::from_raw(resource.cast::<u8>()) });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn descriptor_validation_rejects_wrong_abi_and_accepts_static_values() {
        static NAME: &[u8] = b"example";
        static CONSTANT_NAME: &[u8] = b"answer";
        static CONSTANT_VALUE: &[u8] = b"42";
        let constant = YanxuNativeConstantV1 {
            name: CONSTANT_NAME.as_ptr(),
            name_length: CONSTANT_NAME.len(),
            value_json: CONSTANT_VALUE.as_ptr(),
            value_json_length: CONSTANT_VALUE.len(),
        };
        let mut descriptor = YanxuNativeModuleV1 {
            abi_version: NATIVE_ABI_VERSION,
            struct_size: std::mem::size_of::<YanxuNativeModuleV1>(),
            name: NAME.as_ptr(),
            name_length: NAME.len(),
            functions: ptr::null(),
            function_count: 0,
            constants: &constant,
            constant_count: 1,
            resource_types: ptr::null(),
            resource_type_lengths: ptr::null(),
            resource_type_count: 0,
            free_bytes: Some(release),
            capabilities: 7,
        };
        let validated = unsafe { validate_descriptor(&descriptor, "example") }.unwrap();
        assert_eq!(validated.constants["answer"], 42);
        assert_eq!(validated.capabilities, 7);
        descriptor.abi_version = 2;
        let error = match unsafe { validate_descriptor(&descriptor, "example") } {
            Ok(_) => panic!("ABI 2 should be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, "NATIVE_ABI");
        descriptor.abi_version = NATIVE_ABI_VERSION;
        descriptor.struct_size = std::mem::size_of::<YanxuNativeModuleV1>() - 1;
        let undersized = match unsafe { validate_descriptor(&descriptor, "example") } {
            Ok(_) => panic!("undersized ABI v1 descriptor should be rejected"),
            Err(error) => error,
        };
        assert_eq!(undersized.code, "NATIVE_ABI");
        descriptor.struct_size = std::mem::size_of::<YanxuNativeModuleV1>() + 1;
        let oversized = match unsafe { validate_descriptor(&descriptor, "example") } {
            Ok(_) => panic!("oversized ABI v1 descriptor should be rejected"),
            Err(error) => error,
        };
        assert_eq!(oversized.code, "NATIVE_ABI");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn descriptor_validation_rejects_duplicate_and_oversized_names() {
        static NAME: &[u8] = b"example";
        static CONSTANT_NAME: &[u8] = b"duplicate";
        static CONSTANT_VALUE: &[u8] = b"42";
        let constants = [
            YanxuNativeConstantV1 {
                name: CONSTANT_NAME.as_ptr(),
                name_length: CONSTANT_NAME.len(),
                value_json: CONSTANT_VALUE.as_ptr(),
                value_json_length: CONSTANT_VALUE.len(),
            },
            YanxuNativeConstantV1 {
                name: CONSTANT_NAME.as_ptr(),
                name_length: CONSTANT_NAME.len(),
                value_json: CONSTANT_VALUE.as_ptr(),
                value_json_length: CONSTANT_VALUE.len(),
            },
        ];
        let mut descriptor = YanxuNativeModuleV1 {
            abi_version: NATIVE_ABI_VERSION,
            struct_size: std::mem::size_of::<YanxuNativeModuleV1>(),
            name: NAME.as_ptr(),
            name_length: NAME.len(),
            functions: ptr::null(),
            function_count: 0,
            constants: constants.as_ptr(),
            constant_count: constants.len(),
            resource_types: ptr::null(),
            resource_type_lengths: ptr::null(),
            resource_type_count: 0,
            free_bytes: Some(release),
            capabilities: 0,
        };
        let duplicate = match unsafe { validate_descriptor(&descriptor, "example") } {
            Ok(_) => panic!("duplicate constants should be rejected"),
            Err(error) => error,
        };
        assert_eq!(duplicate.code, "NATIVE_DESCRIPTOR");
        descriptor.name_length = NATIVE_MAX_NAME_BYTES + 1;
        let oversized = match unsafe { validate_descriptor(&descriptor, "example") } {
            Ok(_) => panic!("oversized module name should be rejected"),
            Err(error) => error,
        };
        assert_eq!(oversized.code, "NATIVE_LIMIT");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn malformed_outputs_are_released_on_every_error_path() {
        FREE_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        DROP_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

        let bytes = vec![b'{', b'x', b'}'].into_boxed_slice();
        let pointer = Box::into_raw(bytes).cast::<u8>();
        {
            let guard = NativeOutputGuard::new(
                YanxuNativeOutputV1 {
                    kind: NATIVE_OUTPUT_JSON,
                    json: pointer,
                    json_length: 3,
                    ..YanxuNativeOutputV1::default()
                },
                counted_release,
            );
            let copied = unsafe {
                copy_required_bytes(guard.output.json, guard.output.json_length, "测试 JSON")
            }
            .unwrap();
            assert!(serde_json::from_slice::<Value>(&copied).is_err());
        }
        assert_eq!(FREE_COUNT.load(std::sync::atomic::Ordering::SeqCst), 1);

        {
            let guard = NativeOutputGuard::new(
                YanxuNativeOutputV1 {
                    kind: NATIVE_OUTPUT_JSON,
                    json: ptr::null_mut(),
                    json_length: 1,
                    ..YanxuNativeOutputV1::default()
                },
                counted_release,
            );
            assert!(
                unsafe {
                    copy_required_bytes(guard.output.json, guard.output.json_length, "测试 JSON")
                }
                .is_err()
            );
        }
        assert_eq!(FREE_COUNT.load(std::sync::atomic::Ordering::SeqCst), 2);

        let resource = Box::into_raw(Box::new(7_u8)).cast();
        {
            let _guard = NativeOutputGuard::new(
                YanxuNativeOutputV1 {
                    kind: 999,
                    resource,
                    drop_resource: Some(counted_drop),
                    ..YanxuNativeOutputV1::default()
                },
                counted_release,
            );
        }
        assert_eq!(DROP_COUNT.load(std::sync::atomic::Ordering::SeqCst), 1);

        DROP_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let resource = Box::into_raw(Box::new(9_u8)).cast();
        let (transferred, destructor) = {
            let mut guard = NativeOutputGuard::new(
                YanxuNativeOutputV1 {
                    kind: NATIVE_OUTPUT_RESOURCE,
                    resource,
                    drop_resource: Some(counted_drop),
                    ..YanxuNativeOutputV1::default()
                },
                counted_release,
            );
            guard.take_resource().unwrap()
        };
        assert_eq!(DROP_COUNT.load(std::sync::atomic::Ordering::SeqCst), 0);
        unsafe { destructor(transferred) };
        assert_eq!(DROP_COUNT.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn verified_bytes_are_loaded_from_a_private_content_addressed_copy() {
        let bytes = b"verified-library-bytes";
        let checksum = format!("{:x}", Sha256::digest(bytes));
        let staged = stage_verified_library(bytes, &checksum).unwrap();
        let root = staged.root.clone();
        assert_eq!(std::fs::read(&staged.path).unwrap(), bytes);
        assert_eq!(
            staged
                .path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            checksum
        );
        assert!(
            std::fs::metadata(&staged.path)
                .unwrap()
                .permissions()
                .readonly()
        );
        #[cfg(windows)]
        assert!(
            std::fs::remove_file(&staged.path).is_err(),
            "held staging handle must deny replacement"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                std::fs::metadata(&staged.root)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
            assert_eq!(
                std::fs::metadata(staged.path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
            assert_eq!(
                std::fs::metadata(&staged.path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        drop(staged);
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_entries_start_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "yanxu-native-v1-mode-{}-{unique}",
            std::process::id()
        ));
        create_private_staging_directory(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let content = root.join("content");
        create_private_staging_directory(&content).unwrap();
        assert_eq!(
            std::fs::metadata(&content).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let artifact = content.join("extension.bin");
        drop(create_private_staging_file(&artifact).unwrap());
        assert_eq!(
            std::fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_document_is_stable() {
        assert_eq!(capabilities()["abi_version"], 1);
        assert_eq!(capabilities()["callbacks"], true);
    }
}

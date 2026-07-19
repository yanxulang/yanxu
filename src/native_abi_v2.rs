//! 言序原生扩展 ABI v2。
//!
//! v2 与 v1 使用不同入口符号。参数在调用期间借用，返回值由模块的
//! `free_value` 递归释放；异步投递会在返回前深拷贝为 [`HostValue`]。

use crate::host_events::{HostValue, HostValueLimits};
use crate::native_abi::{NativeError, native_error};
#[cfg(not(target_family = "wasm"))]
use crate::native_abi::{
    StagedLibrary, absolute_native_artifact_path, load_dynamic_library_safely,
    open_native_artifact, stage_verified_library,
};
use crate::package::{NATIVE_ARTIFACT_MAX_BYTES, NativeArtifact, ResolvedPackageFile};
use crate::permissions::PermissionSet;
#[cfg(not(target_family = "wasm"))]
use goblin::Object;
#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
use goblin::mach::{Mach, MachO, SingleArch};
#[cfg(not(target_family = "wasm"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_family = "wasm"))]
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::path::Path;
use std::ptr;
#[cfg(not(target_family = "wasm"))]
use std::rc::Rc;

pub const NATIVE_ABI_VERSION_V2: u32 = 2;
pub const NATIVE_V2_OK: i32 = 0;
pub const NATIVE_V2_ERROR: i32 = 1;
pub const NATIVE_V2_NULL: u32 = 0;
pub const NATIVE_V2_BOOL: u32 = 1;
pub const NATIVE_V2_INTEGER: u32 = 2;
pub const NATIVE_V2_NUMBER: u32 = 3;
pub const NATIVE_V2_STRING: u32 = 4;
pub const NATIVE_V2_BYTES: u32 = 5;
pub const NATIVE_V2_ARRAY: u32 = 6;
pub const NATIVE_V2_MAP: u32 = 7;
pub const NATIVE_V2_RESOURCE: u32 = 8;
pub const NATIVE_V2_CALLBACK: u32 = 9;
pub const NATIVE_V2_ERROR_VALUE: u32 = 10;
pub const NATIVE_V2_FLAG_TRUE: u32 = 1;
pub const NATIVE_V2_FLAG_RESOURCE_HANDLE: u32 = 1 << 1;
const NATIVE_V2_MAX_DESCRIPTORS: usize = 2_048;
#[cfg(not(target_family = "wasm"))]
const NATIVE_V2_MAX_NAME_BYTES: usize = 1_024;
#[cfg(not(target_family = "wasm"))]
const NATIVE_V2_MAX_ERROR_CODE_BYTES: usize = 256;
#[cfg(not(target_family = "wasm"))]
const NATIVE_V2_MAX_ERROR_MESSAGE_BYTES: usize = 64 * 1024;
#[cfg(not(target_family = "wasm"))]
const NATIVE_V2_MAX_DYNAMIC_DEPENDENCIES: usize = 256;
#[cfg(not(target_family = "wasm"))]
const NATIVE_V2_MAX_DYNAMIC_DEPENDENCY_BYTES: usize = 1_024;
#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
const NATIVE_V2_MAX_MACH_ARCHITECTURES: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub union YanxuValueDataV2 {
    pub integer: i64,
    pub number: f64,
    pub bytes: *const u8,
    pub items: *const YanxuValueV2,
    pub resource: *mut YanxuNativeResourceV2,
    pub handle: u64,
}

impl Default for YanxuValueDataV2 {
    fn default() -> Self {
        Self { handle: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct YanxuValueV2 {
    pub kind: u32,
    pub flags: u32,
    pub length: u64,
    pub data: YanxuValueDataV2,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct YanxuNativeErrorV2 {
    pub code: *const u8,
    pub code_length: usize,
    pub message: *const u8,
    pub message_length: usize,
}

pub type NativeDropResourceV2 = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeResourceV2 {
    pub struct_size: usize,
    pub resource: *mut c_void,
    pub type_name: *const u8,
    pub type_name_length: usize,
    pub parent: u64,
    pub drop_resource: Option<NativeDropResourceV2>,
}

pub type NativeCallbackRetainV2 = unsafe extern "C" fn(*mut c_void, u64) -> i32;
pub type NativeCallbackReleaseV2 = unsafe extern "C" fn(*mut c_void, u64) -> i32;
pub type NativeCallbackPostV2 = unsafe extern "C" fn(
    *mut c_void,
    u64,
    *const YanxuValueV2,
    usize,
    *mut YanxuNativeErrorV2,
) -> i32;
pub type NativeHostWakeV2 = unsafe extern "C" fn(*mut c_void);
pub type NativeHostPumpV2 =
    unsafe extern "C" fn(*mut c_void, usize, *mut YanxuNativeErrorV2) -> i32;
pub type NativeHostPermissionV2 = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
pub type NativeHostResourceGetV2 = unsafe extern "C" fn(*mut c_void, u64, *mut *mut c_void) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeHostV2 {
    pub abi_version: u32,
    pub struct_size: usize,
    pub context: *mut c_void,
    pub callback_retain: Option<NativeCallbackRetainV2>,
    pub callback_release: Option<NativeCallbackReleaseV2>,
    pub callback_post: Option<NativeCallbackPostV2>,
    pub wake: Option<NativeHostWakeV2>,
    pub pump: Option<NativeHostPumpV2>,
    pub has_permission: Option<NativeHostPermissionV2>,
    pub resource_get: Option<NativeHostResourceGetV2>,
    pub event_loop_id: u64,
    pub owner_thread_token: u64,
}

pub type NativeFunctionPointerV2 = unsafe extern "C" fn(
    *mut c_void,
    *const YanxuValueV2,
    usize,
    *const YanxuNativeHostV2,
    *mut YanxuValueV2,
    *mut YanxuNativeErrorV2,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeFunctionV2 {
    pub name: *const u8,
    pub name_length: usize,
    pub context: *mut c_void,
    pub call: Option<NativeFunctionPointerV2>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct YanxuNativeConstantV2 {
    pub name: *const u8,
    pub name_length: usize,
    pub value: *const YanxuValueV2,
}

pub type NativeFreeValueV2 = unsafe extern "C" fn(*mut YanxuValueV2);

#[repr(C)]
pub struct YanxuNativeModuleV2 {
    pub abi_version: u32,
    pub struct_size: usize,
    pub name: *const u8,
    pub name_length: usize,
    pub functions: *const YanxuNativeFunctionV2,
    pub function_count: usize,
    pub constants: *const YanxuNativeConstantV2,
    pub constant_count: usize,
    pub resource_types: *const *const u8,
    pub resource_type_lengths: *const usize,
    pub resource_type_count: usize,
    pub free_value: Option<NativeFreeValueV2>,
    pub capabilities: u64,
}

#[cfg(not(target_family = "wasm"))]
type NativeModuleEntryV2 = unsafe extern "C" fn() -> *const YanxuNativeModuleV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLoadAuthority {
    NativeExtension,
    OfficialGui,
}

#[cfg(not(target_family = "wasm"))]
struct NativeInnerV2 {
    library: Option<libloading::Library>,
    _staged: StagedLibrary,
    name: String,
    capabilities: u64,
    functions: BTreeMap<String, YanxuNativeFunctionV2>,
    constants: BTreeMap<String, HostValue>,
    resource_types: Vec<String>,
    free_value: NativeFreeValueV2,
}

#[cfg(not(target_family = "wasm"))]
impl Drop for NativeInnerV2 {
    fn drop(&mut self) {
        drop(self.library.take());
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Clone)]
pub struct NativeExtensionV2 {
    inner: Rc<NativeInnerV2>,
}

#[cfg(target_family = "wasm")]
#[derive(Clone)]
pub struct NativeExtensionV2;

pub enum NativeV2CallResult {
    Value(HostValue),
    Resource(NativeResourceV2),
}

pub struct NativeResourceV2 {
    #[cfg(not(target_family = "wasm"))]
    _owner: Rc<NativeInnerV2>,
    raw: *mut c_void,
    drop_resource: Option<NativeDropResourceV2>,
    type_name: String,
    parent: u64,
}

impl NativeResourceV2 {
    pub fn as_raw(&self) -> *mut c_void {
        self.raw
    }

    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    pub fn parent(&self) -> Option<u64> {
        (self.parent != 0).then_some(self.parent)
    }

    pub fn close(&mut self) {
        if !self.raw.is_null() {
            if let Some(drop_resource) = self.drop_resource.take() {
                // SAFETY: The module transferred this resource and destructor together.
                unsafe { drop_resource(self.raw) };
            }
            self.raw = ptr::null_mut();
        }
    }
}

impl Drop for NativeResourceV2 {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(not(target_family = "wasm"))]
struct OutputGuardV2 {
    value: YanxuValueV2,
    free_value: NativeFreeValueV2,
}

#[cfg(not(target_family = "wasm"))]
impl Drop for OutputGuardV2 {
    fn drop(&mut self) {
        // SAFETY: ABI v2 requires the module release function to accept every initialized
        // output, including null and partially populated error outputs.
        unsafe { (self.free_value)(&mut self.value) };
        self.value = YanxuValueV2::default();
    }
}

#[cfg(not(target_family = "wasm"))]
fn native_format_error(message: impl Into<String>) -> NativeError {
    native_error("NATIVE_FORMAT", message)
}

#[cfg(not(target_family = "wasm"))]
fn native_dependency_error(message: impl Into<String>) -> NativeError {
    native_error("NATIVE_DEPENDENCY", message)
}

#[cfg(not(target_family = "wasm"))]
fn validate_dependency_count(count: usize) -> Result<(), NativeError> {
    if count > NATIVE_V2_MAX_DYNAMIC_DEPENDENCIES {
        return Err(native_dependency_error(format!(
            "原生制品声明 {count} 个动态依赖，超过上限 {NATIVE_V2_MAX_DYNAMIC_DEPENDENCIES}"
        )));
    }
    Ok(())
}

#[cfg(all(
    not(target_family = "wasm"),
    any(test, target_os = "linux", target_os = "windows")
))]
fn validate_bare_dependency_name(name: &str, format: &str) -> Result<(), NativeError> {
    if name.is_empty()
        || name.len() > NATIVE_V2_MAX_DYNAMIC_DEPENDENCY_BYTES
        || !name.is_ascii()
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(native_dependency_error(format!(
            "{format} 动态依赖“{name}”不是受约束的系统库基名"
        )));
    }
    Ok(())
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "linux")))]
fn validate_elf_dependencies(
    libraries: &[&str],
    rpaths: &[&str],
    runpaths: &[&str],
) -> Result<(), NativeError> {
    validate_dependency_count(libraries.len())?;
    if !rpaths.is_empty() || !runpaths.is_empty() {
        return Err(native_dependency_error(
            "ELF 原生制品不得声明 DT_RPATH 或 DT_RUNPATH",
        ));
    }
    for library in libraries {
        validate_bare_dependency_name(library, "ELF DT_NEEDED")?;
    }
    Ok(())
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
fn validate_mach_dependencies(libraries: &[&str], rpaths: &[&str]) -> Result<(), NativeError> {
    validate_dependency_count(libraries.len())?;
    if !rpaths.is_empty() {
        return Err(native_dependency_error("Mach-O 原生制品不得声明 LC_RPATH"));
    }
    for library in libraries {
        let trusted = library.starts_with("/usr/lib/")
            || library.starts_with("/System/Library/Frameworks/")
            || library.starts_with("/System/Library/PrivateFrameworks/");
        if !trusted
            || !library.is_ascii()
            || library.len() > NATIVE_V2_MAX_DYNAMIC_DEPENDENCY_BYTES
            || !library.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+')
            })
            || library.contains("//")
            || library.contains("/./")
            || library.contains("/../")
            || library.ends_with("/.")
            || library.ends_with("/..")
        {
            return Err(native_dependency_error(format!(
                "Mach-O 动态依赖“{library}”不属于固定系统库路径"
            )));
        }
    }
    Ok(())
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "windows")))]
fn validate_pe_dependencies(
    libraries: &[&str],
    has_delay_imports: bool,
) -> Result<(), NativeError> {
    validate_dependency_count(libraries.len())?;
    if has_delay_imports {
        return Err(native_dependency_error(
            "PE 原生制品不得声明未纳入静态闭包验证的延迟导入表",
        ));
    }
    for library in libraries {
        validate_bare_dependency_name(library, "PE 导入")?;
    }
    Ok(())
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "linux")))]
fn expected_elf_machine() -> Result<u16, NativeError> {
    if cfg!(target_arch = "x86_64") {
        Ok(goblin::elf::header::EM_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(goblin::elf::header::EM_AARCH64)
    } else {
        Err(native_format_error(format!(
            "当前架构 {} 尚无 ABI v2 ELF 装载策略",
            std::env::consts::ARCH
        )))
    }
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
fn expected_mach_cpu() -> Result<u32, NativeError> {
    if cfg!(target_arch = "x86_64") {
        Ok(goblin::mach::cputype::CPU_TYPE_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(goblin::mach::cputype::CPU_TYPE_ARM64)
    } else {
        Err(native_format_error(format!(
            "当前架构 {} 尚无 ABI v2 Mach-O 装载策略",
            std::env::consts::ARCH
        )))
    }
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "windows")))]
fn expected_pe_machine() -> Result<u16, NativeError> {
    if cfg!(target_arch = "x86_64") {
        Ok(goblin::pe::header::COFF_MACHINE_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(goblin::pe::header::COFF_MACHINE_ARM64)
    } else {
        Err(native_format_error(format!(
            "当前架构 {} 尚无 ABI v2 PE 装载策略",
            std::env::consts::ARCH
        )))
    }
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "linux")))]
fn validate_elf_library(elf: &goblin::elf::Elf<'_>) -> Result<(), NativeError> {
    if !elf.is_lib || elf.interpreter.is_some() || !elf.is_64 || !elf.little_endian {
        return Err(native_format_error(
            "ABI v2 ELF 制品必须是当前平台的 64 位小端、无解释器共享库",
        ));
    }
    let expected = expected_elf_machine()?;
    if elf.header.e_machine != expected {
        return Err(native_format_error(format!(
            "ELF 机器类型 {} 与当前架构要求 {expected} 不符",
            elf.header.e_machine
        )));
    }
    let dynamic = elf
        .dynamic
        .as_ref()
        .ok_or_else(|| native_format_error("ABI v2 ELF 共享库缺少 PT_DYNAMIC 元数据"))?;
    const DT_AUXILIARY: u64 = 0x7fff_fffd;
    const DT_FILTER: u64 = 0x7fff_ffff;
    let forbidden = dynamic.dyns.iter().find(|entry| {
        matches!(
            entry.d_tag,
            goblin::elf::dynamic::DT_RPATH
                | goblin::elf::dynamic::DT_RUNPATH
                | goblin::elf::dynamic::DT_AUDIT
                | goblin::elf::dynamic::DT_DEPAUDIT
                | DT_AUXILIARY
                | DT_FILTER
        )
    });
    if let Some(entry) = forbidden {
        return Err(native_dependency_error(format!(
            "ELF 原生制品含禁止的动态装载标签 0x{:x}",
            entry.d_tag
        )));
    }
    let needed_count = dynamic
        .dyns
        .iter()
        .filter(|entry| entry.d_tag == goblin::elf::dynamic::DT_NEEDED)
        .count();
    if needed_count != elf.libraries.len() {
        return Err(native_format_error(
            "ELF DT_NEEDED 表含不能完整解析的依赖名称",
        ));
    }
    validate_elf_dependencies(&elf.libraries, &elf.rpaths, &elf.runpaths)
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
fn validate_mach_library(mach: &MachO<'_>) -> Result<(), NativeError> {
    if !matches!(
        mach.header.filetype,
        goblin::mach::header::MH_DYLIB | goblin::mach::header::MH_BUNDLE
    ) {
        return Err(native_format_error(
            "ABI v2 Mach-O 制品必须是动态库或 bundle",
        ));
    }
    if !mach.is_64 || !mach.little_endian {
        return Err(native_format_error(
            "ABI v2 Mach-O 制品必须是当前平台的 64 位小端映像",
        ));
    }
    let expected = expected_mach_cpu()?;
    if mach.header.cputype != expected {
        return Err(native_format_error(format!(
            "Mach-O CPU 类型 {} 与当前架构要求 {expected} 不符",
            mach.header.cputype
        )));
    }
    if mach.load_commands.iter().any(|command| {
        matches!(
            command.command,
            goblin::mach::load_command::CommandVariant::DyldEnvironment(_)
                | goblin::mach::load_command::CommandVariant::LoadDylinker(_)
                | goblin::mach::load_command::CommandVariant::IdDylinker(_)
                | goblin::mach::load_command::CommandVariant::LoadFvmlib(_)
                | goblin::mach::load_command::CommandVariant::IdFvmlib(_)
                | goblin::mach::load_command::CommandVariant::Fvmfile(_)
                | goblin::mach::load_command::CommandVariant::PreboundDylib(_)
                | goblin::mach::load_command::CommandVariant::SubFramework(_)
                | goblin::mach::load_command::CommandVariant::SubUmbrella(_)
                | goblin::mach::load_command::CommandVariant::SubClient(_)
                | goblin::mach::load_command::CommandVariant::SubLibrary(_)
                | goblin::mach::load_command::CommandVariant::FilesetEntry(_)
                | goblin::mach::load_command::CommandVariant::Unimplemented(_)
        )
    }) {
        return Err(native_dependency_error(
            "Mach-O 原生制品含未纳入固定依赖闭包的动态装载命令",
        ));
    }
    // goblin reserves index zero for the image's own LC_ID_DYLIB (or the synthetic
    // "self" entry). Only subsequent entries are dependencies consulted by dyld.
    let libraries = mach.libs.get(1..).unwrap_or_default();
    let dependency_commands = mach
        .load_commands
        .iter()
        .filter(|command| {
            matches!(
                command.command,
                goblin::mach::load_command::CommandVariant::LoadDylib(_)
                    | goblin::mach::load_command::CommandVariant::LoadUpwardDylib(_)
                    | goblin::mach::load_command::CommandVariant::ReexportDylib(_)
                    | goblin::mach::load_command::CommandVariant::LoadWeakDylib(_)
                    | goblin::mach::load_command::CommandVariant::LazyLoadDylib(_)
            )
        })
        .count();
    if dependency_commands != libraries.len() {
        return Err(native_format_error(
            "Mach-O 动态依赖命令含不能完整解析的库名称",
        ));
    }
    let identifier_commands = mach
        .load_commands
        .iter()
        .filter(|command| {
            matches!(
                command.command,
                goblin::mach::load_command::CommandVariant::IdDylib(_)
            )
        })
        .count();
    if (mach.header.filetype == goblin::mach::header::MH_DYLIB && identifier_commands != 1)
        || (mach.header.filetype == goblin::mach::header::MH_BUNDLE && identifier_commands != 0)
    {
        return Err(native_format_error("Mach-O 动态库标识命令与映像类型不一致"));
    }
    validate_mach_dependencies(libraries, &mach.rpaths)
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "macos")))]
fn validate_mach_container(mach: Mach<'_>) -> Result<(), NativeError> {
    match mach {
        Mach::Binary(binary) => validate_mach_library(&binary),
        Mach::Fat(container) => {
            let architecture_count = container
                .arches()
                .map_err(|error| native_format_error(format!("不能解析 Mach-O 架构表：{error}")))?
                .len();
            if architecture_count == 0 || architecture_count > NATIVE_V2_MAX_MACH_ARCHITECTURES {
                return Err(native_format_error(format!(
                    "Mach-O 通用制品架构数 {architecture_count} 不在 1–{NATIVE_V2_MAX_MACH_ARCHITECTURES} 范围内"
                )));
            }
            let expected = expected_mach_cpu()?;
            let mut selected = None;
            for entry in &container {
                let entry = entry.map_err(|error| {
                    native_format_error(format!("不能解析 Mach-O 通用制品：{error}"))
                })?;
                if let SingleArch::MachO(binary) = entry
                    && binary.header.cputype == expected
                {
                    if selected.is_some() {
                        return Err(native_format_error("Mach-O 通用制品含重复的当前架构切片"));
                    }
                    selected = Some(binary);
                }
            }
            let selected =
                selected.ok_or_else(|| native_format_error("Mach-O 通用制品不含当前架构切片"))?;
            validate_mach_library(&selected)
        }
    }
}

#[cfg(all(not(target_family = "wasm"), any(test, target_os = "windows")))]
fn validate_pe_library(pe: &goblin::pe::PE<'_>) -> Result<(), NativeError> {
    if !pe.is_lib || !pe.is_64 {
        return Err(native_format_error("ABI v2 PE 制品必须标记为 64 位 DLL"));
    }
    let expected = expected_pe_machine()?;
    if pe.header.coff_header.machine != expected {
        return Err(native_format_error(format!(
            "PE 机器类型 {} 与当前架构要求 {expected} 不符",
            pe.header.coff_header.machine
        )));
    }
    let optional = pe
        .header
        .optional_header
        .as_ref()
        .ok_or_else(|| native_format_error("ABI v2 PE 制品缺少可选头"))?;
    if let Some(imports) = &pe.import_data {
        validate_dependency_count(imports.import_data.len())?;
    }
    validate_pe_dependencies(
        &pe.libraries,
        optional
            .data_directories
            .get_delay_import_descriptor()
            .is_some(),
    )
}

/// 只解析并验证 ABI v2 动态库的宿主格式与依赖闭包，不执行任何初始化代码。
/// 供加载器、定向回归和结构化输入模糊测试复用。
#[cfg(not(target_family = "wasm"))]
#[doc(hidden)]
pub fn validate_native_library_metadata(bytes: &[u8]) -> Result<(), NativeError> {
    if bytes.len() as u64 > NATIVE_ARTIFACT_MAX_BYTES {
        return Err(native_error("NATIVE_LIMIT", "原生制品不得超过 256 MiB"));
    }
    let object = Object::parse(bytes)
        .map_err(|error| native_format_error(format!("不能解析原生制品头：{error}")))?;
    #[cfg(target_os = "linux")]
    {
        match object {
            Object::Elf(elf) => validate_elf_library(&elf),
            _ => Err(native_format_error("Linux ABI v2 制品必须是 ELF 共享库")),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match object {
            Object::Mach(mach) => validate_mach_container(mach),
            _ => Err(native_format_error("macOS ABI v2 制品必须是 Mach-O 动态库")),
        }
    }
    #[cfg(target_os = "windows")]
    {
        match object {
            Object::PE(pe) => validate_pe_library(&pe),
            _ => Err(native_format_error("Windows ABI v2 制品必须是 PE DLL")),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = object;
        Err(native_format_error(format!(
            "当前系统 {} 尚无 ABI v2 动态库元数据策略",
            std::env::consts::OS
        )))
    }
}

impl NativeExtensionV2 {
    #[cfg(not(target_family = "wasm"))]
    pub fn load_verified(
        path: impl AsRef<Path>,
        artifact: &NativeArtifact,
        permissions: &PermissionSet,
        expected_name: &str,
        authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        let path = absolute_native_artifact_path(path.as_ref())?;
        Self::validate_artifact_declaration(&path, artifact, permissions)?;
        let source = open_native_artifact(&path)?;
        Self::load_verified_file_after_policy(source, artifact, expected_name, authority)
    }

    /// 装载解析阶段已经打开的 ABI v2 制品。路径只用于权限与诊断，全部字节必须
    /// 从令牌中的句柄读取，调用方不得在依赖解析后按环境路径重新打开文件。
    #[cfg(not(target_family = "wasm"))]
    #[doc(hidden)]
    pub fn load_verified_file(
        source: ResolvedPackageFile,
        artifact: &NativeArtifact,
        permissions: &PermissionSet,
        expected_name: &str,
        authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        Self::validate_artifact_declaration(source.path(), artifact, permissions)?;
        Self::load_verified_file_after_policy(source, artifact, expected_name, authority)
    }

    #[cfg(not(target_family = "wasm"))]
    fn validate_artifact_declaration(
        path: &Path,
        artifact: &NativeArtifact,
        permissions: &PermissionSet,
    ) -> Result<(), NativeError> {
        if artifact.abi != NATIVE_ABI_VERSION_V2 {
            return Err(native_error(
                "NATIVE_ABI",
                format!("锁定制品 ABI {} 不是 ABI v2", artifact.abi),
            ));
        }
        permissions
            .check_native_extension(path)
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
        if artifact.size > NATIVE_ARTIFACT_MAX_BYTES {
            return Err(native_error("NATIVE_LIMIT", "原生制品不得超过 256 MiB"));
        }
        Ok(())
    }

    #[cfg(not(target_family = "wasm"))]
    fn load_verified_file_after_policy(
        source: ResolvedPackageFile,
        artifact: &NativeArtifact,
        expected_name: &str,
        _authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        let metadata = source.metadata().map_err(|error| {
            native_error("NATIVE_IO", format!("不能检查已打开的原生制品：{error}"))
        })?;
        if !metadata.is_file() {
            return Err(native_error("NATIVE_IO", "已打开的原生制品不是普通文件"));
        }
        if metadata.len() != artifact.size || metadata.len() > NATIVE_ARTIFACT_MAX_BYTES {
            return Err(native_error(
                "NATIVE_LIMIT",
                format!(
                    "原生制品大小不符或超限：锁定 {}，实际 {}",
                    artifact.size,
                    metadata.len()
                ),
            ));
        }
        let bytes = crate::package::read_resolved_regular_file_snapshot(
            source,
            NATIVE_ARTIFACT_MAX_BYTES,
            "ABI v2 原生制品",
        )
        .map_err(|error| native_error("NATIVE_IO", error.to_string()))?;
        Self::load_verified_bytes_after_policy(&bytes, artifact, expected_name)
    }

    /// 装载已随应用归档携带的锁定制品字节。调用方无须提供源码或包缓存；
    /// 本函数仍会复核 ABI、目标、大小、摘要和权限，并写入随机私有的内容寻址目录。
    #[cfg(not(target_family = "wasm"))]
    pub fn load_verified_bytes(
        bytes: &[u8],
        artifact: &NativeArtifact,
        permissions: &PermissionSet,
        expected_name: &str,
        _authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        Self::validate_artifact_declaration(Path::new(&artifact.path), artifact, permissions)?;
        Self::load_verified_bytes_after_policy(bytes, artifact, expected_name)
    }

    #[cfg(not(target_family = "wasm"))]
    fn load_verified_bytes_after_policy(
        bytes: &[u8],
        artifact: &NativeArtifact,
        expected_name: &str,
    ) -> Result<Self, NativeError> {
        if bytes.len() as u64 != artifact.size || bytes.len() as u64 > NATIVE_ARTIFACT_MAX_BYTES {
            return Err(native_error(
                "NATIVE_LIMIT",
                format!(
                    "原生制品大小不符或超限：锁定 {}，实际 {}",
                    artifact.size,
                    bytes.len()
                ),
            ));
        }
        let checksum = format!("{:x}", Sha256::digest(bytes));
        if checksum != artifact.checksum.to_ascii_lowercase() {
            return Err(native_error(
                "NATIVE_CHECKSUM",
                format!("制品校验不符：声明 {}，实际 {checksum}", artifact.checksum),
            ));
        }
        validate_native_library_metadata(bytes)?;
        let staged = stage_verified_library(bytes, &checksum)?;
        // SAFETY: Bytes were verified and staged privately; descriptors are validated below.
        unsafe { Self::load(staged, expected_name) }
    }

    #[cfg(target_family = "wasm")]
    pub fn load_verified(
        _path: impl AsRef<Path>,
        _artifact: &NativeArtifact,
        _permissions: &PermissionSet,
        _expected_name: &str,
        _authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        Err(native_error(
            "NATIVE_UNSUPPORTED",
            "WASI 禁止装载宿主动态库",
        ))
    }

    #[cfg(target_family = "wasm")]
    #[doc(hidden)]
    pub fn load_verified_file(
        _source: ResolvedPackageFile,
        _artifact: &NativeArtifact,
        _permissions: &PermissionSet,
        _expected_name: &str,
        _authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        Err(native_error(
            "NATIVE_UNSUPPORTED",
            "WASI 禁止装载宿主动态库",
        ))
    }

    #[cfg(target_family = "wasm")]
    pub fn load_verified_bytes(
        _bytes: &[u8],
        _artifact: &NativeArtifact,
        _permissions: &PermissionSet,
        _expected_name: &str,
        _authority: NativeLoadAuthority,
    ) -> Result<Self, NativeError> {
        Err(native_error(
            "NATIVE_UNSUPPORTED",
            "WASI 禁止装载宿主动态库",
        ))
    }

    #[cfg(not(target_family = "wasm"))]
    unsafe fn load(staged: StagedLibrary, expected_name: &str) -> Result<Self, NativeError> {
        // SAFETY: Staged path remains owned until after explicit library unload.
        let library = unsafe { load_dynamic_library_safely(&staged.path) }.map_err(|error| {
            native_error(
                "NATIVE_LOAD",
                format!("不能打开 {}：{error}", staged.path.display()),
            )
        })?;
        // SAFETY: The symbol name and function type are fixed by ABI v2.
        let entry: NativeModuleEntryV2 = unsafe {
            *library
                .get::<NativeModuleEntryV2>(b"yanxu_native_module_v2\0")
                .map_err(|error| {
                    native_error("NATIVE_SYMBOL", format!("缺少 ABI v2 入口：{error}"))
                })?
        };
        // SAFETY: Entry contract promises a stable descriptor; validation copies all fields.
        let descriptor = unsafe { entry() };
        let validated = unsafe { validate_descriptor_v2(descriptor, expected_name) }?;
        Ok(Self {
            inner: Rc::new(NativeInnerV2 {
                library: Some(library),
                _staged: staged,
                name: validated.name,
                capabilities: validated.capabilities,
                functions: validated.functions,
                constants: validated.constants,
                resource_types: validated.resource_types,
                free_value: validated.free_value,
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
    pub fn constants(&self) -> &BTreeMap<String, HostValue> {
        &self.inner.constants
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn resource_types(&self) -> &[String] {
        &self.inner.resource_types
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn call(
        &self,
        name: &str,
        arguments: &[HostValue],
        host: Option<&YanxuNativeHostV2>,
    ) -> Result<NativeV2CallResult, NativeError> {
        let function = self.inner.functions.get(name).ok_or_else(|| {
            native_error(
                "NATIVE_FUNCTION",
                format!("模块“{}”未注册函数“{name}”", self.inner.name),
            )
        })?;
        let (arguments, _arena) = encode_arguments(arguments)?;
        let mut output = YanxuValueV2::default();
        let mut failure = YanxuNativeErrorV2::default();
        let call = function
            .call
            .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "原生函数指针为空"))?;
        // SAFETY: Descriptors are validated; argument arena and host table outlive the call.
        let status = unsafe {
            call(
                function.context,
                arguments.as_ptr(),
                arguments.len(),
                host.map_or(ptr::null(), |host| host),
                &mut output,
                &mut failure,
            )
        };
        let mut output = OutputGuardV2 {
            value: output,
            free_value: self.inner.free_value,
        };
        if status != NATIVE_V2_OK {
            return Err(unsafe { copy_native_error_v2(failure) });
        }
        if output.value.kind == NATIVE_V2_RESOURCE {
            let resource = unsafe { take_resource(&mut output.value, self.inner.clone()) }?;
            if !self.inner.resource_types.contains(&resource.type_name) {
                return Err(native_error(
                    "NATIVE_RESOURCE",
                    format!("未注册资源类型“{}”", resource.type_name),
                ));
            }
            return Ok(NativeV2CallResult::Resource(resource));
        }
        let value = unsafe { decode_borrowed_value(&output.value, 0) }?;
        value
            .validate(HostValueLimits::default())
            .map_err(|error| native_error(error.code, error.message))?;
        Ok(NativeV2CallResult::Value(value))
    }

    #[cfg(target_family = "wasm")]
    pub fn call(
        &self,
        _name: &str,
        _arguments: &[HostValue],
        _host: Option<&YanxuNativeHostV2>,
    ) -> Result<NativeV2CallResult, NativeError> {
        Err(native_error(
            "NATIVE_UNSUPPORTED",
            "WASI 禁止调用宿主动态库",
        ))
    }
}

#[cfg(not(target_family = "wasm"))]
struct EncodedArena {
    buffers: Vec<Vec<u8>>,
    children: Vec<Box<[YanxuValueV2]>>,
}

#[cfg(not(target_family = "wasm"))]
fn encode_arguments(
    arguments: &[HostValue],
) -> Result<(Vec<YanxuValueV2>, EncodedArena), NativeError> {
    let mut arena = EncodedArena {
        buffers: Vec::new(),
        children: Vec::new(),
    };
    let mut encoded = Vec::with_capacity(arguments.len());
    for argument in arguments {
        argument
            .validate(HostValueLimits::default())
            .map_err(|error| native_error(error.code, error.message))?;
        encoded.push(encode_value(argument, &mut arena)?);
    }
    Ok((encoded, arena))
}

/// 深拷贝原生扩展投递的 ABI v2 参数。
///
/// # Safety
/// `arguments` 在本函数返回前必须指向至少 `argument_count` 个可读值；所有
/// 递归指针也必须满足 ABI v2 的借用期约定。
pub unsafe fn copy_posted_arguments(
    arguments: *const YanxuValueV2,
    argument_count: usize,
) -> Result<Vec<HostValue>, NativeError> {
    if argument_count > HostValueLimits::default().max_elements {
        return Err(native_error(
            "NATIVE_VALUE_LIMIT",
            "回调参数数量超过 ABI v2 上限",
        ));
    }
    let arguments = unsafe { pointer_slice_v2(arguments, argument_count, "回调参数") }?;
    let values = arguments
        .iter()
        .map(|value| unsafe { decode_borrowed_value(value, 0) })
        .collect::<Result<Vec<_>, _>>()?;
    HostValue::Array(values.clone())
        .validate(HostValueLimits::default())
        .map_err(|error| native_error(error.code, error.message))?;
    Ok(values)
}

#[cfg(not(target_family = "wasm"))]
fn encode_value(value: &HostValue, arena: &mut EncodedArena) -> Result<YanxuValueV2, NativeError> {
    let encoded = match value {
        HostValue::Nil => YanxuValueV2::default(),
        HostValue::Bool(value) => YanxuValueV2 {
            kind: NATIVE_V2_BOOL,
            flags: u32::from(*value) * NATIVE_V2_FLAG_TRUE,
            ..YanxuValueV2::default()
        },
        HostValue::Integer(value) => YanxuValueV2 {
            kind: NATIVE_V2_INTEGER,
            data: YanxuValueDataV2 { integer: *value },
            ..YanxuValueV2::default()
        },
        HostValue::Number(value) if value.is_finite() => YanxuValueV2 {
            kind: NATIVE_V2_NUMBER,
            data: YanxuValueDataV2 { number: *value },
            ..YanxuValueV2::default()
        },
        HostValue::Number(_) => {
            return Err(native_error("NATIVE_VALUE", "ABI v2 不接受非有限浮点数"));
        }
        HostValue::String(value) => encode_bytes(NATIVE_V2_STRING, value.as_bytes(), arena),
        HostValue::Bytes(value) => encode_bytes(NATIVE_V2_BYTES, value, arena),
        HostValue::Array(values) => {
            let children = values
                .iter()
                .map(|value| encode_value(value, arena))
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice();
            let pointer = children.as_ptr();
            let length = children.len() as u64;
            arena.children.push(children);
            YanxuValueV2 {
                kind: NATIVE_V2_ARRAY,
                length,
                data: YanxuValueDataV2 { items: pointer },
                ..YanxuValueV2::default()
            }
        }
        HostValue::Map(entries) => {
            let mut children = Vec::with_capacity(entries.len().saturating_mul(2));
            for (key, value) in entries {
                children.push(encode_value(key, arena)?);
                children.push(encode_value(value, arena)?);
            }
            let children = children.into_boxed_slice();
            let pointer = children.as_ptr();
            let length = entries.len() as u64;
            arena.children.push(children);
            YanxuValueV2 {
                kind: NATIVE_V2_MAP,
                length,
                data: YanxuValueDataV2 { items: pointer },
                ..YanxuValueV2::default()
            }
        }
        HostValue::Resource(handle) => YanxuValueV2 {
            kind: NATIVE_V2_RESOURCE,
            flags: NATIVE_V2_FLAG_RESOURCE_HANDLE,
            data: YanxuValueDataV2 { handle: *handle },
            ..YanxuValueV2::default()
        },
        HostValue::Callback(handle) => YanxuValueV2 {
            kind: NATIVE_V2_CALLBACK,
            data: YanxuValueDataV2 { handle: *handle },
            ..YanxuValueV2::default()
        },
        HostValue::Error {
            code,
            message,
            details,
        } => {
            let children = vec![
                encode_value(&HostValue::String(code.clone()), arena)?,
                encode_value(&HostValue::String(message.clone()), arena)?,
                encode_value(details.as_deref().unwrap_or(&HostValue::Nil), arena)?,
            ]
            .into_boxed_slice();
            let pointer = children.as_ptr();
            arena.children.push(children);
            YanxuValueV2 {
                kind: NATIVE_V2_ERROR_VALUE,
                length: 3,
                data: YanxuValueDataV2 { items: pointer },
                ..YanxuValueV2::default()
            }
        }
    };
    Ok(encoded)
}

#[cfg(not(target_family = "wasm"))]
fn encode_bytes(kind: u32, bytes: &[u8], arena: &mut EncodedArena) -> YanxuValueV2 {
    let buffer = bytes.to_vec();
    let pointer = buffer.as_ptr();
    let length = buffer.len() as u64;
    arena.buffers.push(buffer);
    YanxuValueV2 {
        kind,
        length,
        data: YanxuValueDataV2 { bytes: pointer },
        ..YanxuValueV2::default()
    }
}

#[cfg(not(target_family = "wasm"))]
struct ValidatedDescriptorV2 {
    name: String,
    capabilities: u64,
    functions: BTreeMap<String, YanxuNativeFunctionV2>,
    constants: BTreeMap<String, HostValue>,
    resource_types: Vec<String>,
    free_value: NativeFreeValueV2,
}

#[cfg(not(target_family = "wasm"))]
unsafe fn validate_descriptor_v2(
    descriptor: *const YanxuNativeModuleV2,
    expected_name: &str,
) -> Result<ValidatedDescriptorV2, NativeError> {
    // SAFETY: Caller obtained this pointer from the ABI entry and checks null here.
    let descriptor = unsafe { descriptor.as_ref() }
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "ABI v2 模块描述符为空"))?;
    if descriptor.abi_version != NATIVE_ABI_VERSION_V2 {
        return Err(native_error(
            "NATIVE_ABI",
            format!(
                "扩展 ABI {} 与运行时 ABI {} 不兼容",
                descriptor.abi_version, NATIVE_ABI_VERSION_V2
            ),
        ));
    }
    if descriptor.struct_size < std::mem::size_of::<YanxuNativeModuleV2>() {
        return Err(native_error("NATIVE_ABI", "ABI v2 模块描述符尺寸过小"));
    }
    let name = unsafe {
        copy_utf8_v2(
            descriptor.name,
            descriptor.name_length,
            "模块名",
            NATIVE_V2_MAX_NAME_BYTES,
        )
    }?;
    if name != expected_name {
        return Err(native_error(
            "NATIVE_NAME",
            format!("扩展声明“{name}”，清单要求“{expected_name}”"),
        ));
    }
    let free_value = descriptor
        .free_value
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "模块未提供递归值释放函数"))?;
    for (count, kind) in [
        (descriptor.function_count, "函数"),
        (descriptor.constant_count, "常量"),
        (descriptor.resource_type_count, "资源类型"),
    ] {
        if count > NATIVE_V2_MAX_DESCRIPTORS {
            return Err(native_error(
                "NATIVE_LIMIT",
                format!("{kind}描述符不得超过 {NATIVE_V2_MAX_DESCRIPTORS}"),
            ));
        }
    }
    let functions = unsafe {
        pointer_slice_v2(
            descriptor.functions,
            descriptor.function_count,
            "函数描述符",
        )
    }?;
    let constants = unsafe {
        pointer_slice_v2(
            descriptor.constants,
            descriptor.constant_count,
            "常量描述符",
        )
    }?;
    let resource_types = unsafe {
        pointer_slice_v2(
            descriptor.resource_types,
            descriptor.resource_type_count,
            "资源类型指针",
        )
    }?;
    let resource_lengths = unsafe {
        pointer_slice_v2(
            descriptor.resource_type_lengths,
            descriptor.resource_type_count,
            "资源类型长度",
        )
    }?;
    let mut function_map = BTreeMap::new();
    for function in functions {
        let function_name = unsafe {
            copy_utf8_v2(
                function.name,
                function.name_length,
                "函数名",
                NATIVE_V2_MAX_NAME_BYTES,
            )
        }?;
        if function.call.is_none()
            || function_map
                .insert(function_name.clone(), *function)
                .is_some()
        {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("函数“{function_name}”为空或重复"),
            ));
        }
    }
    let mut constant_map = BTreeMap::new();
    for constant in constants {
        let constant_name = unsafe {
            copy_utf8_v2(
                constant.name,
                constant.name_length,
                "常量名",
                NATIVE_V2_MAX_NAME_BYTES,
            )
        }?;
        let value = unsafe { constant.value.as_ref() }
            .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "常量值指针为空"))?;
        let value = unsafe { decode_borrowed_value(value, 0) }?;
        value
            .validate(HostValueLimits::default())
            .map_err(|error| native_error(error.code, error.message))?;
        if constant_map.insert(constant_name.clone(), value).is_some() {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("常量“{constant_name}”重复"),
            ));
        }
    }
    let mut resource_names = Vec::new();
    for (pointer, length) in resource_types.iter().zip(resource_lengths) {
        let resource_name =
            unsafe { copy_utf8_v2(*pointer, *length, "资源类型", NATIVE_V2_MAX_NAME_BYTES) }?;
        if resource_names.contains(&resource_name) {
            return Err(native_error(
                "NATIVE_DESCRIPTOR",
                format!("资源类型“{resource_name}”重复"),
            ));
        }
        resource_names.push(resource_name);
    }
    Ok(ValidatedDescriptorV2 {
        name,
        capabilities: descriptor.capabilities,
        functions: function_map,
        constants: constant_map,
        resource_types: resource_names,
        free_value,
    })
}

unsafe fn decode_borrowed_value(
    value: &YanxuValueV2,
    depth: usize,
) -> Result<HostValue, NativeError> {
    let limits = HostValueLimits::default();
    if depth > limits.max_depth {
        return Err(native_error("NATIVE_VALUE_LIMIT", "ABI v2 值递归深度超限"));
    }
    Ok(match value.kind {
        NATIVE_V2_NULL => HostValue::Nil,
        NATIVE_V2_BOOL => HostValue::Bool(value.flags & NATIVE_V2_FLAG_TRUE != 0),
        NATIVE_V2_INTEGER => HostValue::Integer(unsafe { value.data.integer }),
        NATIVE_V2_NUMBER => {
            let number = unsafe { value.data.number };
            if !number.is_finite() {
                return Err(native_error("NATIVE_VALUE", "ABI v2 返回非有限浮点数"));
            }
            HostValue::Number(number)
        }
        NATIVE_V2_STRING => {
            let bytes = unsafe { copy_value_bytes(value, limits.max_string_bytes, "文字") }?;
            HostValue::String(String::from_utf8(bytes).map_err(|error| {
                native_error("NATIVE_UTF8", format!("ABI v2 文字不是 UTF-8：{error}"))
            })?)
        }
        NATIVE_V2_BYTES => HostValue::Bytes(unsafe {
            copy_value_bytes(value, limits.max_byte_string_bytes, "字节串")
        }?),
        NATIVE_V2_ARRAY => {
            let length = usize::try_from(value.length)
                .map_err(|_| native_error("NATIVE_VALUE_LIMIT", "数组长度超出宿主范围"))?;
            if length > limits.max_elements {
                return Err(native_error("NATIVE_VALUE_LIMIT", "数组元素数量超限"));
            }
            let items = unsafe { pointer_slice_v2(value.data.items, length, "数组元素") }?;
            HostValue::Array(
                items
                    .iter()
                    .map(|item| unsafe { decode_borrowed_value(item, depth + 1) })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        NATIVE_V2_MAP => {
            let pairs = usize::try_from(value.length)
                .map_err(|_| native_error("NATIVE_VALUE_LIMIT", "映射长度超出宿主范围"))?;
            if pairs > limits.max_elements / 2 {
                return Err(native_error("NATIVE_VALUE_LIMIT", "映射元素数量超限"));
            }
            let length = pairs
                .checked_mul(2)
                .ok_or_else(|| native_error("NATIVE_VALUE_LIMIT", "映射长度溢出"))?;
            let items = unsafe { pointer_slice_v2(value.data.items, length, "映射元素") }?;
            let mut entries = Vec::with_capacity(pairs);
            for pair in items.chunks_exact(2) {
                entries.push((
                    unsafe { decode_borrowed_value(&pair[0], depth + 1) }?,
                    unsafe { decode_borrowed_value(&pair[1], depth + 1) }?,
                ));
            }
            HostValue::Map(entries)
        }
        NATIVE_V2_RESOURCE => {
            return Err(native_error(
                "NATIVE_RESOURCE",
                "资源值只能作为原生调用的顶层返回值",
            ));
        }
        NATIVE_V2_CALLBACK => HostValue::Callback(unsafe { value.data.handle }),
        NATIVE_V2_ERROR_VALUE => {
            if value.length != 3 {
                return Err(native_error(
                    "NATIVE_VALUE",
                    "结构化错误必须包含代码、消息和详情三项",
                ));
            }
            let items = unsafe { pointer_slice_v2(value.data.items, 3, "结构化错误") }?;
            let code = match unsafe { decode_borrowed_value(&items[0], depth + 1) }? {
                HostValue::String(code) => code,
                _ => return Err(native_error("NATIVE_VALUE", "结构化错误代码必须为文字")),
            };
            let message = match unsafe { decode_borrowed_value(&items[1], depth + 1) }? {
                HostValue::String(message) => message,
                _ => return Err(native_error("NATIVE_VALUE", "结构化错误消息必须为文字")),
            };
            let details = unsafe { decode_borrowed_value(&items[2], depth + 1) }?;
            HostValue::Error {
                code,
                message,
                details: (!matches!(details, HostValue::Nil)).then(|| Box::new(details)),
            }
        }
        kind => {
            return Err(native_error(
                "NATIVE_VALUE",
                format!("未知 ABI v2 值种类 {kind}"),
            ));
        }
    })
}

#[cfg(not(target_family = "wasm"))]
unsafe fn take_resource(
    value: &mut YanxuValueV2,
    owner: Rc<NativeInnerV2>,
) -> Result<NativeResourceV2, NativeError> {
    if value.flags & NATIVE_V2_FLAG_RESOURCE_HANDLE != 0 {
        return Err(native_error(
            "NATIVE_RESOURCE",
            "模块返回了借用资源句柄而非拥有所有权的资源描述符",
        ));
    }
    let pointer = unsafe { value.data.resource };
    // SAFETY: Module marks this value as an owned resource descriptor; null is rejected.
    let descriptor = unsafe { pointer.as_mut() }
        .ok_or_else(|| native_error("NATIVE_RESOURCE", "资源描述符为空"))?;
    if descriptor.struct_size < std::mem::size_of::<YanxuNativeResourceV2>()
        || descriptor.resource.is_null()
        || descriptor.drop_resource.is_none()
    {
        return Err(native_error(
            "NATIVE_RESOURCE",
            "资源描述符尺寸、指针或析构函数无效",
        ));
    }
    let type_name = unsafe {
        copy_utf8_v2(
            descriptor.type_name,
            descriptor.type_name_length,
            "资源类型",
            NATIVE_V2_MAX_NAME_BYTES,
        )
    }?;
    let resource = descriptor.resource;
    let drop_resource = descriptor.drop_resource.take();
    descriptor.resource = ptr::null_mut();
    Ok(NativeResourceV2 {
        _owner: owner,
        raw: resource,
        drop_resource,
        type_name,
        parent: descriptor.parent,
    })
}

unsafe fn copy_value_bytes(
    value: &YanxuValueV2,
    limit: usize,
    kind: &str,
) -> Result<Vec<u8>, NativeError> {
    let length = usize::try_from(value.length)
        .map_err(|_| native_error("NATIVE_VALUE_LIMIT", format!("{kind}长度超出宿主范围")))?;
    if length > limit {
        return Err(native_error(
            "NATIVE_VALUE_LIMIT",
            format!("{kind}不得超过 {limit} 字节"),
        ));
    }
    let pointer = unsafe { value.data.bytes };
    if length == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(native_error(
            "NATIVE_DESCRIPTOR",
            format!("{kind}指针为空但长度非零"),
        ));
    }
    // SAFETY: The ABI owner promises this pointer is readable for the declared call lifetime.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

unsafe fn pointer_slice_v2<'a, T>(
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
    // SAFETY: Caller obtains this pointer and length from a validated ABI descriptor/value.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_utf8_v2(
    pointer: *const u8,
    length: usize,
    kind: &str,
    limit: usize,
) -> Result<String, NativeError> {
    if length == 0 || length > limit {
        return Err(native_error(
            "NATIVE_LIMIT",
            format!("{kind}为空或超过 {limit} 字节"),
        ));
    }
    if pointer.is_null() {
        return Err(native_error(
            "NATIVE_DESCRIPTOR",
            format!("{kind}指针为空但长度非零"),
        ));
    }
    // SAFETY: Descriptor promises this memory is stable for module lifetime/call duration.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| native_error("NATIVE_UTF8", format!("{kind}不是 UTF-8：{error}")))
}

#[cfg(not(target_family = "wasm"))]
unsafe fn copy_native_error_v2(error: YanxuNativeErrorV2) -> NativeError {
    let code = unsafe {
        copy_utf8_v2(
            error.code,
            error.code_length,
            "错误码",
            NATIVE_V2_MAX_ERROR_CODE_BYTES,
        )
    }
    .unwrap_or_else(|_| "NATIVE_FAILURE".into());
    let message = unsafe {
        copy_utf8_v2(
            error.message,
            error.message_length,
            "错误消息",
            NATIVE_V2_MAX_ERROR_MESSAGE_BYTES,
        )
    }
    .unwrap_or_else(|_| "原生函数返回失败但未提供有效错误".into());
    native_error(code, message)
}

pub fn capabilities() -> serde_json::Value {
    let limits = HostValueLimits::default();
    serde_json::json!({
        "abi_version": NATIVE_ABI_VERSION_V2,
        "entry_symbol": "yanxu_native_module_v2",
        "typed_values": ["null", "bool", "i64", "f64", "utf8", "bytes", "array", "map", "resource", "callback", "error"],
        "borrowed_arguments": true,
        "module_owned_results": true,
        "persistent_callbacks": true,
        "host_event_queue": true,
        "thread_safe_post": true,
        "max_depth": limits.max_depth,
        "max_elements": limits.max_elements,
        "max_total_bytes": limits.max_total_bytes,
        "max_string_bytes": limits.max_string_bytes,
        "max_byte_string_bytes": limits.max_byte_string_bytes,
        "max_descriptors": NATIVE_V2_MAX_DESCRIPTORS,
        "max_library_bytes": NATIVE_ARTIFACT_MAX_BYTES,
        "wasi_dynamic_loading": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_values_round_trip_binary_nested_and_structured_error_data() {
        let values = vec![
            HostValue::Integer(i64::MIN + 7),
            HostValue::Bytes(vec![0, 255, 128]),
            HostValue::Map(vec![(
                HostValue::String("键".into()),
                HostValue::Array(vec![HostValue::Bool(true), HostValue::Number(1.5)]),
            )]),
            HostValue::Error {
                code: "GUI_TEST".into(),
                message: "结构化错误".into(),
                details: Some(Box::new(HostValue::Integer(9))),
            },
        ];
        let (encoded, _arena) = encode_arguments(&values).unwrap();
        let decoded = encoded
            .iter()
            .map(|value| unsafe { decode_borrowed_value(value, 0) })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn typed_values_reject_invalid_utf8_depth_and_non_finite_numbers() {
        let bytes = [0xff_u8];
        let invalid = YanxuValueV2 {
            kind: NATIVE_V2_STRING,
            length: 1,
            data: YanxuValueDataV2 {
                bytes: bytes.as_ptr(),
            },
            ..YanxuValueV2::default()
        };
        assert_eq!(
            unsafe { decode_borrowed_value(&invalid, 0) }
                .unwrap_err()
                .code,
            "NATIVE_UTF8"
        );
        let non_finite = match encode_arguments(&[HostValue::Number(f64::NAN)]) {
            Ok(_) => panic!("non-finite values should be rejected"),
            Err(error) => error,
        };
        assert_eq!(non_finite.code, "NATIVE_VALUE");
    }

    #[test]
    fn descriptor_v2_uses_a_separate_version_and_validates_static_constants() {
        unsafe extern "C" fn free_value(_value: *mut YanxuValueV2) {}
        static NAME: &[u8] = b"v2-example";
        static CONSTANT_NAME: &[u8] = b"answer";
        let constant_value = YanxuValueV2 {
            kind: NATIVE_V2_INTEGER,
            data: YanxuValueDataV2 { integer: 42 },
            ..YanxuValueV2::default()
        };
        let constant = YanxuNativeConstantV2 {
            name: CONSTANT_NAME.as_ptr(),
            name_length: CONSTANT_NAME.len(),
            value: &constant_value,
        };
        let descriptor = YanxuNativeModuleV2 {
            abi_version: 2,
            struct_size: std::mem::size_of::<YanxuNativeModuleV2>(),
            name: NAME.as_ptr(),
            name_length: NAME.len(),
            functions: ptr::null(),
            function_count: 0,
            constants: &constant,
            constant_count: 1,
            resource_types: ptr::null(),
            resource_type_lengths: ptr::null(),
            resource_type_count: 0,
            free_value: Some(free_value),
            capabilities: 3,
        };
        let validated = unsafe { validate_descriptor_v2(&descriptor, "v2-example") }.unwrap();
        assert_eq!(validated.constants["answer"], HostValue::Integer(42));
        assert_eq!(validated.capabilities, 3);
    }

    #[test]
    fn capability_document_records_all_limits() {
        assert_eq!(capabilities()["abi_version"], 2);
        assert_eq!(capabilities()["persistent_callbacks"], true);
        assert!(capabilities()["max_depth"].as_u64().unwrap() > 0);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn dynamic_dependency_policies_reject_search_path_and_path_injection() {
        // Keep every host-format validator type-checked even when this test runs on one OS.
        let _elf_validator = validate_elf_library;
        let _mach_validator = validate_mach_container;
        let _pe_validator = validate_pe_library;

        validate_elf_dependencies(&["libc.so.6", "libgcc_s.so.1"], &[], &[]).unwrap();
        assert_eq!(
            validate_elf_dependencies(&["../libescape.so"], &[], &[])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_elf_dependencies(&["$ORIGIN"], &[], &[])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_elf_dependencies(&["libc.so.6"], &["$ORIGIN"], &[])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );

        validate_mach_dependencies(
            &[
                "/usr/lib/libSystem.B.dylib",
                "/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit",
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            validate_mach_dependencies(&["@rpath/libescape.dylib"], &[])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_mach_dependencies(&["/usr/lib/lib\nescape.dylib"], &[])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_mach_dependencies(&["/usr/lib/libSystem.B.dylib"], &["@loader_path"])
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );

        validate_pe_dependencies(&["KERNEL32.dll", "api-ms-win-core-file-l1-1-0.dll"], false)
            .unwrap();
        assert_eq!(
            validate_pe_dependencies(&["..\\escape.dll"], false)
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_pe_dependencies(&["KERNEL32.dll."], false)
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
        assert_eq!(
            validate_pe_dependencies(&["KERNEL32.dll"], true)
                .unwrap_err()
                .code,
            "NATIVE_DEPENDENCY"
        );
    }
}

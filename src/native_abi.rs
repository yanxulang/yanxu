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
use std::path::Path;
use std::ptr;
#[cfg(not(target_family = "wasm"))]
use std::rc::Rc;

pub const NATIVE_ABI_VERSION: u32 = 1;
pub const NATIVE_OK: i32 = 0;
pub const NATIVE_OUTPUT_JSON: u32 = 1;
pub const NATIVE_OUTPUT_RESOURCE: u32 = 2;
const NATIVE_MAX_DESCRIPTORS: usize = 1_024;
const NATIVE_MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

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
    _library: libloading::Library,
    name: String,
    capabilities: u64,
    functions: BTreeMap<String, YanxuNativeFunctionV1>,
    constants: BTreeMap<String, Value>,
    resource_types: Vec<String>,
    free_bytes: NativeFreeBytes,
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
        let path = path.as_ref();
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
        let bytes = std::fs::read(path).map_err(|error| {
            native_error("NATIVE_IO", format!("不能读取 {}：{error}", path.display()))
        })?;
        let checksum = format!("{:x}", Sha256::digest(bytes));
        if checksum != artifact.checksum.to_ascii_lowercase() {
            return Err(native_error(
                "NATIVE_CHECKSUM",
                format!("制品校验不符：声明 {}，实际 {checksum}", artifact.checksum),
            ));
        }
        // SAFETY: The path has passed the caller's explicit permission, target and digest gates.
        // All symbols and descriptor fields are validated before becoming safe wrappers.
        unsafe { Self::load(path, expected_name) }
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
    unsafe fn load(path: &Path, expected_name: &str) -> Result<Self, NativeError> {
        // SAFETY: The caller has completed security gates; Library remains owned by NativeInner.
        let library = unsafe { libloading::Library::new(path) }.map_err(|error| {
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
                _library: library,
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
        if status != NATIVE_OK {
            return Err(unsafe { copy_native_error(native_failure) });
        }
        match output.kind {
            NATIVE_OUTPUT_JSON => {
                let bytes = unsafe {
                    copy_required_bytes(output.json, output.json_length, "原生 JSON 输出")
                }?;
                // SAFETY: The extension transferred this output buffer and its module-wide
                // release function is retained by NativeInner.
                unsafe { (self.inner.free_bytes)(output.json, output.json_length) };
                if bytes.len() > NATIVE_MAX_JSON_BYTES {
                    return Err(native_error("NATIVE_LIMIT", "原生调用结果超过 16 MiB"));
                }
                serde_json::from_slice(&bytes)
                    .map(NativeCallResult::Json)
                    .map_err(|error| native_error("NATIVE_JSON", error.to_string()))
            }
            NATIVE_OUTPUT_RESOURCE => {
                if output.resource.is_null() || output.drop_resource.is_none() {
                    return Err(native_error(
                        "NATIVE_RESOURCE",
                        "不透明资源缺少指针或析构函数",
                    ));
                }
                let type_name = unsafe {
                    copy_utf8(
                        output.resource_type,
                        output.resource_type_length,
                        "资源类型",
                    )
                }?;
                if !self.inner.resource_types.contains(&type_name) {
                    return Err(native_error(
                        "NATIVE_RESOURCE",
                        format!("未注册资源类型“{type_name}”"),
                    ));
                }
                Ok(NativeCallResult::Resource(NativeResource {
                    _owner: self.inner.clone(),
                    raw: output.resource,
                    drop_resource: output.drop_resource.expect("checked"),
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
    let descriptor = unsafe { descriptor.as_ref() }
        .ok_or_else(|| native_error("NATIVE_DESCRIPTOR", "模块描述符为空"))?;
    if descriptor.abi_version != NATIVE_ABI_VERSION {
        return Err(native_error(
            "NATIVE_ABI",
            format!(
                "扩展 ABI {} 与运行时 ABI {NATIVE_ABI_VERSION} 不兼容",
                descriptor.abi_version
            ),
        ));
    }
    if descriptor.struct_size < std::mem::size_of::<YanxuNativeModuleV1>() {
        return Err(native_error("NATIVE_ABI", "模块描述符尺寸过小"));
    }
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
    let code = unsafe { copy_utf8(error.code, error.code_length, "错误码") }
        .unwrap_or_else(|_| "NATIVE_FAILURE".into());
    let message = unsafe { copy_utf8(error.message, error.message_length, "错误消息") }
        .unwrap_or_else(|_| "原生函数返回失败但未提供有效错误".into());
    native_error(code, message)
}

fn native_error(code: impl Into<String>, message: impl Into<String>) -> NativeError {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_family = "wasm"))]
    unsafe extern "C" fn release(bytes: *mut u8, length: usize) {
        if !bytes.is_null() {
            drop(unsafe { Vec::from_raw_parts(bytes, length, length) });
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
    }

    #[test]
    fn capability_document_is_stable() {
        assert_eq!(capabilities()["abi_version"], 1);
        assert_eq!(capabilities()["callbacks"], true);
    }
}

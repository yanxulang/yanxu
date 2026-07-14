//! 面向 C 及其他宿主语言的稳定最小 ABI。
//!
//! 所有执行结果都使用 UTF-8 JSON 返回。调用方必须以
//! [`yanxu_string_free`] 释放返回的字符串，并以 [`yanxu_engine_free`]
//! 释放引擎。默认构造函数启用沙箱；不受限构造函数必须由宿主显式选择。

use crate::embed::{Backend, Engine, EngineConfig, EngineErrorKind};
use serde_json::json;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

const ABI_SCHEMA: u32 = 1;

/// 创建默认的沙箱字节码引擎。
#[unsafe(no_mangle)]
pub extern "C" fn yanxu_engine_new() -> *mut Engine {
    Box::into_raw(Box::new(Engine::new(EngineConfig::default())))
}

/// 创建拥有全部宿主权限的字节码引擎。
///
/// 宿主应仅在代码来源可信时使用此入口。
#[unsafe(no_mangle)]
pub extern "C" fn yanxu_engine_new_unrestricted() -> *mut Engine {
    Box::into_raw(Box::new(Engine::new(EngineConfig::unrestricted(
        Backend::Bytecode,
    ))))
}

/// 释放言序引擎。
///
/// # Safety
///
/// `engine` 必须为空指针，或是由本库构造函数返回且尚未释放的指针。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yanxu_engine_free(engine: *mut Engine) {
    if !engine.is_null() {
        // SAFETY: The function contract requires an owned pointer from Box::into_raw.
        drop(unsafe { Box::from_raw(engine) });
    }
}

/// 在持久引擎中执行一段以 NUL 结尾的 UTF-8 源码，并返回 JSON。
///
/// # Safety
///
/// `engine` 必须指向有效且未释放的引擎；`source` 必须为空指针，或指向
/// 在调用期间有效的 NUL 结尾字节串。返回值必须交给 [`yanxu_string_free`]。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yanxu_engine_run(
    engine: *mut Engine,
    source: *const c_char,
) -> *mut c_char {
    if engine.is_null() {
        return json_string(json!({
            "schema": ABI_SCHEMA,
            "ok": false,
            "kind": "host",
            "message": "引擎指针为空",
        }));
    }
    if source.is_null() {
        return json_string(json!({
            "schema": ABI_SCHEMA,
            "ok": false,
            "kind": "host",
            "message": "源码指针为空",
        }));
    }

    // SAFETY: Both pointer requirements are part of this function's contract.
    let engine = unsafe { &mut *engine };
    // SAFETY: The caller promises a valid NUL-terminated byte string.
    let source = unsafe { CStr::from_ptr(source) };
    let source = match source.to_str() {
        Ok(source) => source,
        Err(error) => {
            return json_string(json!({
                "schema": ABI_SCHEMA,
                "ok": false,
                "kind": "host",
                "message": format!("源码并非有效 UTF-8：{error}"),
            }));
        }
    };

    match catch_unwind(AssertUnwindSafe(|| engine.run(source))) {
        Ok(Ok(execution)) => json_string(json!({
            "schema": ABI_SCHEMA,
            "ok": true,
            "value": execution.value,
            "type": execution.value_type,
            "value_bytes": execution.value_bytes,
            "output": execution.output,
            "backend": backend_name(execution.backend),
        })),
        Ok(Err(error)) => json_string(json!({
            "schema": ABI_SCHEMA,
            "ok": false,
            "kind": error_kind(error.kind),
            "message": error.message,
        })),
        Err(_) => json_string(json!({
            "schema": ABI_SCHEMA,
            "ok": false,
            "kind": "panic",
            "message": "言序引擎发生了未捕获的内部错误",
        })),
    }
}

/// 释放由言序 C ABI 返回的字符串。
///
/// # Safety
///
/// `text` 必须为空指针，或是由本库返回且尚未释放的字符串指针。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yanxu_string_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: The function contract requires a pointer from CString::into_raw.
        drop(unsafe { CString::from_raw(text) });
    }
}

fn json_string(value: serde_json::Value) -> *mut c_char {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            "{{\"schema\":{ABI_SCHEMA},\"ok\":false,\"kind\":\"host\",\"message\":\"JSON 序列化失败\"}}"
        )
    });
    CString::new(text)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

fn backend_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Tree => "tree",
        Backend::Bytecode => "bytecode",
    }
}

fn error_kind(kind: EngineErrorKind) -> &'static str {
    match kind {
        EngineErrorKind::Io => "io",
        EngineErrorKind::Frontend => "frontend",
        EngineErrorKind::Type => "type",
        EngineErrorKind::Compile => "compile",
        EngineErrorKind::Runtime => "runtime",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_abi_returns_versioned_json_and_keeps_state() {
        let engine = yanxu_engine_new();
        for (source, expected) in [
            ("令 数值：数 为 4；言 数值；", "4"),
            ("置 数值 为 数值 加 2；言 数值；", "6"),
        ] {
            let source = CString::new(source).unwrap();
            // SAFETY: Test owns both valid pointers for the duration of the call.
            let result = unsafe { yanxu_engine_run(engine, source.as_ptr()) };
            assert!(!result.is_null());
            // SAFETY: The ABI returns a valid NUL-terminated string.
            let parsed: serde_json::Value = unsafe { CStr::from_ptr(result) }
                .to_str()
                .map(|text| serde_json::from_str(text).unwrap())
                .unwrap();
            assert_eq!(parsed["schema"], ABI_SCHEMA);
            assert_eq!(parsed["ok"], true);
            assert_eq!(parsed["output"][0], expected);
            // SAFETY: `result` came from this ABI and is freed exactly once.
            unsafe { yanxu_string_free(result) };
        }
        // SAFETY: `engine` came from this ABI and is freed exactly once.
        unsafe { yanxu_engine_free(engine) };
    }

    #[test]
    fn c_abi_rejects_null_inputs_without_panicking() {
        // SAFETY: Null pointers are explicitly accepted and reported as errors.
        let result = unsafe { yanxu_engine_run(ptr::null_mut(), ptr::null()) };
        // SAFETY: The ABI returns a valid NUL-terminated string.
        let text = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        assert!(text.contains("引擎指针为空"));
        // SAFETY: `result` came from this ABI and is freed exactly once.
        unsafe { yanxu_string_free(result) };
    }
}

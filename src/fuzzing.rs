//! 无状态模糊测试入口；`fuzz/`中的 cargo-fuzz 目标复用这些函数。

use std::path::PathBuf;

const STRUCTURED_INPUT_LIMIT: usize = 64 * 1024;

pub fn frontend(data: &[u8]) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tokens) = crate::lexer::scan_named(source, "<fuzz>") {
        let _ = crate::parser::parse(tokens);
    }
}

pub fn formatting(data: &[u8]) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(statements) = crate::parse_named(source, "<fuzz>") else {
        return;
    };
    let formatted = crate::formatter::format(&statements);
    let reparsed =
        crate::parse_named(&formatted, "<fuzz-formatted>").expect("格式化器不得生成不可解析源码");
    assert_eq!(crate::formatter::format(&reparsed), formatted);
}

pub fn bytecode_archive(data: &[u8]) {
    if let Ok(chunk) = crate::bytecode::deserialize(data) {
        let encoded = crate::bytecode::serialize(&chunk).expect("已验证归档必须能再次序列化");
        crate::bytecode::deserialize(&encoded).expect("重编码归档必须能再次解码");
    }
}

#[doc(hidden)]
pub fn application_archive(data: &[u8]) {
    if let Ok(archive) = crate::application::deserialize(data) {
        let encoded =
            crate::application::serialize(&archive).expect("已验证应用归档必须能再次序列化");
        crate::application::deserialize(&encoded).expect("重编码应用归档必须能再次解码");
    }
}

#[doc(hidden)]
pub fn manifest(data: &[u8]) {
    let Some(path) = structured_input_path("manifest", crate::package::MANIFEST_NAME, data) else {
        return;
    };
    let _ = crate::package::load(path);
}

#[doc(hidden)]
pub fn lockfile(data: &[u8]) {
    let Some(path) = structured_input_path("lock", crate::package::LOCK_NAME, data) else {
        return;
    };
    let _ = crate::package::read_lock(path);
}

#[doc(hidden)]
pub fn engineering_protocol(data: &[u8]) {
    if data.len() > STRUCTURED_INPUT_LIMIT {
        return;
    }
    let Ok(mut request) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    if let Some(object) = request.as_object_mut() {
        let operation = object.get("operation").and_then(serde_json::Value::as_str);
        if !matches!(operation, Some("handshake" | "template")) {
            object.insert(
                "operation".into(),
                serde_json::Value::String("fuzz-unknown-operation".into()),
            );
        }
    }
    let _ = crate::engineering::response(&request);
}

#[cfg(not(target_family = "wasm"))]
#[doc(hidden)]
pub fn native_library(data: &[u8]) {
    if data.len() > STRUCTURED_INPUT_LIMIT {
        return;
    }
    let _ = crate::native_abi_v2::validate_native_library_metadata(data);
}

fn structured_input_path(kind: &str, name: &str, data: &[u8]) -> Option<PathBuf> {
    if data.len() > STRUCTURED_INPUT_LIMIT {
        return None;
    }
    let root = std::env::temp_dir()
        .join("yanxu-fuzz-inputs")
        .join(format!("{kind}-{}", std::process::id()));
    std::fs::create_dir_all(&root).ok()?;
    let path = root.join(name);
    std::fs::write(&path, data).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_regression_seeds_do_not_panic() {
        for seed in [
            &b"\x00\xff\xe8"[..],
            "异 法 求（）：数 则 归 1；终 言 候 求（）；".as_bytes(),
            "令 表 为 {「未闭」：【1，2；".as_bytes(),
            br#"{"format_version":999,"code":[]}"#,
            "[包]\n格式 = 2\n名称 = \"模糊工程\"\n版本 = \"0.1.0\"\n入口 = \"src/主.yx\"\n"
                .as_bytes(),
            "lock_version = 2\nmanifest_checksum = \"0000\"\n".as_bytes(),
            br#"{"protocol_version":1,"operation":"handshake"}"#,
            b"YANXU-YXB-1\n{\"format_version\":999,\"bytecode_format\":2}",
        ] {
            frontend(seed);
            formatting(seed);
            bytecode_archive(seed);
            application_archive(seed);
            manifest(seed);
            lockfile(seed);
            engineering_protocol(seed);
            #[cfg(not(target_family = "wasm"))]
            native_library(seed);
        }

        let deeply_nested = "[".repeat(768);
        frontend(deeply_nested.as_bytes());
        formatting(deeply_nested.as_bytes());
    }
}

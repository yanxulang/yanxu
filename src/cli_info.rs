//! 只读 CLI 能力、版本和标准库报告。

use std::process::ExitCode;

pub(crate) fn version() {
    println!("言序 {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn version_json() -> ExitCode {
    let document = serde_json::json!({
        "schema_version": 2,
        "version": env!("CARGO_PKG_VERSION"),
        "build": yanxu::build_info::identity(),
        "commit_sha": yanxu::build_info::COMMIT_SHA,
        "build_target": yanxu::build_info::TARGET,
        "build_mode": yanxu::build_info::PROFILE,
        "manifest_formats": yanxu::package::SUPPORTED_MANIFEST_FORMATS,
        "lock_formats": yanxu::package::SUPPORTED_LOCK_FORMATS,
        "bytecode_formats": [yanxu::bytecode::BYTECODE_FORMAT_VERSION],
        "yxb_formats": [yanxu::application::YXB_FORMAT_VERSION],
        "native_abi": [yanxu::native_abi::NATIVE_ABI_VERSION, yanxu::native_abi_v2::NATIVE_ABI_VERSION_V2],
        "native_capabilities": {
            "v1": yanxu::native_abi::capabilities(),
            "v2": yanxu::native_abi_v2::capabilities(),
        },
        "permission_capabilities": yanxu::package::PERMISSION_CAPABILITIES,
        "target": yanxu::package::current_target(),
    });
    match serde_json::to_string_pretty(&document) {
        Ok(document) => {
            println!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => failure(format!("不能生成版本握手：{error}")),
    }
}

pub(crate) fn standard_library(json: bool) -> ExitCode {
    let manifest = match yanxu::stdlib::api_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return failure(format!("标准库清单有误：{error}")),
    };
    if json {
        match serde_json::to_string_pretty(&manifest) {
            Ok(manifest) => println!("{manifest}"),
            Err(error) => return failure(format!("不能生成标准库 JSON：{error}")),
        }
    } else if let Some(modules) = manifest["modules"].as_array() {
        for module in modules {
            println!(
                "标准:{}（{} 项，权限：{}）",
                module["name"].as_str().unwrap_or("?"),
                module["members"].as_array().map_or(0, Vec::len),
                module["permissions"]
                    .as_array()
                    .filter(|permissions| !permissions.is_empty())
                    .map(|permissions| {
                        permissions
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<Vec<_>>()
                            .join("、")
                    })
                    .unwrap_or_else(|| "无".into())
            );
        }
    }
    ExitCode::SUCCESS
}

pub(crate) fn native_abi() -> ExitCode {
    let capabilities = serde_json::json!({
        "v1": yanxu::native_abi::capabilities(),
        "v2": yanxu::native_abi_v2::capabilities(),
    });
    match serde_json::to_string_pretty(&capabilities) {
        Ok(document) => {
            println!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => failure(format!("不能生成原生 ABI 能力：{error}")),
    }
}

fn failure(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("{message}");
    ExitCode::FAILURE
}

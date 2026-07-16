//! 包工程、YXB 与 standalone 相关命令。

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use yanxu::budget::ExecutionBudget;
use yanxu::interpreter::Interpreter;
use yanxu::run_file_with;

fn fail(message: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", message.as_ref());
    ExitCode::from(1)
}

static MAX_STEPS_OVERRIDE: OnceLock<u64> = OnceLock::new();

pub(crate) fn set_max_steps_override(max_steps: u64) {
    let _ = MAX_STEPS_OVERRIDE.set(max_steps);
}

pub(crate) fn parse_max_steps(raw: &str) -> Result<u64, String> {
    match raw.trim().parse::<u64>() {
        Ok(max_steps) if max_steps > 0 => Ok(max_steps),
        _ => Err(format!("max_steps 须为正整数，得到“{}”", raw.trim())),
    }
}

/// 命令行 --max-steps 优先，其次 YANXU_MAX_STEPS 环境变量；都未设置时返回 None。
pub(crate) fn configured_budget() -> Result<Option<ExecutionBudget>, String> {
    let max_steps = match MAX_STEPS_OVERRIDE.get() {
        Some(max_steps) => Some(*max_steps),
        None => match env::var("YANXU_MAX_STEPS") {
            Ok(raw) if !raw.trim().is_empty() => Some(parse_max_steps(&raw)?),
            _ => None,
        },
    };
    Ok(max_steps.map(|max_steps| {
        let default = ExecutionBudget::default();
        ExecutionBudget::new(
            max_steps,
            default.max_call_depth,
            default.max_collection_elements,
        )
    }))
}

pub(crate) fn package_info(path: &str) -> ExitCode {
    match yanxu::package::discover(path) {
        Ok(Some(manifest)) => {
            println!("包：{} {}", manifest.name, manifest.version);
            println!("清单格式：{}", manifest.format_version);
            println!("根：{}", manifest.root.display());
            println!("入口：{}", manifest.entry.display());
            for (name, dependency) in &manifest.dependencies {
                println!("依赖：{name} = {dependency}");
            }
            for root in manifest.permissions.file_roots() {
                println!("权限：文件 {}", root.display());
            }
            for host in manifest.permissions.network_hosts() {
                println!("权限：网络 {host}");
            }
            for host in manifest.permissions.tcp_listen_hosts() {
                println!("权限：TCP监听 {host}");
            }
            for host in manifest.permissions.udp_bind_hosts() {
                println!("权限：UDP绑定 {host}");
            }
            for name in manifest.permissions.environment_variables() {
                println!("权限：环境 {name}");
            }
            println!(
                "权限：进程 {}",
                if manifest.permissions.process_allowed() {
                    "允许"
                } else {
                    "拒绝"
                }
            );
            ExitCode::SUCCESS
        }
        Ok(None) => fail(format!("未找到 {}", yanxu::package::MANIFEST_NAME)),
        Err(error) => fail(error.to_string()),
    }
}

pub(crate) fn package_run(path: &str, arguments: &[String]) -> ExitCode {
    let manifest = match yanxu::package::discover(path) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return fail(format!("未找到 {}", yanxu::package::MANIFEST_NAME)),
        Err(error) => return fail(error.to_string()),
    };
    if let Err(error) = yanxu::package::ensure_lock(&manifest, false) {
        return fail(error.to_string());
    }
    let entry = manifest.root.join(&manifest.entry);
    let mut interpreter = Interpreter::with_permissions(manifest.permissions);
    match configured_budget() {
        Ok(Some(budget)) => interpreter.set_budget(budget),
        Ok(None) => {}
        Err(message) => return fail(message),
    }
    interpreter.set_arguments(arguments.to_vec());
    match run_file_with(&mut interpreter, entry) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

pub(crate) fn package_protocol_command(arguments: &[String]) -> ExitCode {
    let Some(request) = arguments.first() else {
        return fail("用法：yanxu package protocol '<JSON请求>'");
    };
    if arguments.len() != 1 {
        return fail("工程协议只接收一个 JSON 请求参数");
    }
    let request: serde_json::Value = match serde_json::from_str(request) {
        Ok(request) => request,
        Err(error) => return fail(format!("工程协议 JSON 无效：{error}")),
    };
    let response = yanxu::engineering::response(&request);
    match serde_json::to_string(&response) {
        Ok(document) => println!("{document}"),
        Err(error) => return fail(format!("不能生成工程协议响应：{error}")),
    }
    if response["ok"].as_bool() == Some(true) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub(crate) fn compile_command(arguments: &[String]) -> ExitCode {
    let Some(input) = arguments.first() else {
        return fail(
            "用法：yanxu compile <文卷或包目录> [-o 输出] [--release] [--standalone|--bundle] [--runtime 路径]",
        );
    };
    let mut output = None;
    let mut profile = "debug";
    let mut standalone = false;
    let mut bundle = false;
    let mut runtime = None;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-o" | "--output" | "--输出" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    return fail("-o 后须给出输出路径");
                };
                output = Some(PathBuf::from(path));
            }
            "--release" | "--发布" => profile = "release",
            "--standalone" | "--独立" => standalone = true,
            "--bundle" | "--应用包" => bundle = true,
            "--runtime" | "--运行时" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    return fail("--runtime 后须给出目标平台言序运行时路径");
                };
                runtime = Some(PathBuf::from(path));
            }
            option => return fail(format!("不识构建选项“{option}”")),
        }
        index += 1;
    }
    if standalone && bundle {
        return fail("--standalone 与 --bundle 不能同时使用");
    }
    if runtime.is_some() && !bundle {
        return fail("--runtime 只可与 --bundle 一同使用");
    }
    let archive = match yanxu::application::compile_application(input, profile) {
        Ok(archive) => archive,
        Err(error) => return fail(error.to_string()),
    };
    let output = match output {
        Some(output) => output,
        None if bundle => match yanxu::gui_bundle::default_output(&archive) {
            Ok(output) => output,
            Err(error) => return fail(error.to_string()),
        },
        None => default_application_output(input, standalone),
    };
    if bundle
        && output.exists()
        && yanxu::gui_bundle::verify_bundle(&output)
            .is_ok_and(|manifest| manifest.yxb_checksum == archive.content_checksum)
    {
        println!("构建缓存命中：{}", output.display());
        return ExitCode::SUCCESS;
    }
    if !standalone
        && !bundle
        && yanxu::application::read_archive(&output)
            .is_ok_and(|existing| existing.content_checksum == archive.content_checksum)
    {
        println!("构建缓存命中：{}", output.display());
        return ExitCode::SUCCESS;
    }
    if bundle {
        let runtime = match runtime.map(Ok).unwrap_or_else(env::current_exe) {
            Ok(runtime) => runtime,
            Err(error) => return fail(format!("不能定位言序运行时：{error}")),
        };
        return match yanxu::gui_bundle::build_bundle(runtime, &archive, &output) {
            Ok(report) => {
                println!("已生成应用 Bundle：{}", report.output.display());
                println!("Bundle 清单：{}", report.manifest.display());
                println!("清单 SHA-256：{}", report.manifest_sha256);
                ExitCode::SUCCESS
            }
            Err(error) => fail(error.to_string()),
        };
    }
    let result = if standalone {
        env::current_exe()
            .map_err(|error| yanxu::application::ApplicationError {
                message: format!("不能定位言序运行时：{error}"),
            })
            .and_then(|runtime| yanxu::application::write_standalone(runtime, &archive, &output))
    } else {
        yanxu::application::write_archive(&archive, &output)
    };
    match result {
        Ok(()) => {
            println!(
                "已生成{}：{}",
                if standalone {
                    "独立应用"
                } else {
                    " YXB 应用"
                },
                output.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error.to_string()),
    }
}

fn default_application_output(input: &str, standalone: bool) -> PathBuf {
    let path = Path::new(input);
    let name = if path.is_dir() {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("应用")
    } else {
        path.file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("应用")
    };
    if standalone {
        let suffix = env::consts::EXE_SUFFIX;
        PathBuf::from(format!("{name}{suffix}"))
    } else {
        PathBuf::from(format!("{name}.yxb"))
    }
}

pub(crate) fn application_run_command(arguments: &[String]) -> ExitCode {
    let Some(path) = arguments.first() else {
        return fail("用法：yanxu run <应用.yxb、文卷或包目录> [-- 参数...]");
    };
    let program_arguments = match arguments.get(1) {
        None => &[][..],
        Some(delimiter) if delimiter == "--" => &arguments[2..],
        Some(option) => return fail(format!("不识运行选项“{option}”")),
    };
    let archive = if Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "yxb")
    {
        match yanxu::application::read_archive(path) {
            Ok(archive) => archive,
            Err(error) => return fail(error.to_string()),
        }
    } else {
        match yanxu::application::compile_application(path, "debug") {
            Ok(archive) => archive,
            Err(error) => return fail(error.to_string()),
        }
    };
    run_archive(&archive, program_arguments)
}

pub(crate) fn run_archive(
    archive: &yanxu::application::ApplicationArchive,
    arguments: &[String],
) -> ExitCode {
    let mut vm = yanxu::vm::Vm::new();
    match configured_budget() {
        Ok(Some(budget)) => vm.set_budget(budget),
        Ok(None) => {}
        Err(message) => return fail(message),
    }
    vm.set_arguments(arguments.to_vec());
    match vm.execute_application(archive) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

pub(crate) fn package_lock(path: &str, update: bool, offline: bool) -> ExitCode {
    let manifest = match yanxu::package::discover(path) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return fail(format!("未找到 {}", yanxu::package::MANIFEST_NAME)),
        Err(error) => return fail(error.to_string()),
    };
    let result = if update {
        yanxu::package::update_lock(&manifest, offline)
    } else {
        yanxu::package::ensure_lock(&manifest, offline)
    };
    match result {
        Ok(dependencies) => {
            println!(
                "已{} {}（{} 项依赖）",
                if update { "更新" } else { "验证" },
                manifest.root.join(yanxu::package::LOCK_NAME).display(),
                dependencies.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error.to_string()),
    }
}

mod cli_info;
mod cli_package;

use cli_package::{
    application_run_command, compile_command, package_info, package_lock, package_protocol_command,
    package_run, run_archive,
};

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use yanxu::ast::StmtKind;
use yanxu::interpreter::Interpreter;
use yanxu::{parse, parse_named, repl, run_file_with};

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if let Ok(executable) = env::current_exe() {
        if let Err(error) = yanxu::gui_bundle::verify_executable_bundle(&executable) {
            return fail(format!("Bundle 校验有误：{error}"));
        }
        match yanxu::application::read_embedded(&executable) {
            Ok(Some(archive)) => return run_archive(&archive, &args),
            Ok(None) => {}
            Err(error) => return fail(error.to_string()),
        }
    }
    if let Err(message) = extract_max_steps_flag(&mut args) {
        return fail(message);
    }
    if args
        .first()
        .is_some_and(|command| command == "编" || command == "compile")
    {
        return compile_command(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|command| command == "行" || command == "run")
    {
        return application_run_command(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|command| command == "包" || command == "package")
        && args
            .get(1)
            .is_some_and(|action| action == "协议" || action == "protocol")
    {
        return package_protocol_command(&args[2..]);
    }
    if args
        .first()
        .is_some_and(|command| command == "试" || command == "test")
    {
        return test_command(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|command| command == "兼容" || command == "compat")
    {
        return compatibility_command(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|command| command == "迁" || command == "migrate")
    {
        return migration_command(&args[1..]);
    }
    match args.as_slice() {
        [] => interactive_repl(),
        [flag] if flag == "-h" || flag == "--help" || flag == "助" => success(help),
        [flag] if flag == "-V" || flag == "--version" || flag == "版" => {
            success(cli_info::version)
        }
        [command, flag]
            if (command == "version" || command == "版本" || command == "版")
                && flag == "--json" =>
        {
            cli_info::version_json()
        }
        [command] if command == "标准库" || command == "stdlib" => {
            cli_info::standard_library(false)
        }
        [command, flag] if (command == "标准库" || command == "stdlib") && flag == "--json" => {
            cli_info::standard_library(true)
        }
        [command, flag] if (command == "原生" || command == "native") && flag == "--json" => {
            cli_info::native_abi()
        }
        [command, path] if command == "查" || command == "check" => check_file(path),
        [command] if command == "包" || command == "package" => package_info("."),
        [command, action]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run") =>
        {
            package_run(".", &[])
        }
        [command, action, delimiter, program_arguments @ ..]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run")
                && delimiter == "--" =>
        {
            package_run(".", program_arguments)
        }
        [command, action, path]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run") =>
        {
            package_run(path, &[])
        }
        [command, action, path, delimiter, program_arguments @ ..]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run")
                && delimiter == "--" =>
        {
            package_run(path, program_arguments)
        }
        [command, action] if (command == "包" || command == "package") && action == "锁" => {
            package_lock(".", false, false)
        }
        [command, action, flag]
            if (command == "包" || command == "package")
                && action == "锁"
                && (flag == "--离线" || flag == "--offline") =>
        {
            package_lock(".", false, true)
        }
        [command, action, flag, path]
            if (command == "包" || command == "package")
                && action == "锁"
                && (flag == "--离线" || flag == "--offline") =>
        {
            package_lock(path, false, true)
        }
        [command, action, path] if (command == "包" || command == "package") && action == "锁" => {
            package_lock(path, false, false)
        }
        [command, action] if (command == "包" || command == "package") && action == "更新" => {
            package_lock(".", true, false)
        }
        [command, action, path]
            if (command == "包" || command == "package") && action == "更新" =>
        {
            package_lock(path, true, false)
        }
        [command, path] if command == "包" || command == "package" => package_info(path),
        [command, path] if command == "字节" || command == "vm" => run_vm(path, false, &[]),
        [command, path, delimiter, program_arguments @ ..]
            if (command == "字节" || command == "vm") && delimiter == "--" =>
        {
            run_vm(path, false, program_arguments)
        }
        [command, flag, path]
            if (command == "字节" || command == "vm")
                && (flag == "--反汇编" || flag == "--disassemble") =>
        {
            run_vm(path, true, &[])
        }
        [command, path] if command == "格" || command == "fmt" => format_file(path, false),
        [command, flag, path]
            if (command == "格" || command == "fmt") && (flag == "--写" || flag == "--write") =>
        {
            format_file(path, true)
        }
        [command] if command == "语言服务" || command == "lsp" => match yanxu::lsp::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(format!("语言服务有误：{error}")),
        },
        [command] if command == "调试服务" || command == "dap" => {
            match yanxu::debugger::serve() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(format!("调试服务有误：{error}")),
            }
        }
        [command] if command == "基准" || command == "bench" => benchmark(10),
        [command, iterations] if command == "基准" || command == "bench" => {
            match iterations.parse::<usize>() {
                Ok(iterations) => benchmark(iterations),
                Err(_) => fail("基准轮数须为正整数"),
            }
        }
        [command, path] if command == "调" || command == "debug" => debug_file(path),
        [command, flag, path] if (command == "文" || command == "doc") && flag == "--json" => {
            document_json(path, None)
        }
        [command, flag, path, output]
            if (command == "文" || command == "doc") && flag == "--json" =>
        {
            document_json(path, Some(output))
        }
        [command, path] if command == "文" || command == "doc" => document_file(path, None),
        [command, path, output] if command == "文" || command == "doc" => {
            document_file(path, Some(output))
        }
        [path] => run_file(path, &[]),
        [path, delimiter, program_arguments @ ..] if delimiter == "--" => {
            run_file(path, program_arguments)
        }
        _ => fail("用法有误。可用 `yanxu --help` 查看说明。"),
    }
}

fn success(action: fn()) -> ExitCode {
    action();
    ExitCode::SUCCESS
}

/// 从命令参数中剥离全局旗标 --max-steps（`--` 之后的程序参数不受影响）。
fn extract_max_steps_flag(args: &mut Vec<String>) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--" {
            break;
        }
        if let Some(raw) = args[index].strip_prefix("--max-steps=") {
            let max_steps = cli_package::parse_max_steps(raw)?;
            args.remove(index);
            cli_package::set_max_steps_override(max_steps);
            return Ok(());
        }
        if args[index] == "--max-steps" {
            let Some(raw) = args.get(index + 1) else {
                return Err("--max-steps 需要一个正整数参数".into());
            };
            let max_steps = cli_package::parse_max_steps(raw)?;
            args.drain(index..index + 2);
            cli_package::set_max_steps_override(max_steps);
            return Ok(());
        }
        index += 1;
    }
    Ok(())
}

fn fail(message: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", message.as_ref());
    ExitCode::from(1)
}

fn run_file(path: &str, arguments: &[String]) -> ExitCode {
    let mut interpreter = Interpreter::new();
    match cli_package::configured_budget() {
        Ok(Some(budget)) => interpreter.set_budget(budget),
        Ok(None) => {}
        Err(message) => return fail(message),
    }
    interpreter.set_arguments(arguments.to_vec());
    match run_file_with(&mut interpreter, path) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn check_file(path: &str) -> ExitCode {
    let (canonical, source, statements) = match source_file(path) {
        Ok(result) => result,
        Err(error) => return fail(error),
    };
    for finding in yanxu::migration::analyze(&source) {
        eprintln!("{}", finding.render(path));
    }
    match yanxu::type_checker::check_in_directory(
        &statements,
        canonical.parent().unwrap_or_else(|| Path::new(".")),
    ) {
        Ok(()) => {
            println!("类型检查通过：{path}");
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            ExitCode::from(1)
        }
    }
}

fn run_vm(path: &str, disassemble: bool, arguments: &[String]) -> ExitCode {
    let (canonical, _, statements) = match source_file(path) {
        Ok(result) => result,
        Err(error) => return fail(error),
    };
    let chunk = match yanxu::bytecode::compile(&statements) {
        Ok(chunk) => chunk,
        Err(error) => return fail(error.to_string()),
    };
    if disassemble {
        println!("{}", chunk.disassemble());
    }
    let mut vm = yanxu::vm::Vm::new();
    match cli_package::configured_budget() {
        Ok(Some(budget)) => vm.set_budget(budget),
        Ok(None) => {}
        Err(message) => return fail(message),
    }
    vm.set_arguments(arguments.to_vec());
    match vm.execute_in_directory(&chunk, canonical.parent().unwrap_or_else(|| Path::new("."))) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn format_file(path: &str, write: bool) -> ExitCode {
    let (canonical, _, statements) = match source_file(path) {
        Ok(result) => result,
        Err(error) => return fail(error),
    };
    let formatted = yanxu::formatter::format(&statements);
    if write {
        match fs::write(&canonical, formatted) {
            Ok(()) => {
                println!("已格式化：{}", canonical.display());
                ExitCode::SUCCESS
            }
            Err(error) => fail(format!("不能写入“{}”：{error}", canonical.display())),
        }
    } else {
        print!("{formatted}");
        ExitCode::SUCCESS
    }
}

fn test_command(arguments: &[String]) -> ExitCode {
    let mut path = "spec";
    let mut options = yanxu::testing::TestOptions::default();
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--筛" | "--filter" => {
                index += 1;
                let Some(filter) = arguments.get(index) else {
                    return fail("--筛/--filter 后须有文字");
                };
                options.filter = Some(filter.clone());
            }
            "--并发" | "--jobs" => {
                index += 1;
                let Some(jobs) = arguments
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return fail("--并发/--jobs 后须为正整数");
                };
                options.jobs = jobs;
            }
            "--超时" | "--timeout" => {
                index += 1;
                let Some(milliseconds) = arguments
                    .get(index)
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    return fail("--超时/--timeout 后须为毫秒数");
                };
                options.timeout = Duration::from_millis(milliseconds);
            }
            "--json" => json = true,
            argument if argument.starts_with('-') => {
                return fail(format!("不识测试选项“{argument}”"));
            }
            argument if path == "spec" => path = argument,
            argument => return fail(format!("多余测试路径“{argument}”")),
        }
        index += 1;
    }
    test_path(path, &options, json)
}

fn compatibility_command(arguments: &[String]) -> ExitCode {
    let mut path = "compat";
    let mut json = false;
    for argument in arguments {
        match argument.as_str() {
            "--json" => json = true,
            argument if argument.starts_with('-') => {
                return fail(format!("不识兼容选项“{argument}”"));
            }
            argument if path == "compat" => path = argument,
            argument => return fail(format!("多余兼容路径“{argument}”")),
        }
    }
    match yanxu::compatibility::run(path) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(report) => println!("{report}"),
                    Err(error) => return fail(format!("不能生成兼容 JSON：{error}")),
                }
            } else {
                println!("{}", report.human());
            }
            if report.is_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => fail(error),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MigrationMode {
    Check,
    Diff,
    Write,
}

fn migration_command(arguments: &[String]) -> ExitCode {
    let mut path = None;
    let mut mode = MigrationMode::Diff;
    for argument in arguments {
        match argument.as_str() {
            "--检查" | "--check" => mode = MigrationMode::Check,
            "--差异" | "--diff" => mode = MigrationMode::Diff,
            "--写" | "--write" => mode = MigrationMode::Write,
            argument if argument.starts_with('-') => {
                return fail(format!("不识迁移选项“{argument}”"));
            }
            argument if path.is_none() => path = Some(argument),
            argument => return fail(format!("多余迁移路径“{argument}”")),
        }
    }
    let Some(path) = path else {
        return fail("迁移须给出 .yx 文卷路径");
    };
    let (canonical, source) = match module_source_file(Path::new(path)) {
        Ok(source) => source,
        Err(error) => return fail(error),
    };
    let (migrated, findings) = yanxu::migration::migrate(&source);
    if findings.is_empty() {
        println!("无需迁移：{path}");
        return ExitCode::SUCCESS;
    }
    for finding in &findings {
        println!("{}", finding.render(path));
    }
    match mode {
        MigrationMode::Check => ExitCode::from(1),
        MigrationMode::Diff => {
            println!("--- {path}\n+++ {path}（迁移后）");
            for (before, after) in source.lines().zip(migrated.lines()) {
                if before != after {
                    println!("-{before}\n+{after}");
                }
            }
            ExitCode::SUCCESS
        }
        MigrationMode::Write => match fs::write(&canonical, migrated) {
            Ok(()) => {
                println!("已迁移：{path}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(format!("不能写入“{path}”：{error}")),
        },
    }
}

fn test_path(path: &str, options: &yanxu::testing::TestOptions, json: bool) -> ExitCode {
    match yanxu::testing::run_with_options(path, options) {
        Ok(results) if results.is_empty() => fail(format!("未在“{path}”找到 .yx 测试")),
        Ok(results) => {
            let failed = results.iter().filter(|result| !result.passed).count();
            if json {
                println!("{}", yanxu::testing::machine_report(&results));
            } else {
                for result in &results {
                    println!(
                        "{} {}（{} ms）— {}",
                        result.status.label(),
                        result.path.display(),
                        result.duration_ms,
                        result.detail
                    );
                }
                println!(
                    "共 {} 卷，{} 成，{} 败",
                    results.len(),
                    results.len() - failed,
                    failed
                );
            }
            if failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => fail(error),
    }
}

fn debug_file(path: &str) -> ExitCode {
    let mut interpreter = Interpreter::debug();
    let result = run_file_with(&mut interpreter, path);
    eprintln!("—— 执行踪迹 ——");
    for event in interpreter.trace() {
        eprintln!("{event}");
    }
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn benchmark(iterations: usize) -> ExitCode {
    match yanxu::benchmark::compare(iterations) {
        Ok(report) => {
            println!("轮数：{}", report.iterations);
            println!("解析：{:.3} ms", report.parse_time.as_secs_f64() * 1_000.0);
            println!(
                "编译：{:.3} ms",
                report.compile_time.as_secs_f64() * 1_000.0
            );
            println!(
                "树解释器：{:.3} ms",
                report.interpreter_time.as_secs_f64() * 1_000.0
            );
            println!(
                "字节码 VM：{:.3} ms",
                report.vm_time.as_secs_f64() * 1_000.0
            );
            println!("VM 相对倍数：{:.2}x", report.vm_speed_ratio());
            println!("校验输出：{:?}", report.output);
            ExitCode::SUCCESS
        }
        Err(error) => fail(format!("基准有误：{error}")),
    }
}

fn document_file(path: &str, output: Option<&str>) -> ExitCode {
    let input = Path::new(path);
    let markdown = if let Some(directory) = document_directory(input) {
        match yanxu::docgen::markdown_directory(directory) {
            Ok(markdown) => markdown,
            Err(error) => return fail(error),
        }
    } else {
        let (canonical, _, statements) = match source_file(path) {
            Ok(result) => result,
            Err(error) => return fail(error),
        };
        let name = canonical
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("无名模块");
        match yanxu::docgen::markdown_in_directory(
            name,
            &statements,
            canonical.parent().unwrap_or_else(|| Path::new(".")),
        ) {
            Ok(markdown) => markdown,
            Err(error) => return fail(error),
        }
    };
    if let Some(output) = output {
        match fs::write(output, markdown) {
            Ok(()) => {
                println!("已生成：{output}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(format!("不能写入“{output}”：{error}")),
        }
    } else {
        print!("{markdown}");
        ExitCode::SUCCESS
    }
}

fn document_json(path: &str, output: Option<&str>) -> ExitCode {
    let input = Path::new(path);
    if document_directory(input).is_some() {
        return fail("yanxu 文 --json 当前要求单个模块文卷");
    }
    let (canonical, _, statements) = match source_file(path) {
        Ok(result) => result,
        Err(error) => return fail(error),
    };
    let name = canonical
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("无名模块");
    let manifest = match yanxu::docgen::api_manifest_in_directory(
        name,
        &statements,
        canonical.parent().unwrap_or_else(|| Path::new(".")),
    ) {
        Ok(manifest) => manifest,
        Err(error) => return fail(error),
    };
    let document = match serde_json::to_string_pretty(&manifest) {
        Ok(document) => document + "\n",
        Err(error) => return fail(format!("不能生成 API JSON：{error}")),
    };
    if let Some(output) = output {
        match fs::write(output, document) {
            Ok(()) => {
                println!("已生成：{output}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(format!("不能写入“{output}”：{error}")),
        }
    } else {
        print!("{document}");
        ExitCode::SUCCESS
    }
}

fn document_directory(input: &Path) -> Option<PathBuf> {
    match fs::symlink_metadata(input) {
        Ok(metadata) => return metadata.is_dir().then(|| input.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }

    let absolute = if input.is_absolute() {
        input.to_path_buf()
    } else {
        env::current_dir().ok()?.join(input)
    };
    let manifest = yanxu::package::discover(&absolute).ok()??;
    let relative = absolute.strip_prefix(&manifest.root).ok()?;
    let resolved = yanxu::package::resolve_existing_package_path(
        &manifest.root,
        relative,
        yanxu::package::PackagePathPurpose::ManifestReference,
    )
    .ok()?;
    fs::symlink_metadata(&resolved)
        .ok()?
        .is_dir()
        .then_some(resolved)
}

fn source_file(path: &str) -> Result<(PathBuf, String, Vec<yanxu::ast::Stmt>), String> {
    let (canonical, source) = module_source_file(Path::new(path))?;
    let statements =
        parse_named(&source, canonical.display().to_string()).map_err(|error| error.to_string())?;
    Ok((canonical, source, statements))
}

fn module_source_file(requested: &Path) -> Result<(PathBuf, String), String> {
    let requested_absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("不能定位当前目录：{error}"))?
            .join(requested)
    };
    let current_base = requested_absolute
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut roots = yanxu::package::TrustedPackageRoots::default();
    let (resolved, _) = roots
        .resolve_import_file(current_base, &requested_absolute, false)
        .map_err(module_manifest_error)?;
    let canonical = resolved.path().to_path_buf();
    let resolved = resolved.open().map_err(module_manifest_error)?;
    let source = yanxu::package::read_resolved_module_source_snapshot(resolved)
        .map_err(|error| format!("不能读取“{}”：{error}", canonical.display()))?;
    Ok((canonical, source))
}

fn module_manifest_error(error: yanxu::package::ManifestError) -> String {
    if error.code() == "PACKAGE000" {
        error.to_string()
    } else {
        format!(
            "[{}] {}：{}",
            error.code(),
            error.path.display(),
            error.diagnostic_message()
        )
    }
}

fn interactive_repl() -> ExitCode {
    println!(
        "言序 {} —— 可输入多行文句；输入 :助 查看命令",
        env!("CARGO_PKG_VERSION")
    );
    let mut interpreter = Interpreter::new();
    let mut history = repl::load_history();
    let mut editor = match repl::line_editor(&history) {
        Ok(editor) => editor,
        Err(error) => return fail(format!("不能启动终端行编辑：{error}")),
    };

    loop {
        match editor.readline("言序〉") {
            Ok(source) if source.trim_start().starts_with(':') => {
                if handle_command(source.trim(), &mut interpreter, &history) {
                    let _ = editor.save_history(&repl::history_path());
                    return ExitCode::SUCCESS;
                }
            }
            Ok(source) => {
                if source.trim().is_empty() {
                    continue;
                }
                execute_repl_entry(&mut interpreter, &source);
                if let Some(helper) = editor.helper_mut() {
                    helper.observe(&source);
                }
                let _ = editor.add_history_entry(source.as_str());
                history.push(source.trim().into());
                let _ = editor.save_history(&repl::history_path());
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("^C");
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                let _ = editor.save_history(&repl::history_path());
                println!();
                return ExitCode::SUCCESS;
            }
            Err(error) => return fail(format!("读取有误：{error}")),
        }
    }
}

fn execute_repl_entry(interpreter: &mut Interpreter, source: &str) {
    match parse(source) {
        Ok(statements) => {
            let show_result = statements
                .last()
                .is_some_and(|statement| matches!(statement.kind, StmtKind::Expression(_)));
            match interpreter.execute(&statements) {
                Ok(value) if show_result => println!("⇒ {value}"),
                Ok(_) => {}
                Err(error) => eprintln!("{error}"),
            }
        }
        Err(error) => eprintln!("{error}"),
    }
}

/// 返回 `true` 表示退出 REPL。
fn handle_command(command: &str, interpreter: &mut Interpreter, history: &[String]) -> bool {
    match command {
        ":退" | ":quit" | ":q" => true,
        ":助" | ":help" | ":h" => {
            println!(
                ":助              显示此说明\n:退              离开\n:清              清空上下文\n:载 <文卷.yx>    在当前上下文运行\n:史              显示最近历史\n:补 <前缀>       列出补全候选"
            );
            false
        }
        ":清" | ":clear" => {
            *interpreter = Interpreter::new();
            println!("上下文已清。");
            false
        }
        ":史" | ":history" => {
            for (index, entry) in history.iter().rev().take(20).rev().enumerate() {
                println!("{:>3}  {}", index + 1, entry.replace('\n', " "));
            }
            false
        }
        command if command.starts_with(":补 ") || command.starts_with(":complete ") => {
            let prefix = command
                .split_once(' ')
                .map(|(_, value)| value)
                .unwrap_or("");
            println!("{}", repl::completions(prefix, history).join("  "));
            false
        }
        command if command.starts_with(":载 ") || command.starts_with(":load ") => {
            let path = command
                .split_once(' ')
                .map(|(_, path)| path.trim())
                .unwrap_or("");
            if path.is_empty() {
                eprintln!("须给出文卷路径。");
            } else if let Err(error) = run_file_with(interpreter, path) {
                eprintln!("{error}");
            }
            false
        }
        _ => {
            eprintln!("不识命令“{command}”；输入 :助 查看说明。");
            false
        }
    }
}

fn help() {
    println!(
        r#"言序——文言风格的解释型编程语言

用法：
  yanxu [文卷.yx] [-- 参数...]  以树解释器执行（兼容模式，不限制宿主能力）
  yanxu 查 <文卷>        静态类型检查并报告弃用
  yanxu 字节 <文卷> [-- 参数...]  以字节码 VM 执行
  yanxu 编 <文卷或包目录> [-o 输出] [--release] [--standalone|--bundle]
                         编译完整 YXB、独立程序或当前平台桌面应用 Bundle
  yanxu 行 <应用.yxb、文卷或包目录> [-- 参数...]
                         以字节码 VM 运行预编译应用
  yanxu 格 [--写] <文卷>  格式化
  yanxu 试 [目录] [--筛 词] [--并发 N] [--超时 ms] [--json]
                         运行 .yx 规格测试
  yanxu 兼容 [目录] [--json]  对照树解释器与 VM 的版本语料
  yanxu 迁 [--检查|--差异|--写] <文卷>  检查或应用弃用迁移
  yanxu 版本 --json       显示版本、构建、格式、ABI 与权限能力
  yanxu 标准库 [--json]   显示版本化标准库 API 清单
  yanxu 原生 --json       显示原生扩展 ABI v1/v2 能力
  yanxu 包 [路径]          显示包清单
  yanxu 包 运行 [路径] [-- 参数...]  按清单权限运行包入口
  yanxu 包 锁 [--离线] [路径]  生成或验证锁文件
  yanxu 包 协议 '<JSON>'   言包使用的版本化工程协议
  yanxu 文 [--json] <文卷> [输出]  生成公开 API 文档或机器清单
  yanxu 调 <文卷>          执行并输出踪迹
  yanxu 调试服务          启动 DAP 调试适配器
  yanxu 基准 [轮数]       比较树解释器与 VM
  yanxu 语言服务          启动 LSP stdio 服务

全局旗标 --max-steps <N>（或环境变量 YANXU_MAX_STEPS）设置单次执行/单个事件回调的步数预算，默认 1000000。
程序参数通过 `--` 与言序命令分隔，并由 `标准:环境.参数（）` 读取。
不带参数时进入带历史与补全的多行 REPL。"#
    );
    println!("\n包项目的创建、依赖增删与安装请使用独立官方工具 yanbao。");
}

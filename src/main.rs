use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use yanxu::ast::StmtKind;
use yanxu::interpreter::Interpreter;
use yanxu::{parse, parse_named, repl, run_file_with};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
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
        [flag] if flag == "-V" || flag == "--version" || flag == "版" => success(version),
        [command] if command == "标准库" || command == "stdlib" => standard_library_info(false),
        [command, flag] if (command == "标准库" || command == "stdlib") && flag == "--json" => {
            standard_library_info(true)
        }
        [command, path] if command == "查" || command == "check" => check_file(path),
        [command] if command == "包" || command == "package" => package_info("."),
        [command, action]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run") =>
        {
            package_run(".")
        }
        [command, action, path]
            if (command == "包" || command == "package")
                && (action == "运行" || action == "run") =>
        {
            package_run(path)
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
        [command, path] if command == "字节" || command == "vm" => run_vm(path, false),
        [command, flag, path]
            if (command == "字节" || command == "vm")
                && (flag == "--反汇编" || flag == "--disassemble") =>
        {
            run_vm(path, true)
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
        [command, path] if command == "文" || command == "doc" => document_file(path, None),
        [command, path, output] if command == "文" || command == "doc" => {
            document_file(path, Some(output))
        }
        [path] => run_file(path),
        _ => fail("用法有误。可用 `yanxu --help` 查看说明。"),
    }
}

fn success(action: fn()) -> ExitCode {
    action();
    ExitCode::SUCCESS
}

fn fail(message: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", message.as_ref());
    ExitCode::from(1)
}

fn run_file(path: &str) -> ExitCode {
    let mut interpreter = Interpreter::new();
    match run_file_with(&mut interpreter, path) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn check_file(path: &str) -> ExitCode {
    let (canonical, statements) = match source_file(path) {
        Ok(result) => result,
        Err(error) => return fail(error),
    };
    if let Ok(source) = fs::read_to_string(&canonical) {
        for finding in yanxu::migration::analyze(&source) {
            eprintln!("{}", finding.render(path));
        }
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

fn package_info(path: &str) -> ExitCode {
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

fn standard_library_info(json: bool) -> ExitCode {
    let manifest = match yanxu::stdlib::api_manifest() {
        Ok(manifest) => manifest,
        Err(error) => return fail(format!("标准库清单有误：{error}")),
    };
    if json {
        match serde_json::to_string_pretty(&manifest) {
            Ok(manifest) => println!("{manifest}"),
            Err(error) => return fail(format!("不能生成标准库 JSON：{error}")),
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

fn package_run(path: &str) -> ExitCode {
    let manifest = match yanxu::package::discover(path) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return fail(format!("未找到 {}", yanxu::package::MANIFEST_NAME)),
        Err(error) => return fail(error.to_string()),
    };
    let entry = manifest.root.join(&manifest.entry);
    let mut interpreter = Interpreter::with_permissions(manifest.permissions);
    match run_file_with(&mut interpreter, entry) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn package_lock(path: &str, update: bool, offline: bool) -> ExitCode {
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

fn run_vm(path: &str, disassemble: bool) -> ExitCode {
    let (canonical, statements) = match source_file(path) {
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
    match vm.execute_in_directory(&chunk, canonical.parent().unwrap_or_else(|| Path::new("."))) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => fail(error.to_string()),
    }
}

fn format_file(path: &str, write: bool) -> ExitCode {
    let (canonical, statements) = match source_file(path) {
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
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => return fail(format!("不能读取“{path}”：{error}")),
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
        MigrationMode::Write => match fs::write(path, migrated) {
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
    let markdown = if input.is_dir() {
        match yanxu::docgen::markdown_directory(input) {
            Ok(markdown) => markdown,
            Err(error) => return fail(error),
        }
    } else {
        let (canonical, statements) = match source_file(path) {
            Ok(result) => result,
            Err(error) => return fail(error),
        };
        let name = canonical
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("无名模块");
        yanxu::docgen::markdown(name, &statements)
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

fn source_file(path: &str) -> Result<(PathBuf, Vec<yanxu::ast::Stmt>), String> {
    let path = Path::new(path);
    let canonical =
        fs::canonicalize(path).map_err(|error| format!("不能定位“{}”：{error}", path.display()))?;
    let source = fs::read_to_string(&canonical)
        .map_err(|error| format!("不能读取“{}”：{error}", canonical.display()))?;
    let statements =
        parse_named(&source, canonical.display().to_string()).map_err(|error| error.to_string())?;
    Ok((canonical, statements))
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

fn version() {
    println!("言序 {}", env!("CARGO_PKG_VERSION"));
}

fn help() {
    println!(
        "言序——文言风格的解释型编程语言\n\n用法：\n  yanxu [文卷.yx]       以树解释器执行（兼容模式，不限制宿主能力）\n  yanxu 查 <文卷>        静态类型检查并报告弃用\n  yanxu 字节 <文卷>      以字节码 VM 执行\n  yanxu 格 [--写] <文卷>  格式化\n  yanxu 试 [目录] [--筛 词] [--并发 N] [--超时 ms] [--json]\n                         运行 .yx 规格测试\n  yanxu 兼容 [目录] [--json]  对照树解释器与 VM 的版本语料\n  yanxu 迁 [--检查|--差异|--写] <文卷>  检查或应用弃用迁移\n  yanxu 标准库 [--json]   显示版本化标准库 API 清单\n  yanxu 包 [路径]          显示包清单\n  yanxu 包 运行 [路径]     按清单权限运行包入口\n  yanxu 包 锁 [--离线] [路径]  生成或验证锁文件\n  yanxu 文 <文卷> [输出]  生成公开 API 文档\n  yanxu 调 <文卷>          执行并输出踪迹\n  yanxu 调试服务          启动 DAP 调试适配器\n  yanxu 基准 [轮数]       比较树解释器与 VM\n  yanxu 语言服务          启动 LSP stdio 服务\n\n不带参数时进入带历史与补全的多行 REPL。"
    );
    println!("\n包项目的创建、依赖增删与安装请使用独立官方工具 yanbao。");
}

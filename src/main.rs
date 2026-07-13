use std::env;
use std::io::{self, Write};
use std::process::ExitCode;
use yanxu::ast::Stmt;
use yanxu::interpreter::Interpreter;
use yanxu::{parse, repl::needs_more_input, run_file_with};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => repl(),
        [flag] if flag == "-h" || flag == "--help" => {
            help();
            ExitCode::SUCCESS
        }
        [flag] if flag == "-V" || flag == "--version" => {
            println!("言序 {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [path] => run_file(path),
        _ => {
            eprintln!("用法有误。可用 `yanxu --help` 查看说明。");
            ExitCode::from(2)
        }
    }
}

fn run_file(path: &str) -> ExitCode {
    let mut interpreter = Interpreter::new();
    match run_file_with(&mut interpreter, path) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn repl() -> ExitCode {
    println!(
        "言序 {} —— 可输入多行文句；输入 :助 查看命令",
        env!("CARGO_PKG_VERSION")
    );
    let mut interpreter = Interpreter::new();
    let stdin = io::stdin();
    let mut buffer = String::new();

    loop {
        print!(
            "{}",
            if buffer.is_empty() {
                "言序〉"
            } else {
                "续  〉"
            }
        );
        if io::stdout().flush().is_err() {
            return ExitCode::from(1);
        }

        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => {
                if !buffer.trim().is_empty() {
                    eprintln!("文句未完，未予执行。");
                }
                println!();
                return ExitCode::SUCCESS;
            }
            Ok(_) if buffer.is_empty() && line.trim_start().starts_with(':') => {
                if handle_command(line.trim(), &mut interpreter) {
                    return ExitCode::SUCCESS;
                }
            }
            Ok(_) => {
                buffer.push_str(&line);
                if needs_more_input(&buffer) {
                    continue;
                }
                execute_repl_entry(&mut interpreter, &buffer);
                buffer.clear();
            }
            Err(error) => {
                eprintln!("读取有误：{error}");
                return ExitCode::from(1);
            }
        }
    }
}

fn execute_repl_entry(interpreter: &mut Interpreter, source: &str) {
    match parse(source) {
        Ok(statements) => {
            let show_result = matches!(statements.last(), Some(Stmt::Expression(_)));
            match interpreter.execute(&statements) {
                Ok(value) if show_result => println!("⇒ {value}"),
                Ok(_) => {}
                Err(error) => eprintln!("运行有误：{error}"),
            }
        }
        Err(error) => eprintln!("{error}"),
    }
}

/// 返回 `true` 表示退出 REPL。
fn handle_command(command: &str, interpreter: &mut Interpreter) -> bool {
    match command {
        ":退" | ":quit" | ":q" => true,
        ":助" | ":help" | ":h" => {
            println!(
                ":助 / :help       显示此说明\n:退 / :quit       离开\n:清 / :clear      清空当前上下文\n:载 <文卷.yx>     在当前上下文运行文卷"
            );
            false
        }
        ":清" | ":clear" => {
            *interpreter = Interpreter::new();
            println!("上下文已清。");
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
        "言序——文言风格的解释型编程语言\n\n用法：\n  yanxu [文卷.yx]\n  yanxu --help\n  yanxu --version\n\n不带文卷时进入多行交互环境。"
    );
}

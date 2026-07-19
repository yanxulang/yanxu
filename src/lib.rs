pub mod application;
pub mod ast;
pub mod benchmark;
pub mod budget;
pub mod build_info;
pub mod bytecode;
pub mod compatibility;
pub mod debugger;
pub mod docgen;
pub mod embed;
pub mod engineering;
pub mod ffi;
pub mod formatter;
pub mod fuzzing;
pub mod gui_bundle;
pub mod host_events;
pub mod host_handles;
pub mod interpreter;
pub mod lexer;
pub mod lsp;
pub mod migration;
pub mod native_abi;
pub mod native_abi_v2;
pub mod package;
pub mod parser;
pub mod permissions;
#[cfg(not(target_family = "wasm"))]
pub mod repl;
pub mod resolver;
pub mod semantic;
pub mod source;
pub mod stdlib;
pub mod testing;
pub mod token;
pub mod type_checker;
pub mod type_model;
pub mod vm;
pub mod wasm;

use interpreter::{Interpreter, RuntimeError, Value};
use lexer::LexError;
use parser::ParseError;
use resolver::SemanticError;
use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub enum YanxuError {
    Lex(LexError),
    Parse(ParseError),
    Runtime(RuntimeError),
    Semantic(SemanticError),
    Io(String),
}

impl fmt::Display for YanxuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lex(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::Runtime(error) => write!(f, "{error}"),
            Self::Semantic(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "文卷有误：{error}"),
        }
    }
}

impl std::error::Error for YanxuError {}

pub fn parse(source: &str) -> Result<Vec<ast::Stmt>, YanxuError> {
    parse_named(source, "<文句>")
}

pub fn parse_named(source: &str, name: impl Into<String>) -> Result<Vec<ast::Stmt>, YanxuError> {
    let tokens = lexer::scan_named(source, name).map_err(YanxuError::Lex)?;
    let statements = parser::parse(tokens).map_err(YanxuError::Parse)?;
    resolver::resolve(&statements).map_err(YanxuError::Semantic)?;
    Ok(statements)
}

pub fn run(source: &str) -> Result<Value, YanxuError> {
    let statements = parse(source)?;
    let mut interpreter = Interpreter::new();
    interpreter
        .execute(&statements)
        .map_err(YanxuError::Runtime)
}

pub fn run_with(interpreter: &mut Interpreter, source: &str) -> Result<Value, YanxuError> {
    let statements = parse(source)?;
    interpreter
        .execute(&statements)
        .map_err(YanxuError::Runtime)
}

pub fn run_file(path: impl AsRef<Path>) -> Result<Value, YanxuError> {
    let mut interpreter = Interpreter::new();
    run_file_with(&mut interpreter, path)
}

pub fn run_file_with(
    interpreter: &mut Interpreter,
    path: impl AsRef<Path>,
) -> Result<Value, YanxuError> {
    let path = path.as_ref();
    let resolved = resolve_module_file_path(path).map_err(YanxuError::Io)?;
    let canonical = resolved.path().to_path_buf();
    let resolved = resolved
        .open()
        .map_err(|error| YanxuError::Io(module_manifest_error(error)))?;
    let source = package::read_resolved_module_source_snapshot(resolved)
        .map_err(|error| YanxuError::Io(format!("不能读取“{}”：{error}", canonical.display())))?;
    let statements = parse_named(&source, canonical.display().to_string())?;
    let directory = canonical.parent().unwrap_or_else(|| Path::new("."));
    interpreter
        .execute_in_directory(&statements, directory)
        .map_err(YanxuError::Runtime)
}

pub(crate) fn resolve_module_file_path(
    requested: &Path,
) -> Result<package::ResolvedImportFile, String> {
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
    let mut roots = package::TrustedPackageRoots::default();
    roots
        .resolve_import_file(current_base, &requested_absolute, false)
        .map(|(resolved, _)| resolved)
        .map_err(module_manifest_error)
}

fn module_manifest_error(error: package::ManifestError) -> String {
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

pub mod ast;
pub mod interpreter;
pub mod lexer;
pub mod parser;
pub mod repl;
pub mod resolver;
pub mod token;

use interpreter::{Interpreter, RuntimeError, Value};
use lexer::LexError;
use parser::ParseError;
use resolver::SemanticError;
use std::fmt;
use std::fs;
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
            Self::Lex(error) => write!(f, "词法有误：{error}"),
            Self::Parse(error) => write!(f, "语法有误：{error}"),
            Self::Runtime(error) => write!(f, "运行有误：{error}"),
            Self::Semantic(error) => write!(f, "语义有误：{error}"),
            Self::Io(error) => write!(f, "文卷有误：{error}"),
        }
    }
}

impl std::error::Error for YanxuError {}

pub fn parse(source: &str) -> Result<Vec<ast::Stmt>, YanxuError> {
    let tokens = lexer::scan(source).map_err(YanxuError::Lex)?;
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
    let canonical = fs::canonicalize(path)
        .map_err(|error| YanxuError::Io(format!("不能定位“{}”：{error}", path.display())))?;
    let source = fs::read_to_string(&canonical)
        .map_err(|error| YanxuError::Io(format!("不能读取“{}”：{error}", canonical.display())))?;
    let statements = parse(&source)?;
    let directory = canonical.parent().unwrap_or_else(|| Path::new("."));
    interpreter
        .execute_in_directory(&statements, directory)
        .map_err(YanxuError::Runtime)
}

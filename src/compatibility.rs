//! 跨版本、跨执行器兼容语料运行器。

use crate::bytecode;
use crate::interpreter::Interpreter;
use crate::vm::Vm;
use serde::Serialize;
use std::path::Path;

pub const COMPATIBILITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeOutcome {
    pub succeeded: bool,
    pub value: Option<String>,
    pub output: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityCase {
    pub path: String,
    pub passed: bool,
    pub detail: String,
    pub tree: RuntimeOutcome,
    pub bytecode: RuntimeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityReport {
    pub schema: &'static str,
    pub schema_version: u32,
    pub language_version: &'static str,
    pub cases: Vec<CompatibilityCase>,
}

impl CompatibilityReport {
    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|case| case.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.cases.len() - self.passed()
    }

    pub fn is_success(&self) -> bool {
        !self.cases.is_empty() && self.failed() == 0
    }

    pub fn human(&self) -> String {
        let mut lines = self
            .cases
            .iter()
            .map(|case| {
                format!(
                    "{} {} — {}",
                    if case.passed { "成" } else { "败" },
                    case.path,
                    case.detail
                )
            })
            .collect::<Vec<_>>();
        lines.push(format!(
            "兼容语料共 {} 卷，{} 成，{} 败（报告格式 {}）",
            self.cases.len(),
            self.passed(),
            self.failed(),
            self.schema_version
        ));
        lines.join("\n")
    }
}

pub fn run(root: impl AsRef<Path>) -> Result<CompatibilityReport, String> {
    let requested = root.as_ref();
    let (root, paths) = crate::testing::discover_with_root(requested)?;
    if paths.is_empty() {
        return Err(format!("未在“{}”找到兼容语料", root.display()));
    }
    let cases = paths
        .iter()
        .map(|path| run_case(&root, path))
        .collect::<Vec<_>>();
    Ok(CompatibilityReport {
        schema: "https://yanxu.dev/schemas/compatibility-report-v1.json",
        schema_version: COMPATIBILITY_SCHEMA_VERSION,
        language_version: env!("CARGO_PKG_VERSION"),
        cases,
    })
}

fn run_case(root: &Path, path: &Path) -> CompatibilityCase {
    let display_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    let failed = |detail: String| CompatibilityCase {
        path: display_path.clone(),
        passed: false,
        detail: detail.clone(),
        tree: frontend_failure(&detail),
        bytecode: frontend_failure(&detail),
    };
    let (canonical, source) = match crate::read_module_source_file(path) {
        Ok(source) => source,
        Err(error) => return failed(error),
    };
    let statements = match crate::parse_named(&source, canonical.display().to_string()) {
        Ok(statements) => statements,
        Err(error) => return failed(error.to_string()),
    };
    let directory = canonical.parent().unwrap_or_else(|| Path::new("."));
    let mut interpreter = Interpreter::silent();
    let tree_result = interpreter.execute_in_directory(&statements, directory);
    let tree = RuntimeOutcome {
        succeeded: tree_result.is_ok(),
        value: tree_result.as_ref().ok().map(ToString::to_string),
        output: interpreter.take_output(),
        error: tree_result.err().map(|error| error.to_string()),
    };

    let mut vm = Vm::silent();
    let bytecode = match bytecode::compile(&statements) {
        Ok(chunk) => {
            let result = vm.execute_in_directory(&chunk, directory);
            RuntimeOutcome {
                succeeded: result.is_ok(),
                value: result.as_ref().ok().map(ToString::to_string),
                output: vm.take_output(),
                error: result.err().map(|error| error.to_string()),
            }
        }
        Err(error) => frontend_failure(&error.to_string()),
    };
    let passed = tree == bytecode;
    CompatibilityCase {
        path: display_path,
        passed,
        detail: if passed {
            "树解释器与字节码 VM 的结果、输出和错误一致".into()
        } else {
            "两个执行器的可观察结果不一致".into()
        },
        tree,
        bytecode,
    }
}

fn frontend_failure(message: &str) -> RuntimeOutcome {
    RuntimeOutcome {
        succeeded: false,
        value: None,
        output: Vec::new(),
        error: Some(message.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_corpus_matches_both_runtimes_and_has_versioned_json() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("compat");
        let report = run(root).unwrap();
        assert!(report.is_success(), "{}", report.human());
        assert!(report.cases.len() >= 7);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], COMPATIBILITY_SCHEMA_VERSION);
    }
}

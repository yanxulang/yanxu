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
    run_with_hook(root, || Ok(()))
}

fn run_with_hook(
    root: impl AsRef<Path>,
    after_discovery: impl FnOnce() -> Result<(), String>,
) -> Result<CompatibilityReport, String> {
    let requested = root.as_ref();
    let (root, paths) = crate::testing::discover_with_root(requested)?;
    if paths.is_empty() {
        return Err(format!("未在“{}”找到兼容语料", root.display()));
    }
    after_discovery()?;
    let cases = paths
        .into_iter()
        .map(|path| run_case(&root, path))
        .collect::<Vec<_>>();
    Ok(CompatibilityReport {
        schema: "https://yanxu.dev/schemas/compatibility-report-v1.json",
        schema_version: COMPATIBILITY_SCHEMA_VERSION,
        language_version: env!("CARGO_PKG_VERSION"),
        cases,
    })
}

fn run_case(root: &Path, file: crate::package::ResolvedPackageFileSnapshot) -> CompatibilityCase {
    let path = file.path().to_path_buf();
    let opened_roots = file.opened_roots();
    let display_path = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    let failed = |detail: String| CompatibilityCase {
        path: display_path.clone(),
        passed: false,
        detail: detail.clone(),
        tree: frontend_failure(&detail),
        bytecode: frontend_failure(&detail),
    };
    let resolved = match file.open() {
        Ok(resolved) => resolved,
        Err(error) => return failed(error.to_string()),
    };
    let source = match crate::package::read_resolved_module_source_snapshot(resolved) {
        Ok(source) => source,
        Err(error) => return failed(format!("不能读取“{}”：{error}", path.display())),
    };
    let statements = match crate::parse_named(&source, path.display().to_string()) {
        Ok(statements) => statements,
        Err(error) => return failed(error.to_string()),
    };
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut interpreter = Interpreter::silent();
    let tree_result =
        interpreter.execute_in_directory_with_opened_roots(&statements, directory, &opened_roots);
    let tree = RuntimeOutcome {
        succeeded: tree_result.is_ok(),
        value: tree_result.as_ref().ok().map(ToString::to_string),
        output: interpreter.take_output(),
        error: tree_result.err().map(|error| error.to_string()),
    };

    let mut vm = Vm::silent();
    let bytecode = match bytecode::compile(&statements) {
        Ok(chunk) => {
            let result =
                vm.execute_in_directory_with_opened_roots(&chunk, directory, &opened_roots);
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
    #[cfg(all(not(windows), not(target_os = "wasi")))]
    use std::fs;
    #[cfg(all(not(windows), not(target_os = "wasi")))]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn shipped_corpus_matches_both_runtimes_and_has_versioned_json() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("compat");
        let report = run(root).unwrap();
        assert!(report.is_success(), "{}", report.human());
        assert!(report.cases.len() >= 7);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], COMPATIBILITY_SCHEMA_VERSION);
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn compatibility_run_uses_the_discovered_root_snapshot() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-compat-snapshot-{unique}"));
        let backup = root.with_extension("original");
        fs::create_dir_all(root.join("子目录")).unwrap();
        fs::write(
            root.join("子目录/用例.yx"),
            "引「辅助.yx」为 辅助；\n言 辅助.值；\n",
        )
        .unwrap();
        fs::write(root.join("子目录/辅助.yx"), "公 定 值：文 为「原根」；\n").unwrap();
        fs::write(root.join("子目录/包用例.yx"), "引「包:不存在」为 工具；\n").unwrap();

        let report = run_with_hook(&root, || {
            fs::rename(&root, &backup).map_err(|error| error.to_string())?;
            fs::create_dir_all(root.join("子目录")).map_err(|error| error.to_string())?;
            fs::write(
                root.join("子目录/言序.toml"),
                "[包]\n格式 = 2\n名称 = \"替换包\"\n版本 = \"0.1.0\"\n言序 = \">=1.1.15\"\n入口 = \"用例.yx\"\n\n[依赖]\n",
            )
            .map_err(|error| error.to_string())?;
            fs::write(
                root.join("子目录/用例.yx"),
                "引「辅助.yx」为 辅助；\n言 辅助.值；\n",
            )
            .map_err(|error| error.to_string())?;
            fs::write(
                root.join("子目录/辅助.yx"),
                "公 定 值：文 为「替换根」；\n",
            )
            .map_err(|error| error.to_string())
        })
        .unwrap();

        let case = report
            .cases
            .iter()
            .find(|case| case.path.ends_with("子目录/用例.yx"))
            .unwrap();
        assert!(case.passed, "{case:#?}");
        assert_eq!(case.tree.output, ["原根"]);
        assert_eq!(case.bytecode.output, ["原根"]);
        let package_case = report
            .cases
            .iter()
            .find(|case| case.path.ends_with("子目录/包用例.yx"))
            .unwrap();
        assert!(!package_case.tree.succeeded, "{package_case:#?}");
        assert!(!package_case.bytecode.succeeded, "{package_case:#?}");
        assert!(
            package_case
                .tree
                .error
                .as_deref()
                .is_some_and(|error| error.contains("工具包根在目录发现后被替换")),
            "{package_case:#?}"
        );
        assert!(
            package_case
                .bytecode
                .error
                .as_deref()
                .is_some_and(|error| error.contains("工具包根在目录发现后被替换")),
            "{package_case:#?}"
        );
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }
}

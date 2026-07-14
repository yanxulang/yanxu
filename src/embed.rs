//! 稳定的宿主嵌入入口。

use crate::bytecode;
use crate::interpreter::Interpreter;
use crate::permissions::PermissionSet;
use crate::vm::Vm;
use crate::{parse_named, type_checker};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Tree,
    Bytecode,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub backend: Backend,
    pub permissions: PermissionSet,
    pub static_check: bool,
    pub budget: crate::budget::ExecutionBudget,
    pub arguments: Vec<String>,
}

impl EngineConfig {
    pub fn sandboxed(backend: Backend) -> Self {
        Self {
            backend,
            permissions: PermissionSet::sandboxed(),
            static_check: true,
            budget: crate::budget::ExecutionBudget::default(),
            arguments: Vec::new(),
        }
    }

    pub fn unrestricted(backend: Backend) -> Self {
        Self {
            backend,
            permissions: PermissionSet::unrestricted(),
            static_check: true,
            budget: crate::budget::ExecutionBudget::default(),
            arguments: Vec::new(),
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::sandboxed(Backend::Bytecode)
    }
}

pub struct Engine {
    config: EngineConfig,
    runtime: Runtime,
    type_history: Vec<crate::ast::Stmt>,
}

enum Runtime {
    Tree(Interpreter),
    Bytecode(Vm),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    pub value: String,
    pub value_type: String,
    pub value_bytes: Option<Vec<u8>>,
    pub output: Vec<String>,
    pub backend: Backend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineErrorKind {
    Io,
    Frontend,
    Type,
    Compile,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    pub kind: EngineErrorKind,
    pub message: String,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EngineError {}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let runtime = Self::build_runtime(&config);
        Self {
            config,
            runtime,
            type_history: Vec::new(),
        }
    }

    fn build_runtime(config: &EngineConfig) -> Runtime {
        let mut runtime = match config.backend {
            Backend::Tree => Runtime::Tree(Interpreter::silent_with_permissions(
                config.permissions.clone(),
            )),
            Backend::Bytecode => {
                Runtime::Bytecode(Vm::silent_with_permissions(config.permissions.clone()))
            }
        };
        match &mut runtime {
            Runtime::Tree(interpreter) => {
                interpreter.set_budget(config.budget);
                interpreter.set_arguments(config.arguments.clone());
            }
            Runtime::Bytecode(vm) => {
                vm.set_budget(config.budget);
                vm.set_arguments(config.arguments.clone());
            }
        }
        runtime
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// 清空持久运行时、类型历史、输出与所有尚未释放的宿主资源。
    pub fn reset(&mut self) {
        self.runtime = Self::build_runtime(&self.config);
        self.type_history.clear();
    }

    pub fn run(&mut self, source: &str) -> Result<Execution, EngineError> {
        let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        self.run_named(source, "<嵌入>", &directory)
    }

    pub fn run_file(&mut self, path: impl AsRef<Path>) -> Result<Execution, EngineError> {
        let path = path.as_ref();
        self.config
            .permissions
            .check_file(path)
            .map_err(|error| EngineError::new(EngineErrorKind::Runtime, error.to_string()))?;
        let canonical = fs::canonicalize(path).map_err(|error| {
            EngineError::new(
                EngineErrorKind::Io,
                format!("不能定位“{}”：{error}", path.display()),
            )
        })?;
        let source = fs::read_to_string(&canonical).map_err(|error| {
            EngineError::new(
                EngineErrorKind::Io,
                format!("不能读取“{}”：{error}", canonical.display()),
            )
        })?;
        self.run_named(
            &source,
            canonical.display().to_string(),
            canonical.parent().unwrap_or_else(|| Path::new(".")),
        )
    }

    pub fn run_named(
        &mut self,
        source: &str,
        name: impl Into<String>,
        directory: &Path,
    ) -> Result<Execution, EngineError> {
        let statements = parse_named(source, name)
            .map_err(|error| EngineError::new(EngineErrorKind::Frontend, error.to_string()))?;
        if self.config.static_check {
            let mut check_unit = self.type_history.clone();
            check_unit.extend(statements.iter().cloned());
            type_checker::check_in_directory_with_permissions(
                &check_unit,
                directory,
                self.config.permissions.clone(),
            )
            .map_err(|errors| {
                EngineError::new(
                    EngineErrorKind::Type,
                    errors
                        .into_iter()
                        .map(|error| error.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            })?;
        }
        let execution = match &mut self.runtime {
            Runtime::Tree(interpreter) => interpreter
                .execute_in_directory(&statements, directory)
                .map(|value| Execution {
                    value: value.to_string(),
                    value_type: value.type_name(),
                    value_bytes: value.as_bytes().map(<[u8]>::to_vec),
                    output: interpreter.take_output(),
                    backend: Backend::Tree,
                })
                .map_err(|error| EngineError::new(EngineErrorKind::Runtime, error.to_string())),
            Runtime::Bytecode(vm) => {
                let chunk = bytecode::compile(&statements).map_err(|error| {
                    EngineError::new(EngineErrorKind::Compile, error.to_string())
                })?;
                vm.execute_in_directory(&chunk, directory)
                    .map(|value| Execution {
                        value: value.to_string(),
                        value_type: value.type_name(),
                        value_bytes: value.as_bytes().map(<[u8]>::to_vec),
                        output: vm.take_output(),
                        backend: Backend::Bytecode,
                    })
                    .map_err(|error| EngineError::new(EngineErrorKind::Runtime, error.to_string()))
            }
        };
        let execution = match execution {
            Ok(execution) => execution,
            Err(error) => {
                self.reset();
                return Err(error);
            }
        };
        if self.config.static_check {
            self.type_history.extend(statements);
        }
        Ok(execution)
    }
}

impl EngineError {
    fn new(kind: EngineErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn persistent_engines_run_both_backends_with_structured_results() {
        for backend in [Backend::Tree, Backend::Bytecode] {
            let mut engine = Engine::new(EngineConfig::sandboxed(backend));
            let first = engine.run("令 值：数 为 2；言 值；").unwrap();
            assert_eq!(first.output, ["2"]);
            assert_eq!(first.backend, backend);
            let second = engine.run("置 值 为 值 加 3；言 值；").unwrap();
            assert_eq!(second.output, ["5"]);
        }
    }

    #[test]
    fn embedded_engines_return_binary_values_and_arguments() {
        for backend in [Backend::Tree, Backend::Bytecode] {
            let mut config = EngineConfig::sandboxed(backend);
            config.arguments = vec!["甲".into(), "乙".into()];
            let mut engine = Engine::new(config);
            let execution = engine
                .run("引「标准:环境」为 环境；引「标准:字节」为 字节；言 长度（环境.参数（））；字节.从数列（【0，255，128】）；")
                .unwrap();
            assert_eq!(execution.output, ["2"]);
            assert_eq!(execution.value_type, "字节串");
            assert_eq!(execution.value_bytes, Some(vec![0, 255, 128]));
        }
    }

    #[test]
    fn embedded_engine_denies_host_access_until_granted() {
        let source = "引「标准:文件」为 文件；言 文件.存在（「Cargo.toml」）；";
        let mut denied = Engine::new(EngineConfig::sandboxed(Backend::Bytecode));
        let error = denied.run(source).unwrap_err();
        assert_eq!(error.kind, EngineErrorKind::Runtime);
        assert!(error.message.contains("未获文件权限"));

        let mut config = EngineConfig::sandboxed(Backend::Bytecode);
        config.permissions = PermissionSet::sandboxed().allow_file(".");
        let mut allowed = Engine::new(config);
        assert_eq!(allowed.run(source).unwrap().output, ["真"]);
    }

    #[test]
    fn static_check_and_runtime_share_module_file_permissions() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-embed-permission-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("子.yx"), "公 定 值：数 为 9；").unwrap();
        let source = "引「子.yx」为 子；言 子.值；";

        let mut denied = Engine::new(EngineConfig::sandboxed(Backend::Bytecode));
        let error = denied.run_named(source, "<权限测试>", &root).unwrap_err();
        assert_eq!(error.kind, EngineErrorKind::Type);
        assert!(error.message.contains("未获文件权限"));

        let mut config = EngineConfig::sandboxed(Backend::Bytecode);
        config.permissions = PermissionSet::sandboxed().allow_file(&root);
        let mut allowed = Engine::new(config);
        assert_eq!(
            allowed
                .run_named(source, "<权限测试>", &root)
                .unwrap()
                .output,
            ["9"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execution_budgets_are_enforced_by_both_backends() {
        for backend in [Backend::Tree, Backend::Bytecode] {
            let mut config = EngineConfig::sandboxed(backend);
            config.budget = crate::budget::ExecutionBudget::new(20, 32, 2);
            let mut engine = Engine::new(config);
            let collection = engine.run("言【1，2，3】；").unwrap_err();
            assert!(collection.message.contains("max_collection_elements"));

            let loop_error = engine
                .run("令 数值 为 0；当 真 则 置 数值 为 数值 加 1；终")
                .unwrap_err();
            assert!(loop_error.message.contains("max_steps"));

            let mut config = EngineConfig::sandboxed(backend);
            config.budget = crate::budget::ExecutionBudget::new(10_000, 3, 100);
            let mut engine = Engine::new(config);
            let recursion = engine
                .run("法 深入（值：数）：数 则 归 深入（值 加 1）；终 言 深入（0）；")
                .unwrap_err();
            assert!(recursion.message.contains("max_call_depth"));
        }
    }

    #[test]
    fn runtime_failure_resets_persistent_state_and_type_history() {
        for backend in [Backend::Tree, Backend::Bytecode] {
            let mut engine = Engine::new(EngineConfig::sandboxed(backend));
            engine.run("令 值：数 为 2；言 值；").unwrap();
            let error = engine
                .run("置 值 为 9；令 零：数 为 0；言 1 除 零；")
                .unwrap_err();
            assert_eq!(error.kind, EngineErrorKind::Runtime);
            assert!(error.message.contains("不可除以零"));

            let missing = engine.run("言 值；").unwrap_err();
            assert_eq!(missing.kind, EngineErrorKind::Type);
            assert!(missing.message.contains("值"));

            let recovered = engine.run("令 值：数 为 4；言 值；").unwrap();
            assert_eq!(recovered.output, ["4"]);
        }
    }

    #[test]
    fn outbound_permission_does_not_implicitly_allow_socket_binding() {
        let source = "引「标准:套接字」为 套接字；定 监听器 为 套接字.TCP监听（「127.0.0.1:0」）；套接字.关闭（监听器）；";
        for backend in [Backend::Tree, Backend::Bytecode] {
            let mut denied_config = EngineConfig::sandboxed(backend);
            denied_config.permissions = PermissionSet::sandboxed().allow_network("127.0.0.1");
            let error = Engine::new(denied_config).run(source).unwrap_err();
            assert_eq!(error.kind, EngineErrorKind::Runtime);
            assert!(error.message.contains("TCP监听"));

            let mut allowed_config = EngineConfig::sandboxed(backend);
            allowed_config.permissions = PermissionSet::sandboxed().allow_tcp_listen("127.0.0.1");
            Engine::new(allowed_config).run(source).unwrap();
        }
    }
}

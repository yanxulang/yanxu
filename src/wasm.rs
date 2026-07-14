//! WASM/WASI 友好的无宿主默认执行入口。

use crate::embed::{Backend, Engine, EngineConfig, EngineError, Execution};

/// 在沙箱字节码 VM 中执行 UTF-8 言序源码。
///
/// 此入口不授予文件、网络、环境或进程能力，适合由 WASM 宿主再封装。
pub fn run_utf8(source: &str) -> Result<Execution, EngineError> {
    Engine::new(EngineConfig::sandboxed(Backend::Bytecode)).run(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandboxed_wasm_entry_runs_pure_programs() {
        let execution = run_utf8("言「善哉」；").unwrap();
        assert_eq!(execution.output, ["善哉"]);
    }

    #[test]
    fn sandboxed_wasm_entry_reports_unavailable_host_capabilities() {
        let error = run_utf8("引「标准:环境」为 环境；言 环境.读取（「HOME」）；").unwrap_err();
        assert!(error.message.contains("未获环境权限"));
    }
}

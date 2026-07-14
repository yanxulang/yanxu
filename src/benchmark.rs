//! 树解释器与字节码 VM 的可重复微基准。
//!
//! 这里只比较同一份已解析程序的执行阶段；解析与编译耗时另行报告，避免把
//! 一次性前端成本混入运行时对比。该入口主要用于版本回归观察，不把易波动的
//! 绝对时间写成测试断言。

use crate::bytecode;
use crate::interpreter::Interpreter;
use crate::vm::Vm;
use std::hint::black_box;
use std::time::{Duration, Instant};

const SOURCE: &str = r#"
    法 阶乘（值：数）：数 则
        若 值 不大于 1 则 归 1；终
        归 值 乘 阶乘（值 减 1）；
    终
    令 总和：数 为 0；令 次：数 为 0；
    当 次 小于 200 则
        置 总和 为 总和 加 阶乘（8）；
        置 次 为 次 加 1；
    终
    言 总和；
"#;

#[derive(Debug, Clone)]
pub struct BenchmarkReport {
    pub iterations: usize,
    pub parse_time: Duration,
    pub compile_time: Duration,
    pub interpreter_time: Duration,
    pub vm_time: Duration,
    pub output: Vec<String>,
}

impl BenchmarkReport {
    pub fn vm_speed_ratio(&self) -> f64 {
        let denominator = self.vm_time.as_secs_f64();
        if denominator == 0.0 {
            f64::INFINITY
        } else {
            self.interpreter_time.as_secs_f64() / denominator
        }
    }
}

pub fn compare(iterations: usize) -> Result<BenchmarkReport, String> {
    if iterations == 0 {
        return Err("基准轮数须大于零".into());
    }

    let started = Instant::now();
    let statements = crate::parse_named(SOURCE, "<内建基准>").map_err(|error| error.to_string())?;
    let parse_time = started.elapsed();

    let started = Instant::now();
    let chunk = bytecode::compile(&statements).map_err(|error| error.to_string())?;
    let compile_time = started.elapsed();

    let started = Instant::now();
    let mut tree_output = Vec::new();
    for _ in 0..iterations {
        let mut interpreter = Interpreter::silent();
        black_box(
            interpreter
                .execute(black_box(&statements))
                .map_err(|error| error.to_string())?,
        );
        tree_output = interpreter.take_output();
    }
    let interpreter_time = started.elapsed();

    let started = Instant::now();
    let mut vm_output = Vec::new();
    for _ in 0..iterations {
        let mut vm = Vm::silent();
        black_box(
            vm.execute(black_box(&chunk))
                .map_err(|error| error.to_string())?,
        );
        vm_output = vm.take_output();
    }
    let vm_time = started.elapsed();

    if tree_output != vm_output {
        return Err(format!(
            "基准程序语义不一致：树解释器 {tree_output:?}，VM {vm_output:?}"
        ));
    }
    Ok(BenchmarkReport {
        iterations,
        parse_time,
        compile_time,
        interpreter_time,
        vm_time,
        output: tree_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_compares_equal_program_results() {
        let report = compare(1).unwrap();
        assert_eq!(report.output, ["8064000"]);
        assert!(report.vm_speed_ratio().is_finite());
    }
}

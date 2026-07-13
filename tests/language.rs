use std::path::PathBuf;
use yanxu::{interpreter::Interpreter, run_file_with, run_with};

#[test]
fn executes_a_complete_program() {
    let source = r#"
        令 合计 为 0；
        令 次 为 1；
        当 次 不大于 5 则
            置 合计 为 合计 加 次；
            置 次 为 次 加 1；
        终
        若 合计 等于 15 则
            言 「善」；
        否则
            言 「误」；
        终
    "#;
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, source).unwrap();
    assert_eq!(interpreter.output(), &["善"]);
}

#[test]
fn reports_undefined_names_in_chinese() {
    let mut interpreter = Interpreter::silent();
    let error = run_with(&mut interpreter, "言 未知；").unwrap_err();
    assert!(error.to_string().contains("未曾定义“未知”"));
}

#[test]
fn imports_a_relative_module() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/模块化.yx");
    let mut interpreter = Interpreter::silent();
    run_file_with(&mut interpreter, path).unwrap();
    assert_eq!(interpreter.output(), &["81", "3.1415926"]);
}

#[test]
fn typed_function_rejects_wrong_arguments() {
    let mut interpreter = Interpreter::silent();
    let error = run_with(
        &mut interpreter,
        "法 加一（数值：数）：数 则 归 数值 加 1；终 加一（「一」）；",
    )
    .unwrap_err();
    assert!(error.to_string().contains("变量“数值”注为数，不可纳入文"));
}

#[test]
fn caches_modules_after_first_load() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/缓存入口.yx");
    let mut interpreter = Interpreter::silent();
    run_file_with(&mut interpreter, path).unwrap();
    assert_eq!(interpreter.output(), &["模块已载", "8"]);
}

#[test]
fn rejects_circular_modules() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/循环甲.yx");
    let mut interpreter = Interpreter::silent();
    let error = run_file_with(&mut interpreter, path).unwrap_err();
    assert!(error.to_string().contains("模块循环相引"));
}

#[test]
fn semantic_phase_rejects_duplicate_declarations() {
    let mut interpreter = Interpreter::silent();
    let error = run_with(&mut interpreter, "令 同名 为 1；令 同名 为 2；").unwrap_err();
    assert!(error.to_string().contains("重复声明“同名”"));
}

#[test]
fn thrown_values_are_catchable() {
    let source = "试 则 抛「自定义之误」；救 错 则 言 错.消息；终";
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, source).unwrap();
    assert_eq!(interpreter.output(), &["自定义之误"]);
}

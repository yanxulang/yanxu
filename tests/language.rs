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
    assert_eq!(interpreter.module_initialization_order().len(), 1);
}

#[test]
fn rejects_circular_modules() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/循环甲.yx");
    let mut interpreter = Interpreter::silent();
    let error = run_file_with(&mut interpreter, path).unwrap_err();
    assert!(error.to_string().contains("模块循环相引"));
    assert!(error.to_string().contains('→'));
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

#[test]
fn module_frontend_errors_keep_the_module_location() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("tests/fixtures/坏模块入口.yx");
    let expected_module = root.join("tests/fixtures/坏模块.yx");
    let mut interpreter = Interpreter::silent();
    let error = run_file_with(&mut interpreter, path)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&format!("{}:1:7", expected_module.display())));
    assert!(error.contains("令 数值 为；"));
}

#[test]
fn container_primitives_cover_lists_and_maps() {
    let source = r#"
        令 项 为【1，3】；
        插入（项，1，2）；
        言 删除（项，0）；
        定 对照 为{「甲」：1，「乙」：2}；
        言 长度（键列（对照））；
        言 值列（对照）【0】；
    "#;
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, source).unwrap();
    assert_eq!(interpreter.output(), &["1", "2", "1"]);
}

#[test]
fn runtime_annotations_accept_union_types() {
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, "定 值：数|文 为「善」；言 值；").unwrap();
    assert_eq!(interpreter.output(), &["善"]);
}

#[test]
fn standard_modules_have_stable_explicit_exports() {
    let source = "引「标准:数学」为 数学；言 数学.幂（2，8）；";
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, source).unwrap();
    assert_eq!(interpreter.output(), &["256"]);
}

#[test]
fn modules_hide_declarations_without_public_marker() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("tests/fixtures/私有入口.yx");
    let mut interpreter = Interpreter::silent();
    let error = run_file_with(&mut interpreter, path)
        .unwrap_err()
        .to_string();
    assert!(error.contains("未导出“秘密”"));
}

#[test]
fn classes_reuse_parent_methods() {
    let source = r#"
        类 生灵 则
            法 名号（）：文 则 归 此.名；终
        终
        类 人 承 生灵 则
            法 初始化（名：文）则 置 此.名 为 名；终
        终
        言 人（「子路」）.名号（）；
    "#;
    let mut interpreter = Interpreter::silent();
    run_with(&mut interpreter, source).unwrap();
    assert_eq!(interpreter.output(), &["子路"]);
}

#[test]
fn static_checker_reads_module_api_without_executing_module() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("tests/fixtures/类型入口.yx");
    let source = std::fs::read_to_string(&path).unwrap();
    let statements = yanxu::parse_named(&source, path.display().to_string()).unwrap();
    yanxu::type_checker::check_in_directory(&statements, path.parent().unwrap()).unwrap();

    let bad = yanxu::parse_named(
        "引「类型模块.yx」为 工具；定 坏：数 为 工具.加一（「一」）；言 工具.私值；",
        "跨模块错误.yx",
    )
    .unwrap();
    let errors = yanxu::type_checker::check_in_directory(&bad, path.parent().unwrap()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("参数应为 数"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("未公开“私值”"))
    );
}

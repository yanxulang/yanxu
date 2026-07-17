use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use yanxu::{interpreter::Interpreter, run_file_with, run_with};

fn multi_file_project(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-runtime-{name}-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in files {
        std::fs::write(root.join(path), source).unwrap();
    }
    root
}

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
    let expected_module =
        std::fs::canonicalize(root.join("tests/fixtures/坏模块.yx")).expect("测试模块应当存在");
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
fn type_checker_accepts_super_calls_subtyping_and_type_narrowing() {
    let source = r#"
        类 生灵 则
            法 自述（）：文 则 归「生灵」；终
        终
        类 人 承 生灵 则
            法 自述（）：文 则 归 父.自述（）加「人」；终
        终
        定 子：生灵 为 人（）；
        令 值：数|文 为「言序」；
        若 值 是 文 则
            定 复制：文 为 值 加「语言」；
        否则
            定 数值：数 为 值 加 1；
        终
    "#;
    let statements = yanxu::parse(source).unwrap();
    yanxu::type_checker::check(&statements).unwrap();
}

#[test]
fn type_checker_rejects_incompatible_overrides_and_super_usage() {
    let bad_override = yanxu::parse(
        r#"
            类 生灵 则 法 自述（值：文）：文 则 归 值；终 终
            类 人 承 生灵 则 法 自述（值：数）：文 则 归「坏」；终 终
        "#,
    )
    .unwrap();
    let errors = yanxu::type_checker::check(&bad_override).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("参数或归值须与父类签名一致"))
    );

    let error = yanxu::parse("类 独 则 法 坏（）：空 则 父.坏（）；终 终").unwrap_err();
    assert!(error.to_string().contains("父"));
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

#[test]
fn tree_interpreter_executes_cross_module_oop_and_facades() {
    let helper = "公 法 前缀（）：文 则 归「基础-」；终";
    let base = r#"
        引「helper.yx」为 辅助；
        公 协 可描述 则 法 描述（）：文；终
        公 类 视图 纳 可描述 则
            公 域 名称：文；
            法 初始化（名称：文）则 置 此.名称 为 名称；终
            公 法 描述（）：文 则 归 辅助.前缀（）加 此.名称；终
            私 法 秘密（）：文 则 归「秘密」；终
            公 静 法 种类（）：文 则 归「视图」；终
        终
    "#;
    let controls = r#"
        引「base.yx」为 基础；
        公 类 按钮 承 基础.视图 纳 基础.可描述 则
            公 域 点击数：数 为 0；
            公 域 所属视图：基础.视图；
            法 初始化（名称：文）则
                父.初始化（名称）；
                置 此.所属视图 为 此；
            终
            公 法 描述（）：文 则 归 父.描述（）加「-按钮」；终
            公 静 法 新建（名称：文）：按钮 则 归 按钮（名称）；终
        终
        公 法 包装（内容：基础.视图）：基础.视图 则 归 内容；终
    "#;
    let facade = "公 引「controls.yx」为 控件；";
    let main = r#"
        引「base.yx」为 基础；
        引「facade.yx」为 界面；
        定 根：基础.视图 为 界面.控件.按钮.新建（「确定」）；
        定 协议值：基础.可描述 为 根；
        定 包装后：基础.视图 为 界面.控件.包装（根）；
        言 根.描述（）；
        言 根 是 基础.视图；
        言 根 是 基础.可描述；
        言 根 是 界面.控件.按钮；
        言 包装后 是 基础.视图；
        言 根.点击数；
        言 根.所属视图 是 基础.视图；
        言 基础.视图.种类（）；
    "#;
    let root = multi_file_project(
        "oop",
        &[
            ("helper.yx", helper),
            ("base.yx", base),
            ("controls.yx", controls),
            ("facade.yx", facade),
            ("main.yx", main),
        ],
    );
    let main_path = root.join("main.yx");
    let source = std::fs::read_to_string(&main_path).unwrap();
    let statements = yanxu::parse_named(&source, main_path.display().to_string()).unwrap();
    yanxu::type_checker::check_in_directory(&statements, &root).unwrap();
    let mut interpreter = Interpreter::silent();
    run_file_with(&mut interpreter, &main_path).unwrap();
    assert_eq!(
        interpreter.output(),
        &["基础-确定-按钮", "真", "真", "真", "真", "0", "真", "视图"]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tree_interpreter_keeps_same_short_names_isolated_by_module() {
    let class = r#"
        公 类 节点 则
            公 域 标签：文；
            法 初始化（标签：文）则 置 此.标签 为 标签；终
        终
    "#;
    let main = r#"
        引「a.yx」为 甲；引「b.yx」为 乙；引「a.yx」为 核心；
        定 左：甲.节点 为 甲.节点（「左」）；
        定 右：乙.节点 为 乙.节点（「右」）；
        定 同一：核心.节点 为 左；
        言 左 是 甲.节点；
        言 左 是 核心.节点；
        言 左 是 乙.节点；
        言 右 是 乙.节点；
        言 左.标签 加 右.标签；
    "#;
    let root = multi_file_project(
        "same-name",
        &[("a.yx", class), ("b.yx", class), ("main.yx", main)],
    );
    let main_path = root.join("main.yx");
    let mut interpreter = Interpreter::silent();
    run_file_with(&mut interpreter, &main_path).unwrap();
    assert_eq!(interpreter.output(), &["真", "真", "假", "真", "左右"]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tree_interpreter_rejects_private_cross_module_super_calls() {
    let base = r#"
        公 类 基类 则 私 法 秘密（）：文 则 归「秘密」；终 终
    "#;
    let main = r#"
        引「base.yx」为 基础；
        类 子类 承 基础.基类 则 法 读取（）：文 则 归 父.秘密（）；终 终
        言 子类（）.读取（）；
    "#;
    let root = multi_file_project("private-super", &[("base.yx", base), ("main.yx", main)]);
    let mut interpreter = Interpreter::silent();
    let error = run_file_with(&mut interpreter, root.join("main.yx"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("父类私法“秘密”不可由子类调用"));
    std::fs::remove_dir_all(root).unwrap();
}

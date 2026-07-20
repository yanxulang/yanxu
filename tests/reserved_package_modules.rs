use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use yanxu::bytecode;
use yanxu::embed::{Backend, Engine, EngineConfig, EngineError, EngineErrorKind};
use yanxu::interpreter::Interpreter;
use yanxu::package::{
    self, PACKAGE_MODULE_OUTSIDE_ROOT_CODE, PACKAGE_MODULE_RESERVED_PATH_CODE,
    PACKAGE_PATH_NON_PORTABLE_CODE,
};
use yanxu::vm::Vm;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "yanxu-reserved-modules-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write(path: impl AsRef<Path>, contents: &str) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn package_fixture(
    dependency_relative: &str,
    hidden_directory: &str,
) -> (PathBuf, PathBuf, String) {
    let root = temporary_root("fixture");
    let app = root.join("app");
    let dependency = app.join(dependency_relative);
    write(
        dependency.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='受测依赖'\n版本='1.0.0'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n",
    );
    write(
        dependency.join("src/主.yx"),
        &format!("引「../{hidden_directory}/隐藏.yx」为 隐藏；公 定 答：数 为 隐藏.值；\n"),
    );
    write(
        dependency.join(hidden_directory).join("隐藏.yx"),
        "公 定 值：数 为 42；\n",
    );
    write(
        app.join(package::MANIFEST_NAME),
        &format!(
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n依赖={{包='受测依赖',路径='{dependency_relative}',版='^1'}}\n"
        ),
    );
    let source = "引「包:依赖」为 依赖；言 依赖.答；".to_owned();
    write(app.join("src/主.yx"), &source);
    (root, app, source)
}

#[test]
fn reserved_dependency_module_is_rejected_consistently_after_graph_cache_hit() {
    let (root, app, source) = package_fixture("../dependency", "build");
    let entry = app.join("src/主.yx");
    let manifest = package::load(app.join(package::MANIFEST_NAME)).unwrap();
    package::ensure_lock_with_dev(&manifest, false).unwrap();
    let statements = yanxu::parse_named(&source, entry.display().to_string()).unwrap();

    let type_errors =
        yanxu::type_checker::check_in_directory(&statements, entry.parent().unwrap()).unwrap_err();
    assert!(
        type_errors
            .iter()
            .any(|error| error.code() == PACKAGE_MODULE_RESERVED_PATH_CODE),
        "{type_errors:#?}"
    );

    let mut interpreter = Interpreter::silent();
    let tree_error = interpreter
        .execute_in_directory(&statements, entry.parent().unwrap())
        .unwrap_err();
    assert_eq!(tree_error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
    assert!(!tree_error.message.contains("[RUN000]"));

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    let vm_error = vm
        .execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap_err();
    assert_eq!(vm_error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
    assert!(!vm_error.message.contains("[RUN000]"));

    let compile_error = yanxu::application::compile_application(&app, "release").unwrap_err();
    assert_eq!(compile_error.code(), PACKAGE_MODULE_RESERVED_PATH_CODE);

    let uri = url::Url::from_file_path(&entry).unwrap().to_string();
    let diagnostics = yanxu::lsp::diagnostics(&source, &uri);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic["code"] == PACKAGE_MODULE_RESERVED_PATH_CODE),
        "{diagnostics:#?}"
    );

    let doc_error =
        yanxu::docgen::markdown_in_directory("主", &statements, entry.parent().unwrap())
            .unwrap_err();
    assert!(
        doc_error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE),
        "{doc_error}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_dependency_nested_under_vendor_uses_the_deepest_package_root() {
    let (root, app, _) = package_fixture("vendor/dependency", "src/子");
    let dependency = app.join("vendor/dependency");
    write(
        dependency.join("src/主.yx"),
        "引「子/隐藏.yx」为 隐藏；公 定 答：数 为 隐藏.值；\n",
    );
    let source = fs::read_to_string(app.join("src/主.yx")).unwrap();
    let directory = app.join("src");
    let statements =
        yanxu::parse_named(&source, app.join("src/主.yx").display().to_string()).unwrap();
    yanxu::type_checker::check_in_directory(&statements, &directory).unwrap();

    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, &directory)
        .unwrap();
    assert_eq!(interpreter.take_output(), ["42"]);

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, &directory).unwrap();
    assert_eq!(vm.take_output(), ["42"]);

    let archive = yanxu::application::compile_application(&app, "release").unwrap();
    assert!(
        archive
            .modules
            .keys()
            .any(|id| id.contains("src/子/隐藏.yx"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn module_cache_cannot_bypass_a_later_package_policy() {
    let root = temporary_root("cache");
    write(root.join("build/隐藏.yx"), "公 定 值：数 为 7；\n");
    let source = "引「build/隐藏.yx」为 隐藏；言 隐藏.值；";
    let statements = yanxu::parse_named(source, root.join("主.yx").display().to_string()).unwrap();
    let chunk = bytecode::compile(&statements).unwrap();

    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, &root)
        .unwrap();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, &root).unwrap();

    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='缓存边界'\n版本='1.0.0'\n入口='主.yx'\n",
    );
    write(root.join("主.yx"), source);

    let tree_error = interpreter
        .execute_in_directory(&statements, &root)
        .unwrap_err()
        .to_string();
    let vm_error = vm
        .execute_in_directory(&chunk, &root)
        .unwrap_err()
        .to_string();
    for error in [tree_error, vm_error] {
        assert!(error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE), "{error}");
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mixed_case_reserved_alias_is_rejected_before_module_read() {
    let (root, app, _) = package_fixture("../dependency", "Build");
    let source = fs::read_to_string(app.join("src/主.yx")).unwrap();
    let statements =
        yanxu::parse_named(&source, app.join("src/主.yx").display().to_string()).unwrap();
    let mut interpreter = Interpreter::silent();
    let error = interpreter
        .execute_in_directory(&statements, &app.join("src"))
        .unwrap_err()
        .to_string();
    assert!(error.contains(PACKAGE_PATH_NON_PORTABLE_CODE), "{error}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn top_level_package_file_in_reserved_directory_is_rejected_before_read() {
    let root = temporary_root("top-level");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='顶层边界'\n版本='1.0.0'\n入口='主.yx'\n",
    );
    write(root.join("主.yx"), "言 1；\n");
    let hidden = root.join("target/隐藏.yx");
    write(&hidden, "言 2；\n");

    let error = yanxu::run_file(&hidden).unwrap_err().to_string();
    assert!(error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE), "{error}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_import_cannot_read_a_vendor_dependency_private_module() {
    let (root, app, _) = package_fixture("vendor/dependency", "src/内部");
    let dependency = app.join("vendor/dependency");
    write(dependency.join("src/私有.yx"), "公 定 值：数 为 99；\n");
    let source = "引「../vendor/dependency/src/私有.yx」为 私有；言 私有.值；";
    let entry = app.join("src/主.yx");
    write(&entry, source);
    let manifest = package::load(app.join(package::MANIFEST_NAME)).unwrap();
    package::ensure_lock_with_dev(&manifest, false).unwrap();
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();

    let type_errors =
        yanxu::type_checker::check_in_directory(&statements, entry.parent().unwrap()).unwrap_err();
    assert!(
        type_errors
            .iter()
            .any(|error| error.code() == PACKAGE_MODULE_OUTSIDE_ROOT_CODE),
        "{type_errors:#?}"
    );
    let mut interpreter = Interpreter::silent();
    assert_eq!(
        interpreter
            .execute_in_directory(&statements, entry.parent().unwrap())
            .unwrap_err()
            .code,
        PACKAGE_MODULE_OUTSIDE_ROOT_CODE
    );
    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    assert_eq!(
        vm.execute_in_directory(&chunk, entry.parent().unwrap())
            .unwrap_err()
            .code,
        PACKAGE_MODULE_OUTSIDE_ROOT_CODE
    );
    let application_error = yanxu::application::compile_application(&app, "release").unwrap_err();
    assert_eq!(application_error.code(), PACKAGE_MODULE_OUTSIDE_ROOT_CODE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nonexistent_reserved_paths_are_rejected_before_io_and_lsp_syntax_errors() {
    let root = temporary_root("nonexistent-reserved");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='缺失保留路径'\n版本='1.0.0'\n入口='主.yx'\n",
    );
    write(root.join("主.yx"), "言 1；\n");
    let missing = root.join("build/缺失.yx");

    let error = yanxu::run_file(&missing).unwrap_err().to_string();
    assert!(error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE), "{error}");
    assert!(!error.contains("No such file"), "{error}");

    let mut config = EngineConfig::sandboxed(Backend::Tree);
    config.permissions = package::PermissionSet::sandboxed().allow_file(&root);
    let mut engine = Engine::new(config);
    let error = engine.run_file(&missing).unwrap_err();
    assert_eq!(error.kind, EngineErrorKind::Frontend);
    assert!(
        error
            .message
            .starts_with(&format!("[{PACKAGE_MODULE_RESERVED_PATH_CODE}]")),
        "{error}"
    );

    let uri = url::Url::from_file_path(&missing).unwrap().to_string();
    let diagnostics = yanxu::lsp::diagnostics("定", &uri);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic["code"] == PACKAGE_MODULE_RESERVED_PATH_CODE),
        "{diagnostics:#?}"
    );
    assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn package_directory_tools_prune_reserved_content_and_reject_aliases() {
    let root = temporary_root("directory-tools");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='目录工具'\n版本='1.0.0'\n入口='src/主.yx'\n",
    );
    write(root.join("src/主.yx"), "言 1；\n");
    write(root.join("build/坏.yx"), "这不是合法源码");
    write(root.join("target/坏.yx"), "这不是合法源码");

    let docs = yanxu::docgen::markdown_directory(&root).unwrap();
    assert!(docs.contains("[`src/主`](#模块-src-主)"), "{docs}");
    assert!(!docs.contains("build/坏"), "{docs}");
    let tests = yanxu::testing::discover(&root).unwrap();
    assert_eq!(tests, [fs::canonicalize(root.join("src/主.yx")).unwrap()]);
    let report = yanxu::compatibility::run(&root).unwrap();
    assert!(report.is_success(), "{}", report.human());

    for explicit in [root.join("build"), root.join("build/坏.yx")] {
        let test_error = yanxu::testing::discover(&explicit).unwrap_err();
        assert!(
            test_error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE),
            "{test_error}"
        );
    }
    write(root.join("Build/坏.yx"), "言 2；\n");
    let alias_error = yanxu::testing::discover(root.join("Build")).unwrap_err();
    assert!(
        alias_error.contains(PACKAGE_PATH_NON_PORTABLE_CODE),
        "{alias_error}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn directory_tools_accept_unicode_equivalent_explicit_directory() {
    let root = temporary_root("unicode-directory-entry");
    let actual = root.join("cases/é");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='目录规范化'\n版本='1.0.0'\n入口='cases/e\u{301}/主.yx'\n",
    );
    write(actual.join("主.yx"), "言 1；\n");
    let requested = root.join("cases/e\u{301}");
    let canonical_file = fs::canonicalize(actual.join("主.yx")).unwrap();

    assert_eq!(
        yanxu::testing::discover(&requested).unwrap(),
        [canonical_file]
    );
    assert!(yanxu::compatibility::run(&requested).unwrap().is_success());
    let markdown = yanxu::docgen::markdown_directory(&requested).unwrap();
    assert!(markdown.contains("[`主`](#模块-主)"), "{markdown}");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_yanxu"))
        .arg("文")
        .arg(&requested)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("[`主`](#模块-主)"));

    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn package_directory_tools_reject_explicit_symlink_roots_and_entry_symlinks() {
    use std::os::unix::fs::symlink;

    let root = temporary_root("directory-symlinks");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='符号链接边界'\n版本='1.0.0'\n入口='src/主.yx'\n",
    );
    write(root.join("src/实际.yx"), "言 1；\n");
    symlink(root.join("src/实际.yx"), root.join("src/主.yx")).unwrap();
    let compile_error = yanxu::application::compile_application(&root, "release").unwrap_err();
    assert!(
        compile_error.to_string().contains("符号链接"),
        "{compile_error}"
    );

    let link = root.join("测试链接");
    symlink(root.join("src"), &link).unwrap();
    assert!(
        yanxu::testing::discover(&link)
            .unwrap_err()
            .contains("符号链接")
    );
    assert!(
        yanxu::docgen::markdown_directory(&link)
            .unwrap_err()
            .contains("符号链接")
    );
    assert!(
        yanxu::compatibility::run(&link)
            .unwrap_err()
            .contains("符号链接")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn virtual_nonexistent_base_directories_remain_valid_without_imports() {
    let root = temporary_root("virtual-directory");
    let missing = root.join("尚未创建");
    let statements = yanxu::parse("言 1；").unwrap();
    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, &missing)
        .unwrap();
    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, &missing).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_public_error_messages_remain_unchanged() {
    let manifest_error = package::ManifestError {
        message: "原始包错误".into(),
        path: PathBuf::from("言序.toml"),
        line: None,
    };
    assert_eq!(manifest_error.code(), "PACKAGE000");
    assert_eq!(
        manifest_error.to_string(),
        "包解析有误：言序.toml：原始包错误"
    );

    let application_error = yanxu::application::ApplicationError {
        message: "原始应用错误".into(),
    };
    assert_eq!(application_error.message, "原始应用错误");
    assert_eq!(application_error.to_string(), "YXB 应用有误：原始应用错误");

    let type_error = yanxu::type_checker::TypeError {
        message: "原始类型错误".into(),
        span: yanxu::source::Span::synthetic(),
    };
    assert_eq!(type_error.message, "原始类型错误");
    assert!(!type_error.to_string().contains("[TYPE000]"));

    let engine_error = EngineError {
        kind: EngineErrorKind::Io,
        message: "原始嵌入错误".into(),
    };
    assert_eq!(engine_error.to_string(), "原始嵌入错误");
}

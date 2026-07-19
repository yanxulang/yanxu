use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use yanxu::bytecode;
use yanxu::embed::{Backend, Engine, EngineConfig, EngineErrorKind};
use yanxu::interpreter::Interpreter;
use yanxu::package::{self, PACKAGE_MODULE_OUTSIDE_ROOT_CODE, PACKAGE_MODULE_RESERVED_PATH_CODE};
use yanxu::vm::Vm;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "yanxu-module-capability-{label}-{}-{}-{}",
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
fn reserved_dependency_module_is_rejected_by_every_execution_path() {
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

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    let vm_error = vm
        .execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap_err();
    assert_eq!(vm_error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);

    let compile_error = yanxu::application::compile_application(&app, "release").unwrap_err();
    assert_eq!(compile_error.code(), PACKAGE_MODULE_RESERVED_PATH_CODE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_vendor_dependency_uses_the_deepest_opened_package_root() {
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
fn ordinary_import_cannot_cross_into_a_nested_dependency_private_module() {
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
    let compile_error = yanxu::application::compile_application(&app, "release").unwrap_err();
    assert_eq!(compile_error.code(), PACKAGE_MODULE_OUTSIDE_ROOT_CODE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reserved_top_level_source_is_rejected_before_io_and_permission_checks() {
    let root = temporary_root("top-level-reserved");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='顶层边界'\n版本='1.0.0'\n入口='主.yx'\n",
    );
    write(root.join("主.yx"), "言 1；\n");
    let missing = root.join("build/缺失.yx");

    let error = yanxu::run_file(&missing).unwrap_err().to_string();
    assert!(error.contains(PACKAGE_MODULE_RESERVED_PATH_CODE), "{error}");

    let mut denied_engine = Engine::new(EngineConfig::sandboxed(Backend::Tree));
    let denied = denied_engine.run_file(&missing).unwrap_err();
    assert_eq!(denied.kind, EngineErrorKind::Runtime);
    assert!(denied.message.contains("未获文件权限"), "{denied}");
    assert!(
        !denied.message.contains(PACKAGE_MODULE_RESERVED_PATH_CODE),
        "{denied}"
    );

    let mut config = EngineConfig::sandboxed(Backend::Tree);
    config.permissions = package::PermissionSet::sandboxed().allow_file(&root);
    let mut allowed_engine = Engine::new(config);
    let error = allowed_engine.run_file(&missing).unwrap_err();
    assert_eq!(error.kind, EngineErrorKind::Frontend);
    assert!(
        error
            .message
            .starts_with(&format!("[{PACKAGE_MODULE_RESERVED_PATH_CODE}]")),
        "{error}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn unauthorized_external_import_is_denied_before_adjacent_manifest_discovery() {
    let root = temporary_root("permission-before-discovery");
    let app = root.join("app");
    let secret = root.join("secret");
    let secret_module = secret.join("模块.yx");
    write(secret.join(package::MANIFEST_NAME), "这不是可解析的包清单");
    write(&secret_module, "公 定 值：数 为 9；\n");
    let entry = app.join("主.yx");
    write(
        &entry,
        &format!("引「{}」为 私密；言 私密.值；", secret_module.display()),
    );

    for (backend, static_check, expected_kind) in [
        (Backend::Tree, true, EngineErrorKind::Type),
        (Backend::Tree, false, EngineErrorKind::Runtime),
        (Backend::Bytecode, false, EngineErrorKind::Runtime),
    ] {
        let mut config = EngineConfig::sandboxed(backend);
        config.permissions = package::PermissionSet::sandboxed().allow_file(&app);
        config.static_check = static_check;
        let error = Engine::new(config).run_file(&entry).unwrap_err();
        assert_eq!(error.kind, expected_kind);
        assert!(error.message.contains("未获文件权限"), "{error}");
        assert!(!error.message.contains("包清单 TOML"), "{error}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn application_entry_symlink_is_rejected_before_module_compilation() {
    use std::os::unix::fs::symlink;

    let root = temporary_root("entry-symlink");
    write(
        root.join(package::MANIFEST_NAME),
        "[包]\n格式=2\n名称='入口链接'\n版本='1.0.0'\n入口='src/主.yx'\n",
    );
    write(root.join("src/实际.yx"), "言 1；\n");
    symlink("实际.yx", root.join("src/主.yx")).unwrap();

    let error = yanxu::application::compile_application(&root, "release").unwrap_err();
    assert!(error.to_string().contains("符号链接"), "{error}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn module_cache_cannot_bypass_a_package_policy_added_between_runs() {
    let root = temporary_root("cache-policy");
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
        .unwrap_err();
    let vm_error = vm.execute_in_directory(&chunk, &root).unwrap_err();
    assert_eq!(tree_error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
    assert_eq!(vm_error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_module_reads_do_not_poison_later_loader_state() {
    let root = temporary_root("loader-recovery");
    let module = root.join("模块.yx");
    write(&module, "定");
    let source = "引「模块.yx」为 模块；言 模块.值；";
    let statements = yanxu::parse_named(source, root.join("主.yx").display().to_string()).unwrap();
    let chunk = bytecode::compile(&statements).unwrap();

    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, &root)
        .unwrap_err();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, &root).unwrap_err();

    write(&module, "公 定 值：数 为 7；\n");
    interpreter
        .execute_in_directory(&statements, &root)
        .unwrap();
    assert_eq!(interpreter.take_output(), ["7"]);
    vm.execute_in_directory(&chunk, &root).unwrap();
    assert_eq!(vm.take_output(), ["7"]);
    fs::remove_dir_all(root).unwrap();
}

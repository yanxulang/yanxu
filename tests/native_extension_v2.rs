#![cfg(not(target_family = "wasm"))]

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use yanxu::host_events::HostValue;
use yanxu::native_abi_v2::{
    NATIVE_V2_INTEGER, NATIVE_V2_OK, NativeExtensionV2, NativeLoadAuthority, NativeV2CallResult,
    YanxuNativeErrorV2, YanxuNativeHostV2, YanxuValueV2,
};
use yanxu::package::{NativeArtifact, PackagePathPurpose, TrustedPackageRoots};
use yanxu::permissions::PermissionSet;

fn library_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let status = std::process::Command::new(env!("CARGO"))
            .args([
                "build",
                "--manifest-path",
                root.join("examples/native-extension-v2-rust/Cargo.toml")
                    .to_str()
                    .unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        root.join("target").join("debug").join(format!(
            "{}yanxu_native_v2_example{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ))
    })
    .clone()
}

fn artifact(library: &PathBuf) -> NativeArtifact {
    let bytes = std::fs::read(library).unwrap();
    NativeArtifact {
        abi: 2,
        target: yanxu::package::current_target(),
        path: library.to_string_lossy().into_owned(),
        checksum: format!("{:x}", Sha256::digest(&bytes)),
        size: bytes.len() as u64,
    }
}

#[derive(Default)]
struct TestHost {
    retained: AtomicUsize,
    released: AtomicUsize,
    posted: Mutex<Vec<i64>>,
}

unsafe extern "C" fn retain(context: *mut c_void, _callback: u64) -> i32 {
    let host = unsafe { &*(context.cast::<TestHost>()) };
    host.retained.fetch_add(1, Ordering::SeqCst);
    NATIVE_V2_OK
}

unsafe extern "C" fn release(context: *mut c_void, _callback: u64) -> i32 {
    let host = unsafe { &*(context.cast::<TestHost>()) };
    host.released.fetch_add(1, Ordering::SeqCst);
    NATIVE_V2_OK
}

unsafe extern "C" fn post(
    context: *mut c_void,
    _callback: u64,
    arguments: *const YanxuValueV2,
    count: usize,
    _error: *mut YanxuNativeErrorV2,
) -> i32 {
    if count != 1 || arguments.is_null() {
        return 1;
    }
    let argument = unsafe { &*arguments };
    if argument.kind != NATIVE_V2_INTEGER {
        return 1;
    }
    let host = unsafe { &*(context.cast::<TestHost>()) };
    host.posted
        .lock()
        .unwrap()
        .push(unsafe { argument.data.integer });
    NATIVE_V2_OK
}

#[test]
fn loads_v2_typed_values_resources_callbacks_and_isolates_panics() {
    let library = library_path();
    let extension = NativeExtensionV2::load_verified(
        &library,
        &artifact(&library),
        &PermissionSet::sandboxed().allow_native_extensions(),
        "v2-example",
        NativeLoadAuthority::NativeExtension,
    )
    .unwrap();
    assert_eq!(extension.name(), "v2-example");
    assert_eq!(extension.constants()["answer"], HostValue::Integer(42));
    match extension
        .call(
            "sum_i64",
            &[HostValue::Integer(i64::MAX), HostValue::Integer(9)],
            None,
        )
        .unwrap()
    {
        NativeV2CallResult::Value(value) => assert_eq!(value, HostValue::Integer(i64::MAX)),
        NativeV2CallResult::Resource(_) => panic!("expected typed value"),
    }
    match extension.call("binary", &[], None).unwrap() {
        NativeV2CallResult::Value(value) => {
            assert_eq!(value, HostValue::Bytes(vec![0, 255, 128]))
        }
        NativeV2CallResult::Resource(_) => panic!("expected bytes"),
    }
    let mut resource = match extension.call("resource", &[], None).unwrap() {
        NativeV2CallResult::Resource(resource) => resource,
        NativeV2CallResult::Value(_) => panic!("expected resource"),
    };
    assert_eq!(resource.type_name(), "example.v2.resource");
    assert!(!resource.as_raw().is_null());
    resource.close();
    resource.close();

    let mut test_host = TestHost::default();
    let host = YanxuNativeHostV2 {
        abi_version: 2,
        struct_size: std::mem::size_of::<YanxuNativeHostV2>(),
        context: (&mut test_host as *mut TestHost).cast(),
        callback_retain: Some(retain),
        callback_release: Some(release),
        callback_post: Some(post),
        wake: None,
        pump: None,
        has_permission: None,
        resource_get: None,
        event_loop_id: 7,
        owner_thread_token: 11,
    };
    extension
        .call("callback", &[HostValue::Callback(55)], Some(&host))
        .unwrap();
    assert_eq!(test_host.retained.load(Ordering::SeqCst), 1);
    assert_eq!(test_host.released.load(Ordering::SeqCst), 1);
    assert_eq!(*test_host.posted.lock().unwrap(), vec![99]);

    let error = match extension.call("panic", &[], None) {
        Ok(_) => panic!("isolated panic should become a native error"),
        Err(error) => error,
    };
    assert_eq!(error.code, "EXAMPLE_PANIC");
}

#[test]
fn v2_rejects_gui_only_authority_even_for_official_names() {
    let library = library_path();
    for expected_name in ["v2-example", "yanxu-gui", "言窗"] {
        for authority in [
            NativeLoadAuthority::NativeExtension,
            NativeLoadAuthority::OfficialGui,
        ] {
            let denied = match NativeExtensionV2::load_verified(
                &library,
                &artifact(&library),
                &PermissionSet::sandboxed().allow_graphical_interface(),
                expected_name,
                authority,
            ) {
                Ok(_) => panic!("图形界面权限不得授予动态库装载权限"),
                Err(error) => error,
            };
            assert_eq!(denied.code, "NATIVE_PERMISSION");
            assert!(denied.message.contains("原生扩展"));
        }
    }
}

#[test]
fn v2_rejects_authenticated_bytes_that_are_not_a_host_dynamic_library() {
    let bytes = b"authenticated-but-not-a-dynamic-library";
    let artifact = NativeArtifact {
        abi: 2,
        target: yanxu::package::current_target(),
        path: "invalid-native-library".into(),
        checksum: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len() as u64,
    };
    let failure = match NativeExtensionV2::load_verified_bytes(
        bytes,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "v2-example",
        NativeLoadAuthority::NativeExtension,
    ) {
        Ok(_) => panic!("非动态库字节不得进入系统装载器"),
        Err(error) => error,
    };
    assert_eq!(failure.code, "NATIVE_FORMAT");
}

fn temporary_native_root(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "yanxu-native-v2-{tag}-{}-{unique}",
        std::process::id()
    ))
}

#[test]
fn opened_v2_artifact_token_does_not_follow_same_length_path_replacement() {
    let source_library = library_path();
    let root = temporary_native_root("file-token");
    std::fs::create_dir_all(&root).unwrap();
    let library = root.join(format!("extension{}", std::env::consts::DLL_SUFFIX));
    std::fs::copy(&source_library, &library).unwrap();
    let artifact = artifact(&library);
    let mut roots = TrustedPackageRoots::new();
    roots.insert(&root).unwrap();
    let source = roots
        .resolve_existing_file(&library, PackagePathPurpose::ManifestReference)
        .unwrap()
        .unwrap();

    let parked = root.join(format!("parked{}", std::env::consts::DLL_SUFFIX));
    let replaced = std::fs::rename(&library, &parked).is_ok();
    if replaced {
        std::fs::write(&library, vec![0_u8; artifact.size as usize]).unwrap();
    }
    let extension = NativeExtensionV2::load_verified_file(
        source,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "v2-example",
        NativeLoadAuthority::NativeExtension,
    )
    .unwrap();
    assert_eq!(extension.name(), "v2-example");
    if replaced {
        assert_eq!(std::fs::metadata(&library).unwrap().len(), artifact.size);
        assert_ne!(
            format!("{:x}", Sha256::digest(std::fs::read(&library).unwrap())),
            artifact.checksum
        );
    }
    drop(extension);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn opened_v2_artifact_token_does_not_follow_replaced_package_root() {
    let source_library = library_path();
    let root = temporary_native_root("root-token");
    std::fs::create_dir_all(&root).unwrap();
    let library = root.join(format!("extension{}", std::env::consts::DLL_SUFFIX));
    std::fs::copy(&source_library, &library).unwrap();
    let artifact = artifact(&library);
    let mut roots = TrustedPackageRoots::new();
    roots.insert(&root).unwrap();
    let source = roots
        .resolve_existing_file(&library, PackagePathPurpose::ManifestReference)
        .unwrap()
        .unwrap();

    let parked = root.with_extension("opened-root");
    let replaced = std::fs::rename(&root, &parked).is_ok();
    if replaced {
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(format!("extension{}", std::env::consts::DLL_SUFFIX)),
            vec![0_u8; artifact.size as usize],
        )
        .unwrap();
    }
    let extension = NativeExtensionV2::load_verified_file(
        source,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "v2-example",
        NativeLoadAuthority::NativeExtension,
    )
    .unwrap();
    assert_eq!(extension.name(), "v2-example");
    drop(extension);
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    if parked.exists() {
        std::fs::remove_dir_all(&parked).unwrap();
    }
}

#[test]
fn vm_rejects_transitive_native_package_without_a_direct_dependency_edge() {
    let source_library = library_path();
    let root = temporary_native_root("transitive-edge");
    let middle = root.join("middle");
    let native = root.join("native");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(middle.join("src")).unwrap();
    std::fs::create_dir_all(native.join("src")).unwrap();
    let staged_name = format!("backend{}", std::env::consts::DLL_SUFFIX);
    let staged_library = native.join(&staged_name);
    std::fs::copy(&source_library, &staged_library).unwrap();
    let bytes = std::fs::read(&staged_library).unwrap();
    let checksum = format!("{:x}", Sha256::digest(&bytes));
    let (os, architecture) = if cfg!(target_os = "windows") {
        (
            "windows",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else if cfg!(target_os = "macos") {
        (
            "macos",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else {
        (
            "linux",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    };
    std::fs::write(
        native.join("言序.toml"),
        format!(
            "[包]\n格式=2\n名称='v2-example'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[\"原生\"]\nABI=2\n[\"原生\".{os}.{architecture}]\n文件='{staged_name}'\n校验和='{checksum}'\n大小={}\n",
            bytes.len()
        ),
    )
    .unwrap();
    std::fs::write(native.join("src/主.yx"), "公 定 ABI：数 为 2；\n").unwrap();
    std::fs::write(
        middle.join("言序.toml"),
        "[包]\n格式=2\n名称='middle'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[依赖]\n后端={包='v2-example',路径='../native',版='^0.1'}\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    std::fs::write(middle.join("src/主.yx"), "公 定 值：数 为 1；\n").unwrap();
    std::fs::write(
        root.join("言序.toml"),
        "[包]\n格式=2\n名称='transitive-native-test'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[依赖]\n中间={包='middle',路径='middle',版='^0.1'}\n[权限]\n原生扩展=true\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    let source = "引「标准:原生」为 原生；定 后端 为 原生.加载（「v2-example」）；";
    let entry = root.join("src/主.yx");
    std::fs::write(&entry, source).unwrap();
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();
    let chunk = yanxu::bytecode::compile(&statements).unwrap();
    let mut vm = yanxu::vm::Vm::silent();
    let failure = vm
        .execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap_err();
    assert!(
        failure.message.contains("当前包没有直接声明"),
        "意外错误：{}",
        failure.message
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn vm_allows_a_locked_native_package_to_load_its_own_artifact() {
    let source_library = library_path();
    let root = temporary_native_root("self-artifact");
    let native = root.join("native");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(native.join("src")).unwrap();
    let staged_name = format!("backend{}", std::env::consts::DLL_SUFFIX);
    let staged_library = native.join(&staged_name);
    std::fs::copy(&source_library, &staged_library).unwrap();
    let bytes = std::fs::read(&staged_library).unwrap();
    let checksum = format!("{:x}", Sha256::digest(&bytes));
    let (os, architecture) = if cfg!(target_os = "windows") {
        (
            "windows",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else if cfg!(target_os = "macos") {
        (
            "macos",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else {
        (
            "linux",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    };
    std::fs::write(
        native.join("言序.toml"),
        format!(
            "[包]\n格式=2\n名称='v2-example'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[\"原生\"]\nABI=2\n[\"原生\".{os}.{architecture}]\n文件='{staged_name}'\n校验和='{checksum}'\n大小={}\n",
            bytes.len()
        ),
    )
    .unwrap();
    std::fs::write(
        native.join("src/主.yx"),
        "引「标准:原生」为 原生；定 后端 为 原生.加载（「v2-example」）；公 定 已加载：理 为 真；\n",
    )
    .unwrap();
    std::fs::write(
        root.join("言序.toml"),
        "[包]\n格式=2\n名称='native-self-test'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[依赖]\n后端={包='v2-example',路径='native',版='^0.1'}\n[权限]\n原生扩展=true\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    let source = "引「包:后端」为 后端；定 已加载 为 后端.已加载；";
    let entry = root.join("src/主.yx");
    std::fs::write(&entry, source).unwrap();
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();
    let chunk = yanxu::bytecode::compile(&statements).unwrap();
    let mut vm = yanxu::vm::Vm::silent();
    vm.execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn vm_executes_posted_v2_callbacks_only_through_the_owner_thread_event_pump() {
    let library = library_path();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-native-v2-vm-{unique}"));
    let dependency = root.join("dependency");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(dependency.join("src")).unwrap();
    let staged_name = format!("backend{}", std::env::consts::DLL_SUFFIX);
    let staged_library = dependency.join(&staged_name);
    std::fs::copy(&library, &staged_library).unwrap();
    let bytes = std::fs::read(&staged_library).unwrap();
    let checksum = format!("{:x}", Sha256::digest(&bytes));
    let (os, architecture) = if cfg!(target_os = "windows") {
        (
            "windows",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else if cfg!(target_os = "macos") {
        (
            "macos",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else {
        (
            "linux",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    };
    std::fs::write(
        dependency.join("言序.toml"),
        format!(
            "[包]\n格式=2\n名称='v2-example'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[\"原生\"]\nABI=2\n[\"原生\".{os}.{architecture}]\n文件='{staged_name}'\n校验和='{checksum}'\n大小={}\n",
            bytes.len()
        ),
    )
    .unwrap();
    std::fs::write(dependency.join("src/主.yx"), "公 定 ABI：数 为 2；\n").unwrap();
    std::fs::write(
        root.join("言序.toml"),
        "[包]\n格式=2\n名称='v2-vm-test'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[依赖]\n例={包='v2-example',路径='dependency',版='^0.1'}\n[权限]\n原生扩展=true\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    let source = r#"
        引「标准:原生」为 原生；
        定 后端 为 原生.加载（「v2-example」）；
        法 回调（值：数）则 言 值；终
        原生.调用（后端，「callback」，【回调】）；
        言 原生.调用（后端，「sum_i64」，【40，2】）；
    "#;
    let entry = root.join("src/主.yx");
    std::fs::write(&entry, source).unwrap();
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();
    let chunk = yanxu::bytecode::compile(&statements).unwrap();
    let mut vm = yanxu::vm::Vm::silent();
    vm.execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap();
    assert_eq!(vm.output(), &["99", "42"]);

    let archive = yanxu::application::compile_application(&root, "release").unwrap();
    assert_eq!(archive.native_modules["v2-example"].abi, 2);
    let encoded = yanxu::application::serialize(&archive).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    let decoded = yanxu::application::deserialize(&encoded).unwrap();
    let mut packaged_vm = yanxu::vm::Vm::silent();
    packaged_vm.execute_application(&decoded).unwrap();
    assert_eq!(packaged_vm.output(), &["99", "42"]);
}

fn scaffold_native_project(tag: &str, source: &str) -> (PathBuf, PathBuf) {
    let library = library_path();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-native-v2-{tag}-{unique}"));
    let dependency = root.join("dependency");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(dependency.join("src")).unwrap();
    let staged_name = format!("backend{}", std::env::consts::DLL_SUFFIX);
    let staged_library = dependency.join(&staged_name);
    std::fs::copy(&library, &staged_library).unwrap();
    let bytes = std::fs::read(&staged_library).unwrap();
    let checksum = format!("{:x}", Sha256::digest(&bytes));
    let (os, architecture) = if cfg!(target_os = "windows") {
        (
            "windows",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else if cfg!(target_os = "macos") {
        (
            "macos",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    } else {
        (
            "linux",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            },
        )
    };
    std::fs::write(
        dependency.join("言序.toml"),
        format!(
            "[包]\n格式=2\n名称='v2-example'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n[\"原生\"]\nABI=2\n[\"原生\".{os}.{architecture}]\n文件='{staged_name}'\n校验和='{checksum}'\n大小={}\n",
            bytes.len()
        ),
    )
    .unwrap();
    std::fs::write(dependency.join("src/主.yx"), "公 定 ABI：数 为 2；\n").unwrap();
    std::fs::write(
        root.join("言序.toml"),
        "[包]\n格式=2\n名称='v2-budget-test'\n版本='0.1.0'\n言序='>=1.1.7'\n入口='src/主.yx'\n[依赖]\n例={包='v2-example',路径='dependency',版='^0.1'}\n[权限]\n原生扩展=true\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    let entry = root.join("src/主.yx");
    std::fs::write(&entry, source).unwrap();
    (root, entry)
}

#[test]
fn host_callback_step_budget_is_metered_per_event_not_cumulatively() {
    // 常驻程序回归：每个回调远低于预算，但所有回调的累计步数远超预算。
    // 预算按事件计量后必须能跑完；按全程累计则会以 RUN000 中止。
    let source = r#"
        引「标准:原生」为 原生；
        定 后端 为 原生.加载（「v2-example」）；
        法 回调（值：数）则
            令 计 为 0；
            当 计 小于 200 则
                置 计 为 计 加 1；
            终
            言 值；
        终
        令 轮 为 0；
        当 轮 小于 12 则
            原生.调用（后端，「callback」，【回调】）；
            置 轮 为 轮 加 1；
        终
    "#;
    let (root, entry) = scaffold_native_project("budget-window", source);
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();
    let chunk = yanxu::bytecode::compile(&statements).unwrap();
    let mut vm = yanxu::vm::Vm::silent();
    vm.set_budget(yanxu::budget::ExecutionBudget::new(3_000, 256, 100_000));
    vm.execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap();
    // 十二个回调必须全部真实执行过，防止“事件未被泵送”造成的假通过。
    assert_eq!(vm.output(), &["99"; 12]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn runaway_host_callback_still_exhausts_step_budget() {
    // 反向回归：单个回调内的死循环仍须被步数预算拦截。
    let source = r#"
        引「标准:原生」为 原生；
        定 后端 为 原生.加载（「v2-example」）；
        法 回调（值：数）则
            令 计 为 0；
            当 真 则
                置 计 为 计 加 1；
            终
        终
        原生.调用（后端，「callback」，【回调】）；
    "#;
    let (root, entry) = scaffold_native_project("budget-runaway", source);
    let statements = yanxu::parse_named(source, entry.display().to_string()).unwrap();
    let chunk = yanxu::bytecode::compile(&statements).unwrap();
    let mut vm = yanxu::vm::Vm::silent();
    vm.set_budget(yanxu::budget::ExecutionBudget::new(3_000, 256, 100_000));
    let error = vm
        .execute_in_directory(&chunk, entry.parent().unwrap())
        .unwrap_err();
    assert!(
        error.message.contains("步数超过预算"),
        "意外错误：{}",
        error.message
    );
    std::fs::remove_dir_all(root).unwrap();
}

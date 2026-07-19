#![cfg(not(target_family = "wasm"))]

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use std::sync::OnceLock;
use yanxu::native_abi::{
    NATIVE_OK, NATIVE_OUTPUT_JSON, NativeCallResult, NativeExtension, YanxuNativeCallbackV1,
    YanxuNativeErrorV1, YanxuNativeOutputV1,
};
use yanxu::package::NativeArtifact;
use yanxu::permissions::PermissionSet;

fn example_library() -> &'static PathBuf {
    static LIBRARY: OnceLock<PathBuf> = OnceLock::new();
    LIBRARY.get_or_init(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "yanxu-native-example"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .unwrap();
        assert!(status.success(), "example extension failed to build");
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join(format!(
                "{}yanxu_native_example{}",
                std::env::consts::DLL_PREFIX,
                std::env::consts::DLL_SUFFIX
            ))
    })
}

fn artifact(library: &PathBuf) -> NativeArtifact {
    assert!(
        library.is_file(),
        "example extension was not built: {}",
        library.display()
    );
    let checksum = format!("{:x}", Sha256::digest(std::fs::read(library).unwrap()));
    NativeArtifact {
        abi: 1,
        target: yanxu::package::current_target(),
        path: library.to_string_lossy().into_owned(),
        checksum,
        size: std::fs::metadata(library).unwrap().len(),
    }
}

#[test]
fn loads_verified_native_functions_constants_and_resources() {
    let library = example_library();
    let artifact = artifact(library);
    let denied = match NativeExtension::load_verified(
        library,
        &artifact,
        &PermissionSet::sandboxed(),
        "example",
    ) {
        Ok(_) => panic!("sandboxed loader should reject native extensions"),
        Err(error) => error,
    };
    assert_eq!(denied.code, "NATIVE_PERMISSION");

    let extension = NativeExtension::load_verified(
        library,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    )
    .unwrap();
    assert_eq!(extension.name(), "example");
    assert_eq!(extension.constants()["answer"], 42);
    match extension
        .call_json("sum", &serde_json::json!([2, 3]))
        .unwrap()
    {
        NativeCallResult::Json(value) => assert_eq!(value, 5.0),
        NativeCallResult::Resource(_) => panic!("sum returned a resource"),
    }
    let resource = match extension
        .call_json("counter", &serde_json::json!([]))
        .unwrap()
    {
        NativeCallResult::Resource(resource) => resource,
        NativeCallResult::Json(_) => panic!("counter returned JSON"),
    };
    assert_eq!(resource.type_name(), "example.counter");
}

#[test]
fn rejects_non_v1_and_size_mismatched_artifacts_before_loading() {
    let library = example_library();
    let permissions = PermissionSet::sandboxed().allow_native_extensions();

    let mut wrong_abi = artifact(library);
    wrong_abi.abi = 2;
    let missing = library.with_extension("missing-native-extension");
    let abi_error =
        match NativeExtension::load_verified(&missing, &wrong_abi, &permissions, "example") {
            Ok(_) => panic!("non-v1 artifact should be rejected"),
            Err(error) => error,
        };
    assert_eq!(abi_error.code, "NATIVE_ABI");

    let mut wrong_size = artifact(library);
    wrong_size.size += 1;
    let size_error =
        match NativeExtension::load_verified(library, &wrong_size, &permissions, "example") {
            Ok(_) => panic!("size-mismatched artifact should be rejected"),
            Err(error) => error,
        };
    assert_eq!(size_error.code, "NATIVE_LIMIT");
}

#[test]
fn rejects_directory_native_artifacts() {
    let directory = std::env::temp_dir();
    let artifact = NativeArtifact {
        abi: 1,
        target: yanxu::package::current_target(),
        path: directory.to_string_lossy().into_owned(),
        checksum: "0".repeat(64),
        size: std::fs::metadata(&directory).unwrap().len(),
    };
    let error = match NativeExtension::load_verified(
        &directory,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    ) {
        Ok(_) => panic!("directory artifact should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code, "NATIVE_IO");
}

#[cfg(any(unix, windows))]
#[test]
fn rejects_symlinked_or_reparsed_native_artifacts_without_following_them() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_file as symlink;

    let library = example_library();
    let artifact = artifact(library);
    let link = std::env::temp_dir().join(format!(
        "yanxu-native-link-{}-{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::env::consts::DLL_SUFFIX
    ));
    symlink(library, &link).unwrap();
    let error = match NativeExtension::load_verified(
        &link,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    ) {
        Ok(_) => panic!("symlinked artifact should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code, "NATIVE_IO");
    std::fs::remove_file(link).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_fifo_native_artifacts_without_blocking() {
    let fifo = std::env::temp_dir().join(format!(
        "yanxu-native-fifo-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let artifact = NativeArtifact {
        abi: 1,
        target: yanxu::package::current_target(),
        path: fifo.to_string_lossy().into_owned(),
        checksum: "0".repeat(64),
        size: 0,
    };
    let error = match NativeExtension::load_verified(
        &fifo,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    ) {
        Ok(_) => panic!("FIFO artifact should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code, "NATIVE_IO");
    std::fs::remove_file(fifo).unwrap();
}

#[test]
fn loads_verified_native_artifacts_from_relative_paths() {
    let library = example_library();
    let current = std::env::current_dir().unwrap();
    let relative = library.strip_prefix(&current).unwrap();
    let extension = NativeExtension::load_verified(
        relative,
        &artifact(library),
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    )
    .unwrap();
    assert_eq!(extension.name(), "example");
}

#[test]
fn replacing_the_original_after_verification_cannot_change_loaded_code() {
    let source = example_library();
    let path = std::env::temp_dir().join(format!(
        "yanxu-native-replacement-{}-{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::copy(source, &path).unwrap();
    let artifact = artifact(&path);
    let extension = NativeExtension::load_verified(
        &path,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    )
    .unwrap();
    std::fs::write(&path, b"replaced-after-verification").unwrap();
    match extension
        .call_json("sum", &serde_json::json!([4, 5]))
        .unwrap()
    {
        NativeCallResult::Json(value) => assert_eq!(value, 9.0),
        NativeCallResult::Resource(_) => panic!("sum returned a resource"),
    }
    drop(extension);
    std::fs::remove_file(path).unwrap();
}

struct CallbackState {
    extension: *const NativeExtension,
    depth: usize,
    maximum: usize,
}

unsafe extern "C" fn recursive_callback(
    context: *mut c_void,
    _name: *const u8,
    _name_length: usize,
    arguments: *const u8,
    arguments_length: usize,
    output: *mut YanxuNativeOutputV1,
    _error: *mut YanxuNativeErrorV1,
) -> i32 {
    if context.is_null() || output.is_null() {
        return 1;
    }
    let state = context.cast::<CallbackState>();
    // SAFETY: The test owns CallbackState for the complete synchronous recursive call.
    let depth = unsafe { (*state).depth + 1 };
    unsafe { (*state).depth = depth };
    let value = if depth < unsafe { (*state).maximum } {
        let callback = YanxuNativeCallbackV1 {
            abi_version: 1,
            struct_size: std::mem::size_of::<YanxuNativeCallbackV1>(),
            context,
            invoke: Some(recursive_callback),
        };
        let bytes = unsafe { std::slice::from_raw_parts(arguments, arguments_length) };
        let Ok(arguments) = serde_json::from_slice(bytes) else {
            unsafe { (*state).depth -= 1 };
            return 1;
        };
        let extension = unsafe { &*(*state).extension };
        match extension.call_json_with_callback("callback", &arguments, Some(&callback)) {
            Ok(NativeCallResult::Json(value)) => value,
            _ => {
                unsafe { (*state).depth -= 1 };
                return 1;
            }
        }
    } else {
        serde_json::json!(depth)
    };
    let Ok(bytes) = serde_json::to_vec(&value) else {
        unsafe { (*state).depth -= 1 };
        return 1;
    };
    let bytes = bytes.into_boxed_slice();
    let length = bytes.len();
    let json = Box::into_raw(bytes).cast::<u8>();
    unsafe {
        *output = YanxuNativeOutputV1 {
            kind: NATIVE_OUTPUT_JSON,
            json,
            json_length: length,
            resource: ptr::null_mut(),
            resource_type: ptr::null(),
            resource_type_length: 0,
            drop_resource: None,
        };
        (*state).depth -= 1;
    }
    NATIVE_OK
}

#[test]
fn native_callbacks_support_bounded_reentrant_recursion() {
    let library = example_library();
    let artifact = artifact(library);
    let extension = NativeExtension::load_verified(
        library,
        &artifact,
        &PermissionSet::sandboxed().allow_native_extensions(),
        "example",
    )
    .unwrap();
    let mut state = CallbackState {
        extension: &extension,
        depth: 0,
        maximum: 3,
    };
    let callback = YanxuNativeCallbackV1 {
        abi_version: 1,
        struct_size: std::mem::size_of::<YanxuNativeCallbackV1>(),
        context: (&mut state as *mut CallbackState).cast(),
        invoke: Some(recursive_callback),
    };
    match extension
        .call_json_with_callback("callback", &serde_json::json!([1]), Some(&callback))
        .unwrap()
    {
        NativeCallResult::Json(value) => assert_eq!(value, 3),
        NativeCallResult::Resource(_) => panic!("callback returned a resource"),
    }
    assert_eq!(state.depth, 0);
}

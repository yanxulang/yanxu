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

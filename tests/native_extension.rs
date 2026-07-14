#![cfg(not(target_family = "wasm"))]

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use yanxu::native_abi::{NativeCallResult, NativeExtension};
use yanxu::package::NativeArtifact;
use yanxu::permissions::PermissionSet;

#[test]
fn loads_verified_native_functions_constants_and_resources() {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "yanxu-native-example"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(status.success(), "example extension failed to build");
    let library = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(format!(
            "{}yanxu_native_example{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    assert!(
        library.is_file(),
        "example extension was not built: {}",
        library.display()
    );
    let checksum = format!("{:x}", Sha256::digest(std::fs::read(&library).unwrap()));
    let artifact = NativeArtifact {
        target: yanxu::package::current_target(),
        path: library.to_string_lossy().into_owned(),
        checksum,
    };
    let denied = match NativeExtension::load_verified(
        &library,
        &artifact,
        &PermissionSet::sandboxed(),
        "example",
    ) {
        Ok(_) => panic!("sandboxed loader should reject native extensions"),
        Err(error) => error,
    };
    assert_eq!(denied.code, "NATIVE_PERMISSION");

    let extension = NativeExtension::load_verified(
        &library,
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

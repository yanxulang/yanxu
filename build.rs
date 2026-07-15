use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=YANXU_BUILD_SHA");
    emit_git_rerun_paths();

    let commit = std::env::var("YANXU_BUILD_SHA")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(git_commit)
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".into());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    emit_windows_runtime_stack(&target);
    println!("cargo:rustc-env=YANXU_BUILD_SHA={commit}");
    println!("cargo:rustc-env=YANXU_BUILD_TARGET={target}");
    println!("cargo:rustc-env=YANXU_BUILD_PROFILE={profile}");
}

fn emit_windows_runtime_stack(target: &str) {
    if target.ends_with("-pc-windows-msvc") {
        // The VM owner thread also pumps native GUI callbacks. Reserve enough
        // stack for ordinary Yanxu method nesting inside that callback path;
        // Windows executables otherwise receive the 1 MiB linker default.
        println!("cargo:rustc-link-arg-bin=yanxu=/STACK:8388608");
    }
}

fn emit_git_rerun_paths() {
    if let Some(path) = git_output(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_output(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn git_commit() -> Option<String> {
    git_output(&["rev-parse", "HEAD"])
}

fn git_output(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(std::env::var_os("CARGO_MANIFEST_DIR")?)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

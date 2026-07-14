use std::fs;
use std::process::Command;

fn temporary_directory(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "yanxu-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn cli_builds_source_independent_yxb_and_standalone_applications() {
    let root = temporary_directory("application-cli");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("言序.toml"),
        "[包]\n格式=2\n名称='命令应用'\n版本='0.1.0'\n言序='>=1.1.5'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n",
    )
    .unwrap();
    fs::write(root.join("src/模块.yx"), "公 定 答：数 为 42；\n").unwrap();
    fs::write(
        root.join("src/主.yx"),
        "引「模块.yx」为 模块；引「标准:环境」为 环境；言 模块.答；言 环境.参数（）【0】；\n",
    )
    .unwrap();
    let runtime = env!("CARGO_BIN_EXE_yanxu");
    let archive = root.join("命令应用.yxb");
    let standalone = root.join(format!("命令应用{}", std::env::consts::EXE_SUFFIX));

    let compile = Command::new(runtime)
        .args(["compile", root.to_str().unwrap(), "-o"])
        .arg(&archive)
        .arg("--release")
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let standalone_compile = Command::new(runtime)
        .args(["compile", root.to_str().unwrap(), "-o"])
        .arg(&standalone)
        .arg("--release")
        .arg("--standalone")
        .output()
        .unwrap();
    assert!(
        standalone_compile.status.success(),
        "{}",
        String::from_utf8_lossy(&standalone_compile.stderr)
    );
    fs::remove_dir_all(root.join("src")).unwrap();

    let run = Command::new(runtime)
        .arg("run")
        .arg(&archive)
        .args(["--", "归档参数"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "42\n归档参数\n");

    let standalone_run = Command::new(&standalone).arg("独立参数").output().unwrap();
    assert!(
        standalone_run.status.success(),
        "{}",
        String::from_utf8_lossy(&standalone_run.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&standalone_run.stdout),
        "42\n独立参数\n"
    );
    fs::remove_dir_all(root).ok();
}

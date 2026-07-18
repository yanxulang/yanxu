use semver::Version;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn project_status_matches_implemented_contracts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = fs::read_to_string(root.join("docs/project/status.md")).unwrap();
    let metadata = status_metadata(&status);

    let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    assert_eq!(metadata["current_version"], current_version.to_string());
    assert_eq!(package_version(&root), current_version);
    assert_eq!(example_version(&root), current_version);

    assert_eq!(metadata["language_spec_version"], 1);
    assert!(root.join("spec/language/v1/README.md").is_file());

    assert_eq!(
        metadata["manifest_format"],
        json!({
            "current": yanxu::package::MANIFEST_FORMAT_VERSION,
            "readable": yanxu::package::SUPPORTED_MANIFEST_FORMATS,
        })
    );
    assert_eq!(
        metadata["lock_format"],
        json!({
            "current": yanxu::package::LOCK_FORMAT_VERSION,
            "readable": yanxu::package::SUPPORTED_LOCK_FORMATS,
        })
    );
    assert_eq!(
        metadata["yxb_format"],
        json!({
            "current": yanxu::application::YXB_FORMAT_VERSION,
            "readable": [yanxu::application::YXB_FORMAT_VERSION],
        })
    );
    assert_eq!(
        metadata["bytecode_format"],
        json!({
            "current": yanxu::bytecode::BYTECODE_FORMAT_VERSION,
            "readable": [yanxu::bytecode::BYTECODE_FORMAT_VERSION],
        })
    );
    assert_eq!(
        metadata["native_abi"],
        json!({
            "current": yanxu::native_abi_v2::NATIVE_ABI_VERSION_V2,
            "provided": [
                yanxu::native_abi::NATIVE_ABI_VERSION,
                yanxu::native_abi_v2::NATIVE_ABI_VERSION_V2,
            ],
        })
    );
    assert_eq!(
        metadata["engineering_protocol"],
        json!({
            "current": yanxu::engineering::ENGINEERING_PROTOCOL_VERSION,
            "readable": [yanxu::engineering::ENGINEERING_PROTOCOL_VERSION],
        })
    );

    let standard_library = yanxu::stdlib::api_manifest().unwrap();
    assert_eq!(
        metadata["stdlib_api_schema"],
        yanxu::stdlib::API_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(
        metadata["stdlib_modules"],
        standard_library["modules"].as_array().unwrap().len()
    );

    let corpus = compatibility_corpus(&root.join("compat"));
    assert_eq!(
        metadata["compatibility_report_schema"],
        yanxu::compatibility::COMPATIBILITY_SCHEMA_VERSION
    );
    assert_eq!(metadata["compatibility_cases"], corpus.files);
    assert_eq!(metadata["minimum_supported_source_version"], corpus.minimum);

    let cargo = root_cargo(&root);
    assert_eq!(
        metadata["rust_msrv"],
        cargo["package"]
            .get("rust-version")
            .map_or(Value::Null, |value| Value::String(
                value.as_str().unwrap().into()
            ))
    );

    assert_human_status(
        &status,
        &current_version,
        standard_library["modules"].as_array().unwrap().len(),
        &corpus,
    );
    assert_document_links_and_archives(&root, &status, &current_version);
}

fn status_metadata(status: &str) -> Value {
    let (_, after_start) = status
        .split_once("```json\n")
        .expect("status must contain one JSON contract block");
    let (document, _) = after_start
        .split_once("\n```")
        .expect("status JSON contract block must be closed");
    let metadata: Value = serde_json::from_str(document).expect("status JSON must be valid");
    assert_eq!(metadata["status_schema"], 1);
    metadata
}

fn root_cargo(root: &Path) -> toml::Value {
    fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap()
}

fn package_version(root: &Path) -> Version {
    let cargo: toml::Value = fs::read_to_string(root.join("crates/yanxu-package/Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    Version::parse(cargo["package"]["version"].as_str().unwrap()).unwrap()
}

fn example_version(root: &Path) -> Version {
    let manifest = yanxu::package::load(root.join("言序.toml")).unwrap();
    manifest.version
}

struct CorpusStatus {
    files: usize,
    minimum: String,
}

fn compatibility_corpus(root: &Path) -> CorpusStatus {
    let mut files = 0;
    let mut versions = Vec::new();
    for entry in fs::read_dir(root).unwrap().map(Result::unwrap) {
        if !entry.path().is_dir() {
            continue;
        }
        let label = entry.file_name().into_string().unwrap();
        let version = Version::parse(&format!("{label}.0")).unwrap();
        versions.push((version, label));
        files += count_yanxu_sources(&entry.path());
    }
    versions.sort_by(|left, right| left.0.cmp(&right.0));
    CorpusStatus {
        files,
        minimum: versions.first().unwrap().1.clone(),
    }
}

fn count_yanxu_sources(path: &Path) -> usize {
    if path.is_file() {
        return usize::from(path.extension().is_some_and(|extension| extension == "yx"));
    }
    fs::read_dir(path)
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| count_yanxu_sources(&entry.path()))
        .sum()
}

fn assert_human_status(
    status: &str,
    version: &Version,
    standard_modules: usize,
    corpus: &CorpusStatus,
) {
    assert!(status.contains(&format!("- 当前源码版本：`{version}`")));
    assert!(status.contains(&format!(
        "| 包清单 | {} | {} |",
        yanxu::package::MANIFEST_FORMAT_VERSION,
        chinese_versions(yanxu::package::SUPPORTED_MANIFEST_FORMATS)
    )));
    assert!(status.contains(&format!(
        "| 锁文件 | {} | {} |",
        yanxu::package::LOCK_FORMAT_VERSION,
        chinese_versions(yanxu::package::SUPPORTED_LOCK_FORMATS)
    )));
    assert!(status.contains(&format!(
        "| YXB | {0} | {0} |",
        yanxu::application::YXB_FORMAT_VERSION
    )));
    assert!(status.contains(&format!(
        "| 字节码 | {0} | {0} |",
        yanxu::bytecode::BYTECODE_FORMAT_VERSION
    )));
    assert!(status.contains(&format!(
        "| 原生扩展 ABI | {} | {} |",
        yanxu::native_abi_v2::NATIVE_ABI_VERSION_V2,
        chinese_versions(&[
            yanxu::native_abi::NATIVE_ABI_VERSION,
            yanxu::native_abi_v2::NATIVE_ABI_VERSION_V2,
        ])
    )));
    assert!(status.contains(&format!(
        "| 工程协议 | {0} | {0} |",
        yanxu::engineering::ENGINEERING_PROTOCOL_VERSION
    )));
    assert!(status.contains(&format!(
        "| 标准库 API 清单 | {} | {standard_modules} 个模块 |",
        yanxu::stdlib::API_MANIFEST_SCHEMA_VERSION
    )));
    assert!(status.contains(&format!(
        "| 兼容报告 | {} | {} 卷语料 |",
        yanxu::compatibility::COMPATIBILITY_SCHEMA_VERSION,
        corpus.files
    )));
    assert!(status.contains(&format!(
        "- 最早受兼容语料持续验证的源码版本：`{}`",
        corpus.minimum
    )));
}

fn chinese_versions(versions: &[u32]) -> String {
    versions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、")
}

fn assert_document_links_and_archives(root: &Path, status: &str, version: &Version) {
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    assert!(readme.contains("(docs/project/status.md)"));
    assert!(readme.contains(&version.to_string()));

    let changelog = fs::read_to_string(root.join("CHANGELOG.md")).unwrap();
    assert!(changelog.contains(&format!("## {version}")));

    let formats = fs::read_to_string(root.join("spec/language/v1/formats.md")).unwrap();
    assert!(formats.contains("| 原生扩展 ABI | 2 | 1、2 |"));

    assert!(!root.join("DEVELOPMENT.md").exists());
    assert!(!root.join("ROADMAP_1_0.md").exists());
    for path in [
        "docs/project/archive/DEVELOPMENT_0_3_TO_0_7.md",
        "docs/project/archive/ROADMAP_0_8_TO_1_0.md",
    ] {
        let archive = fs::read_to_string(root.join(path)).unwrap();
        assert!(archive.contains("不再描述项目当前状态"));
        assert!(!archive.contains("管理真源"));
    }
    assert!(status.contains("唯一状态真源"));
}

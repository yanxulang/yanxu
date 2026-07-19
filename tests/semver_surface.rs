use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use semver::Version;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, ItemFn, ItemMod, Lit, Pat, Type, UseTree, Visibility};

const BASELINE_TAG: &str = "v1.1.15";
const BASELINE_COMMIT: &str = "baba646a666df45c53ac671a15357bfb79b0b6a4";
const REQUIRE_BASELINE_ENV: &str = "YANXU_REQUIRE_SEMVER_BASELINE";

const BASELINE_RUNTIME_SURFACE: &str = r#"
{
  "native_abi": {
    "v1": {
      "abi_version": 1,
      "callbacks": true,
      "constants": true,
      "functions": true,
      "max_descriptors": 1024,
      "max_error_code_bytes": 256,
      "max_error_message_bytes": 65536,
      "max_json_bytes": 16777216,
      "max_library_bytes": 268435456,
      "max_name_bytes": 1024,
      "opaque_resources": true,
      "structured_errors": true,
      "value_transport": "utf8-json",
      "wasi_dynamic_loading": false
    },
    "v2": {
      "abi_version": 2,
      "borrowed_arguments": true,
      "entry_symbol": "yanxu_native_module_v2",
      "host_event_queue": true,
      "max_byte_string_bytes": 16777216,
      "max_depth": 64,
      "max_descriptors": 2048,
      "max_elements": 65536,
      "max_library_bytes": 268435456,
      "max_string_bytes": 4194304,
      "max_total_bytes": 16777216,
      "module_owned_results": true,
      "persistent_callbacks": true,
      "thread_safe_post": true,
      "typed_values": [
        "null", "bool", "i64", "f64", "utf8", "bytes", "array", "map",
        "resource", "callback", "error"
      ],
      "wasi_dynamic_loading": false
    }
  },
  "engineering_handshake": {
    "bytecode_formats": [2],
    "lock_formats": [1, 2],
    "manifest_formats": [1, 2],
    "native_abi": [1, 2],
    "native_capabilities": {
      "v1": {
        "abi_version": 1,
        "callbacks": true,
        "constants": true,
        "functions": true,
        "max_descriptors": 1024,
        "max_error_code_bytes": 256,
        "max_error_message_bytes": 65536,
        "max_json_bytes": 16777216,
        "max_library_bytes": 268435456,
        "max_name_bytes": 1024,
        "opaque_resources": true,
        "structured_errors": true,
        "value_transport": "utf8-json",
        "wasi_dynamic_loading": false
      },
      "v2": {
        "abi_version": 2,
        "borrowed_arguments": true,
        "entry_symbol": "yanxu_native_module_v2",
        "host_event_queue": true,
        "max_byte_string_bytes": 16777216,
        "max_depth": 64,
        "max_descriptors": 2048,
        "max_elements": 65536,
        "max_library_bytes": 268435456,
        "max_string_bytes": 4194304,
        "max_total_bytes": 16777216,
        "module_owned_results": true,
        "persistent_callbacks": true,
        "thread_safe_post": true,
        "typed_values": [
          "null", "bool", "i64", "f64", "utf8", "bytes", "array", "map",
          "resource", "callback", "error"
        ],
        "wasi_dynamic_loading": false
      }
    },
    "operations": [
      "handshake", "template", "inspect", "edit", "edit_application",
      "resolve", "graph", "plan_update", "outdated", "why", "doctor",
      "workspace", "pack", "bundle", "vendor", "audit"
    ],
    "permission_capabilities": [
      "文件", "网络", "本地网络", "TCP监听", "UDP绑定", "环境", "进程",
      "原生扩展", "图形界面", "剪贴板", "文件对话框", "系统通知", "托盘",
      "打开外部地址", "全局快捷键"
    ],
    "yxb_formats": [1]
  }
}
"#;

#[derive(Clone)]
struct RepositoryView {
    root: PathBuf,
    tag: Option<&'static str>,
}

impl RepositoryView {
    fn current(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            tag: None,
        }
    }

    fn baseline(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            tag: Some(BASELINE_TAG),
        }
    }

    fn read(&self, path: &str) -> Result<String, String> {
        if let Some(tag) = self.tag {
            let output = Command::new("git")
                .args(["show", &format!("{tag}:{path}")])
                .current_dir(&self.root)
                .output()
                .map_err(|error| format!("cannot run git show for {path}: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cannot read {tag}:{path}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|error| format!("{tag}:{path} is not UTF-8: {error}"))
        } else {
            fs::read_to_string(self.root.join(path))
                .map_err(|error| format!("cannot read {path}: {error}"))
        }
    }

    fn json(&self, path: &str) -> Result<Value, String> {
        serde_json::from_str(&self.read(path)?)
            .map_err(|error| format!("invalid JSON in {path}: {error}"))
    }

    fn schema_paths(&self) -> Result<Vec<String>, String> {
        let mut paths = if let Some(tag) = self.tag {
            let output = Command::new("git")
                .args(["ls-tree", "-r", "--name-only", tag, "--", "schemas"])
                .current_dir(&self.root)
                .output()
                .map_err(|error| format!("cannot list {tag} schemas: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cannot list {tag} schemas: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|error| format!("schema path list is not UTF-8: {error}"))?
                .lines()
                .filter(|path| path.ends_with(".json"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        } else {
            fs::read_dir(self.root.join("schemas"))
                .map_err(|error| format!("cannot list schemas: {error}"))?
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let name = entry.file_name().into_string().ok()?;
                    name.ends_with(".json").then(|| format!("schemas/{name}"))
                })
                .collect::<Vec<_>>()
        };
        paths.sort();
        Ok(paths)
    }

    fn rust_sources(&self) -> Result<BTreeMap<String, String>, String> {
        let mut paths = if let Some(tag) = self.tag {
            let output = Command::new("git")
                .args([
                    "ls-tree",
                    "-r",
                    "--name-only",
                    tag,
                    "--",
                    "src",
                    "crates/yanxu-package/src",
                ])
                .current_dir(&self.root)
                .output()
                .map_err(|error| format!("cannot list {tag} Rust sources: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cannot list {tag} Rust sources: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|error| format!("Rust source path list is not UTF-8: {error}"))?
                .lines()
                .filter(|path| path.ends_with(".rs"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        } else {
            let mut paths = Vec::new();
            for directory in ["src", "crates/yanxu-package/src"] {
                collect_current_rust_paths(&self.root, &self.root.join(directory), &mut paths)?;
            }
            paths
        };
        paths.sort();
        paths.dedup();
        paths
            .into_iter()
            .map(|path| self.read(&path).map(|source| (path, source)))
            .collect()
    }
}

fn collect_current_rust_paths(
    repository: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("cannot read entry in {}: {error}", directory.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_current_rust_paths(repository, &path, paths)?;
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            let relative = path.strip_prefix(repository).map_err(|error| {
                format!(
                    "cannot make {} repository-relative: {error}",
                    path.display()
                )
            })?;
            paths.push(repository_path(relative)?);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RequiredBump {
    Patch,
    Minor,
    Major,
}

#[derive(Debug)]
struct SurfaceChange {
    bump: RequiredBump,
    kind: &'static str,
    path: String,
}

#[test]
fn classifies_additions_removals_and_required_fields() {
    let baseline = normalized(json!({
        "surface": {"kept": 1},
        "required_fields": {"name": "string"}
    }));

    let addition = normalized(json!({
        "surface": {"kept": 1, "added": true},
        "required_fields": {"name": "string"}
    }));
    assert_eq!(classify(&baseline, &addition).0, RequiredBump::Minor);

    let removal = normalized(json!({
        "surface": {},
        "required_fields": {"name": "string"}
    }));
    assert_eq!(classify(&baseline, &removal).0, RequiredBump::Major);

    let required_addition = normalized(json!({
        "surface": {"kept": 1},
        "required_fields": {"name": "string", "entry": "string"}
    }));
    assert_eq!(
        classify(&baseline, &required_addition).0,
        RequiredBump::Major
    );

    let changed = normalized(json!({
        "surface": {"kept": 2},
        "required_fields": {"name": "string"}
    }));
    assert_eq!(classify(&baseline, &changed).0, RequiredBump::Major);

    let choice_baseline = normalized(json!({
        "type": "CHOICE",
        "members": [{"type": "STRING", "value": "令"}]
    }));
    let choice_addition = normalized(json!({
        "type": "CHOICE",
        "members": [
            {"type": "STRING", "value": "令"},
            {"type": "STRING", "value": "定"}
        ]
    }));
    assert_eq!(
        classify(&choice_baseline, &choice_addition).0,
        RequiredBump::Minor
    );

    let sequence_baseline = normalized(json!({
        "type": "SEQ",
        "members": ["令", "为"]
    }));
    let sequence_changed = normalized(json!({
        "type": "SEQ",
        "members": ["为", "令"]
    }));
    assert_eq!(
        classify(&sequence_baseline, &sequence_changed).0,
        RequiredBump::Major
    );
}

#[test]
fn reviewed_patch_changes_require_exact_paths_and_values() {
    let path = "native_and_embedding_abi/rust/yanxu/stdlib/const/BYTES_MAX_VALUE_BYTES/value"
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let baseline = Value::String("4 * 1024 * 1024".into());
    let current = Value::String("16 * 1024 * 1024".into());
    let mut changes = Vec::new();
    compare_values(&baseline, &current, &mut path.clone(), &mut changes);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].bump, RequiredBump::Patch);

    let changed_again = Value::String("32 * 1024 * 1024".into());
    let mut changes = Vec::new();
    compare_values(&baseline, &changed_again, &mut path.clone(), &mut changes);
    assert_eq!(changes[0].bump, RequiredBump::Major);

    let mut wrong_path = path;
    *wrong_path.last_mut().unwrap() = "type".into();
    let mut changes = Vec::new();
    compare_values(&baseline, &current, &mut wrong_path, &mut changes);
    assert_eq!(changes[0].bump, RequiredBump::Major);
}

#[test]
fn nested_public_rust_addition_requires_minor() {
    let baseline = fixture_sources(&[
        ("src/lib.rs", "pub mod api;\n"),
        ("src/api/mod.rs", "pub struct Stable;\n"),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let current = fixture_sources(&[
        ("src/lib.rs", "pub mod api;\n"),
        ("src/api/mod.rs", "pub struct Stable;\npub fn added() {}\n"),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);

    let baseline = normalized(rust_public_surface_from_sources(&baseline).unwrap());
    let current = normalized(rust_public_surface_from_sources(&current).unwrap());
    assert_eq!(classify(&baseline, &current).0, RequiredBump::Minor);
}

#[test]
fn doc_hidden_public_rust_addition_is_internal() {
    let baseline = fixture_sources(&[
        ("src/lib.rs", "pub mod api;\n"),
        ("src/api.rs", "pub struct Stable;\n"),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let current = fixture_sources(&[
        ("src/lib.rs", "pub mod api;\n"),
        (
            "src/api.rs",
            concat!(
                "pub struct Stable;\n",
                "#[doc(hidden)]\npub fn internal() {}\n",
                "#[doc(hidden)]\npub struct Internal;\n",
                "impl Internal { pub fn method_on_hidden_type() {} }\n",
                "impl Stable { #[doc(hidden)] pub fn hidden_method() {} }\n",
                "mod private;\n",
                "#[doc(hidden)]\npub use private::*;\n",
            ),
        ),
        ("src/api/private.rs", "pub fn hidden_reexport() {}\n"),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);

    let baseline = normalized(rust_public_surface_from_sources(&baseline).unwrap());
    let current = normalized(rust_public_surface_from_sources(&current).unwrap());
    assert_eq!(baseline, current);
    assert_eq!(classify(&baseline, &current).0, RequiredBump::Patch);
}

#[test]
fn package_crate_reexported_public_addition_requires_minor() {
    let baseline = fixture_sources(&[
        ("src/lib.rs", ""),
        (
            "crates/yanxu-package/src/lib.rs",
            "mod package;\npub use package::*;\n",
        ),
        (
            "crates/yanxu-package/src/package.rs",
            "pub fn stable() {}\n",
        ),
    ]);
    let current = fixture_sources(&[
        ("src/lib.rs", ""),
        (
            "crates/yanxu-package/src/lib.rs",
            "mod package;\npub use package::*;\n",
        ),
        (
            "crates/yanxu-package/src/package.rs",
            "pub fn stable() {}\npub fn added() {}\n",
        ),
    ]);

    let baseline = normalized(rust_public_surface_from_sources(&baseline).unwrap());
    let current = normalized(rust_public_surface_from_sources(&current).unwrap());
    assert_eq!(classify(&baseline, &current).0, RequiredBump::Minor);
}

#[test]
fn collects_public_rust_item_kinds_and_impl_members() {
    let sources = fixture_sources(&[
        (
            "src/lib.rs",
            concat!(
                "pub fn function() {}\n",
                "pub struct Record { pub field: u8, private: u8 }\n",
                "pub enum Choice { First }\n",
                "pub union Bits { pub integer: u32, pub number: f32 }\n",
                "pub type Alias = u8;\n",
                "pub const LIMIT: u8 = 1;\n",
                "pub static VALUE: u8 = 1;\n",
                "pub trait Contract { fn call(&self); }\n",
                "pub use external::Thing;\n",
                "#[macro_export]\nmacro_rules! exported { () => {} }\n",
                "struct Private;\n",
                "impl Private { pub fn not_publicly_reachable() {} }\n",
                "impl Record {\n",
                "    pub fn new() -> Self { Self { field: 0, private: 0 } }\n",
                "    pub const ZERO: u8 = 0;\n",
                "    pub type Item = u8;\n",
                "}\n",
            ),
        ),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let surface = collect_crate_public_surface(&sources, "src/lib.rs")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    for expected in [
        "fn/function",
        "struct/Record",
        "enum/Choice",
        "union/Bits",
        "type/Alias",
        "const/LIMIT",
        "static/VALUE",
        "trait/Contract",
        "use/external :: Thing",
        "macro/exported",
        "impl/Record/fn/new",
        "impl/Record/const/ZERO",
        "impl/Record/type/Item",
    ] {
        assert!(
            surface.contains(expected),
            "missing Rust surface {expected}"
        );
    }
    assert!(!surface.contains("impl/Private/fn/not_publicly_reachable"));
}

#[test]
fn public_constant_value_and_type_changes_require_review() {
    let baseline = fixture_sources(&[
        (
            "src/lib.rs",
            concat!(
                "pub struct Record;\n",
                "pub const LIMIT: u8 = 1;\n",
                "pub static VALUE: u8 = 1;\n",
                "impl Record { pub const ZERO: u8 = 0; }\n",
            ),
        ),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let changed_values = fixture_sources(&[
        (
            "src/lib.rs",
            concat!(
                "pub struct Record;\n",
                "pub const LIMIT: u8 = 2;\n",
                "pub static VALUE: u8 = 2;\n",
                "impl Record { pub const ZERO: u8 = 1; }\n",
            ),
        ),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let changed_type = fixture_sources(&[
        (
            "src/lib.rs",
            concat!(
                "pub struct Record;\n",
                "pub const LIMIT: u16 = 2;\n",
                "pub static VALUE: u8 = 2;\n",
                "impl Record { pub const ZERO: u8 = 1; }\n",
            ),
        ),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);

    let baseline = normalized(rust_public_surface_from_sources(&baseline).unwrap());
    let changed_values = normalized(rust_public_surface_from_sources(&changed_values).unwrap());
    let changed_type = normalized(rust_public_surface_from_sources(&changed_type).unwrap());
    assert_ne!(baseline, changed_values);
    assert_eq!(classify(&baseline, &changed_values).0, RequiredBump::Major);
    assert_eq!(classify(&baseline, &changed_type).0, RequiredBump::Major);
}

#[test]
fn named_reexport_does_not_expose_unselected_public_items() {
    let sources = fixture_sources(&[
        ("src/lib.rs", ""),
        (
            "crates/yanxu-package/src/lib.rs",
            "mod private;\npub use private::Selected;\n",
        ),
        (
            "crates/yanxu-package/src/private.rs",
            concat!(
                "pub struct Selected;\n",
                "impl Selected { pub fn selected_method() {} }\n",
                "pub struct NotSelected;\n",
                "impl NotSelected { pub fn unselected_method() {} }\n",
                "pub fn unselected_function() {}\n",
            ),
        ),
    ]);
    let surface = collect_crate_public_surface(&sources, "crates/yanxu-package/src/lib.rs")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    assert!(surface.contains("private/struct/Selected"));
    assert!(surface.contains("impl/private::Selected/fn/selected_method"));
    assert!(!surface.contains("private/struct/NotSelected"));
    assert!(!surface.contains("impl/private::NotSelected/fn/unselected_method"));
    assert!(!surface.contains("private/fn/unselected_function"));
}

#[test]
fn inherent_impl_in_another_module_is_part_of_the_public_type_surface() {
    let sources = fixture_sources(&[
        ("src/lib.rs", "pub mod api;\npub mod extensions;\n"),
        ("src/api.rs", "pub struct Public;\nstruct Private;\n"),
        (
            "src/extensions.rs",
            concat!(
                "impl crate::api::Public { pub fn cross_module() {} }\n",
                "pub struct Local;\n",
                "impl Local { pub fn local() {} }\n",
            ),
        ),
        ("crates/yanxu-package/src/lib.rs", ""),
    ]);
    let surface = collect_crate_public_surface(&sources, "src/lib.rs")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    assert!(surface.contains("impl/api::Public/fn/cross_module"));
    assert!(surface.contains("impl/extensions::Local/fn/local"));
}

fn fixture_sources(files: &[(&str, &str)]) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
        .collect()
}

#[test]
fn declared_version_matches_v1_1_15_public_surface() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(commit) = baseline_commit(&root) else {
        if env::var_os(REQUIRE_BASELINE_ENV).is_some() {
            panic!("{BASELINE_TAG} is required for the SemVer public-surface gate");
        }
        eprintln!("skipping SemVer comparison because {BASELINE_TAG} is unavailable");
        return;
    };
    assert_eq!(
        commit, BASELINE_COMMIT,
        "{BASELINE_TAG} does not point to the approved baseline commit"
    );

    let baseline_view = RepositoryView::baseline(&root);
    let current_view = RepositoryView::current(&root);
    let baseline = normalized(
        collect_surface(&baseline_view, true)
            .unwrap_or_else(|error| panic!("cannot collect baseline surface: {error}")),
    );
    let current = normalized(
        collect_surface(&current_view, false)
            .unwrap_or_else(|error| panic!("cannot collect current surface: {error}")),
    );
    let (required, changes) = classify(&baseline, &current);

    let (baseline_core, baseline_package) = declared_versions(&baseline_view)
        .unwrap_or_else(|error| panic!("cannot read baseline versions: {error}"));
    let (current_core, current_package) = declared_versions(&current_view)
        .unwrap_or_else(|error| panic!("cannot read current versions: {error}"));
    assert_eq!(baseline_core, Version::new(1, 1, 15));
    assert_eq!(baseline_core, baseline_package);
    assert_eq!(
        current_core, current_package,
        "yanxu and yanxu-package versions must move together"
    );

    let declared = declared_bump(&baseline_core, &current_core).unwrap_or_else(|error| {
        panic!("invalid version movement from {baseline_core} to {current_core}: {error}")
    });
    if declared < required {
        let details = changes
            .iter()
            .take(40)
            .map(|change| format!("{:?} {} {}", change.bump, change.kind, change.path))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "public surface requires a {required:?} version bump, but {current_core} declares {declared:?}\n{details}"
        );
    }
}

fn baseline_commit(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", &format!("{BASELINE_TAG}^{{commit}}")])
        .current_dir(root)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn collect_surface(view: &RepositoryView, baseline: bool) -> Result<Value, String> {
    let lexer = view.read("src/lexer.rs")?;
    let cli = view.read("src/main.rs")?;
    let engineering = view.read("src/engineering.rs")?;
    let package = view.read("crates/yanxu-package/src/package.rs")?;
    let application = view.read("src/application.rs")?;
    let bytecode = view.read("src/bytecode.rs")?;

    let mut schemas = Map::new();
    for path in view.schema_paths()? {
        let name = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid schema path {path}"))?;
        schemas.insert(name.to_owned(), view.json(&path)?);
    }

    let runtime = if baseline {
        serde_json::from_str(BASELINE_RUNTIME_SURFACE)
            .map_err(|error| format!("invalid baseline runtime surface: {error}"))?
    } else {
        current_runtime_surface()?
    };

    Ok(json!({
        "language": {
            "keywords": keyword_surface(&lexer)?,
            "tree_sitter_grammar": view.json("tree-sitter-yanxu/src/grammar.json")?,
            "tree_sitter_nodes": view.json("tree-sitter-yanxu/src/node-types.json")?,
        },
        "standard_library": view.json("stdlib/api-v1.json")?,
        "formats": {
            "manifest": {
                "aliases": call_field_surface(
                    &package,
                    &["table_alias", "string_alias", "array_alias", "integer_alias", "bool_alias"],
                )?,
                "public_fields": struct_field_surface(
                    &package,
                    &["Manifest", "ApplicationConfig", "WindowConfig", "NativeArtifact"],
                )?,
                "versions": const_surface(
                    &package,
                    &["MANIFEST_FORMAT_VERSION", "SUPPORTED_MANIFEST_FORMATS"],
                )?,
            },
            "lock": {
                "fields": struct_field_surface(&package, &["LockFile", "LockedPackage"] )?,
                "versions": const_surface(
                    &package,
                    &["LOCK_FORMAT_VERSION", "SUPPORTED_LOCK_FORMATS"],
                )?,
            },
            "yxb": const_surface(&application, &["YXB_FORMAT_VERSION"] )?,
            "bytecode": const_surface(&bytecode, &["BYTECODE_FORMAT_VERSION"] )?,
        },
        "native_and_embedding_abi": {
            "runtime": runtime["native_abi"].clone(),
            "c_embedding_header": header_surface(&view.read("include/yanxu.h")?),
            "native_header": header_surface(&view.read("include/yanxu_native.h")?),
            "rust": rust_public_surface(view)?,
        },
        "engineering_protocol": {
            "version": const_surface(&engineering, &["ENGINEERING_PROTOCOL_VERSION"] )?,
            "operations": match_string_surface(&engineering, "handle", "operation")?,
            "request_fields": call_field_surface(
                &engineering,
                &["required_string", "optional_string", "optional_bool", "optional_u32"],
            )?,
            "response_fields": json_key_surface(&engineering)?,
            "handshake": runtime["engineering_handshake"].clone(),
        },
        "stable_cli": {
            "recognized_tokens": cli_token_surface(&cli)?,
            "help_patterns": help_pattern_surface(&cli)?,
        },
        "json_schemas": Value::Object(schemas),
    }))
}

fn current_runtime_surface() -> Result<Value, String> {
    let mut handshake = yanxu::engineering::handle(&json!({
        "protocol_version": 1,
        "operation": "handshake"
    }))
    .map_err(|error| error.to_string())?;
    let object = handshake
        .as_object_mut()
        .ok_or_else(|| "engineering handshake is not an object".to_owned())?;
    object.remove("yanxu_version");
    object.remove("build");
    object.remove("target");
    Ok(json!({
        "native_abi": {
            "v1": yanxu::native_abi::capabilities(),
            "v2": yanxu::native_abi_v2::capabilities(),
        },
        "engineering_handshake": handshake,
    }))
}

fn declared_versions(view: &RepositoryView) -> Result<(Version, Version), String> {
    fn version(text: &str, path: &str) -> Result<Version, String> {
        let document = text
            .parse::<toml::Value>()
            .map_err(|error| format!("invalid {path}: {error}"))?;
        let raw = document
            .get("package")
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{path} has no package.version"))?;
        Version::parse(raw).map_err(|error| format!("invalid version in {path}: {error}"))
    }

    Ok((
        version(&view.read("Cargo.toml")?, "Cargo.toml")?,
        version(
            &view.read("crates/yanxu-package/Cargo.toml")?,
            "crates/yanxu-package/Cargo.toml",
        )?,
    ))
}

fn declared_bump(baseline: &Version, current: &Version) -> Result<RequiredBump, String> {
    if current < baseline {
        return Err("version cannot move backwards".into());
    }
    if current.major > baseline.major {
        Ok(RequiredBump::Major)
    } else if current.minor > baseline.minor {
        Ok(RequiredBump::Minor)
    } else if current.major == baseline.major && current.minor == baseline.minor {
        Ok(RequiredBump::Patch)
    } else {
        Err("version movement crosses an invalid boundary".into())
    }
}

fn parse_source(source: &str) -> Result<syn::File, String> {
    syn::parse_file(source).map_err(|error| format!("cannot parse Rust surface: {error}"))
}

fn find_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a ItemFn, String> {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .ok_or_else(|| format!("cannot find function {name}"))
}

fn keyword_surface(source: &str) -> Result<Value, String> {
    struct Keywords {
        values: BTreeMap<String, String>,
    }

    impl<'ast> Visit<'ast> for Keywords {
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            for arm in &node.arms {
                let Some(kind) = token_kind(&arm.body) else {
                    continue;
                };
                for spelling in pattern_strings(&arm.pat) {
                    self.values.insert(spelling, kind.clone());
                }
            }
            visit::visit_expr_match(self, node);
        }
    }

    let file = parse_source(source)?;
    let function = find_function(&file, "keyword")?;
    let mut visitor = Keywords {
        values: BTreeMap::new(),
    };
    visitor.visit_block(&function.block);
    serde_json::to_value(visitor.values).map_err(|error| error.to_string())
}

fn token_kind(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = expression else {
        return None;
    };
    let mut segments = path.path.segments.iter().rev();
    let kind = segments.next()?.ident.to_string();
    (segments.next()?.ident == "TokenKind").then_some(kind)
}

fn pattern_strings(pattern: &Pat) -> Vec<String> {
    match pattern {
        Pat::Lit(literal) => match &literal.lit {
            Lit::Str(value) => vec![value.value()],
            _ => Vec::new(),
        },
        Pat::Or(or) => or.cases.iter().flat_map(pattern_strings).collect(),
        _ => Vec::new(),
    }
}

fn const_surface(source: &str, names: &[&str]) -> Result<Value, String> {
    let requested = names.iter().copied().collect::<BTreeSet<_>>();
    let file = parse_source(source)?;
    let mut values = Map::new();
    for item in file.items {
        if let Item::Const(item) = item {
            let name = item.ident.to_string();
            if requested.contains(name.as_str()) {
                values.insert(name, expression_surface(&item.expr));
            }
        }
    }
    for name in names {
        if !values.contains_key(*name) {
            return Err(format!("cannot find constant {name}"));
        }
    }
    Ok(Value::Object(values))
}

fn expression_surface(expression: &Expr) -> Value {
    match expression {
        Expr::Lit(literal) => match &literal.lit {
            Lit::Str(value) => Value::String(value.value()),
            Lit::Bool(value) => Value::Bool(value.value),
            Lit::Int(value) => value
                .base10_parse::<u64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(compact_tokens(expression))),
            Lit::Float(value) => value
                .base10_parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .unwrap_or_else(|| Value::String(compact_tokens(expression))),
            _ => Value::String(compact_tokens(expression)),
        },
        Expr::Array(array) => Value::Array(
            array
                .elems
                .iter()
                .map(expression_surface)
                .collect::<Vec<_>>(),
        ),
        Expr::Reference(reference) => expression_surface(&reference.expr),
        _ => Value::String(compact_tokens(expression)),
    }
}

fn call_field_surface(source: &str, call_names: &[&str]) -> Result<Value, String> {
    struct Calls<'a> {
        scope: String,
        allowed: BTreeSet<&'a str>,
        required: BTreeMap<String, Value>,
        optional: BTreeMap<String, Value>,
    }

    impl<'ast> Visit<'ast> for Calls<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            let Some(call_name) = expression_path_name(&node.func) else {
                visit::visit_expr_call(self, node);
                return;
            };
            if self.allowed.contains(call_name.as_str()) {
                let names = node
                    .args
                    .iter()
                    .nth(1)
                    .map(expression_strings)
                    .unwrap_or_default();
                if let Some(primary) = names.first() {
                    let key = format!("{}/{call_name}/{primary}", self.scope);
                    let value = Value::Array(names.into_iter().map(Value::String).collect());
                    if call_name.starts_with("required_") {
                        self.required.insert(key, value);
                    } else {
                        self.optional.insert(key, value);
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let file = parse_source(source)?;
    let allowed = call_names.iter().copied().collect::<BTreeSet<_>>();
    let mut required = BTreeMap::new();
    let mut optional = BTreeMap::new();
    for item in &file.items {
        let Item::Fn(function) = item else {
            continue;
        };
        let mut visitor = Calls {
            scope: function.sig.ident.to_string(),
            allowed: allowed.clone(),
            required: BTreeMap::new(),
            optional: BTreeMap::new(),
        };
        visitor.visit_block(&function.block);
        required.extend(visitor.required);
        optional.extend(visitor.optional);
    }
    Ok(json!({
        "required_fields": required,
        "optional_fields": optional,
    }))
}

fn expression_path_name(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn expression_strings(expression: &Expr) -> Vec<String> {
    match expression {
        Expr::Lit(literal) => match &literal.lit {
            Lit::Str(value) => vec![value.value()],
            _ => Vec::new(),
        },
        Expr::Array(array) => array.elems.iter().flat_map(expression_strings).collect(),
        Expr::Reference(reference) => expression_strings(&reference.expr),
        _ => Vec::new(),
    }
}

fn struct_field_surface(source: &str, names: &[&str]) -> Result<Value, String> {
    let requested = names.iter().copied().collect::<BTreeSet<_>>();
    let file = parse_source(source)?;
    let mut structs = Map::new();
    for item in file.items {
        let Item::Struct(item) = item else {
            continue;
        };
        let name = item.ident.to_string();
        if !requested.contains(name.as_str()) {
            continue;
        }
        let mut required = Map::new();
        let mut optional = Map::new();
        for field in item.fields {
            let Some(ident) = field.ident else {
                continue;
            };
            if !is_public(&field.vis) {
                continue;
            }
            let serialized_name = serde_rename(&field.attrs).unwrap_or_else(|| ident.to_string());
            let signature = Value::String(compact_tokens(&field.ty));
            if is_optional_type(&field.ty) || serde_has_default(&field.attrs) {
                optional.insert(serialized_name, signature);
            } else {
                required.insert(serialized_name, signature);
            }
        }
        structs.insert(
            name,
            json!({"required_fields": required, "optional_fields": optional}),
        );
    }
    for name in names {
        if !structs.contains_key(*name) {
            return Err(format!("cannot find public struct {name}"));
        }
    }
    Ok(Value::Object(structs))
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn is_optional_type(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Option")
}

fn serde_rename(attributes: &[syn::Attribute]) -> Option<String> {
    let mut rename = None;
    for attribute in attributes {
        if !attribute.path().is_ident("serde") {
            continue;
        }
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                rename = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            }
            Ok(())
        });
    }
    rename
}

fn serde_has_default(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("serde") {
            return false;
        }
        let mut found = false;
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("default") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn match_string_surface(source: &str, function: &str, subject: &str) -> Result<Value, String> {
    struct Matches<'a> {
        subject: &'a str,
        values: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for Matches<'_> {
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            let matches_subject = matches!(
                node.expr.as_ref(),
                Expr::Path(path) if path.path.is_ident(self.subject)
            );
            if matches_subject {
                for arm in &node.arms {
                    self.values.extend(pattern_strings(&arm.pat));
                }
            }
            visit::visit_expr_match(self, node);
        }
    }

    let file = parse_source(source)?;
    let function = find_function(&file, function)?;
    let mut visitor = Matches {
        subject,
        values: BTreeSet::new(),
    };
    visitor.visit_block(&function.block);
    Ok(Value::Array(
        visitor.values.into_iter().map(Value::String).collect(),
    ))
}

fn json_key_surface(source: &str) -> Result<Value, String> {
    let file = parse_source(source)?;
    let mut functions = Map::new();
    for item in &file.items {
        let Item::Fn(function) = item else {
            continue;
        };
        let mut keys = BTreeSet::new();
        struct JsonKeys<'a> {
            keys: &'a mut BTreeSet<String>,
        }
        impl<'ast> Visit<'ast> for JsonKeys<'_> {
            fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
                if node
                    .mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "json")
                {
                    collect_colon_keys(node.mac.tokens.clone(), self.keys);
                }
                visit::visit_expr_macro(self, node);
            }
        }
        JsonKeys { keys: &mut keys }.visit_block(&function.block);
        if !keys.is_empty() {
            functions.insert(
                function.sig.ident.to_string(),
                Value::Array(keys.into_iter().map(Value::String).collect()),
            );
        }
    }
    Ok(Value::Object(functions))
}

fn collect_colon_keys(stream: TokenStream, keys: &mut BTreeSet<String>) {
    let tokens = stream.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if let TokenTree::Group(group) = token {
            collect_colon_keys(group.stream(), keys);
        }
        let TokenTree::Literal(literal) = token else {
            continue;
        };
        let Some(TokenTree::Punct(punctuation)) = tokens.get(index + 1) else {
            continue;
        };
        if punctuation.as_char() != ':' {
            continue;
        }
        if let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
            keys.insert(value.value());
        }
    }
}

fn cli_token_surface(source: &str) -> Result<Value, String> {
    struct Equalities {
        values: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for Equalities {
        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if matches!(node.op, syn::BinOp::Eq(_))
                && let Some((name, value)) = identifier_and_string(&node.left, &node.right)
                    .or_else(|| identifier_and_string(&node.right, &node.left))
                && matches!(name.as_str(), "command" | "action" | "flag" | "delimiter")
            {
                self.values.insert(format!("{name}={value}"));
            }
            visit::visit_expr_binary(self, node);
        }
    }

    let file = parse_source(source)?;
    let mut visitor = Equalities {
        values: BTreeSet::new(),
    };
    visitor.visit_file(&file);
    Ok(Value::Array(
        visitor.values.into_iter().map(Value::String).collect(),
    ))
}

fn identifier_and_string(left: &Expr, right: &Expr) -> Option<(String, String)> {
    let Expr::Path(path) = left else {
        return None;
    };
    let name = path.path.get_ident()?.to_string();
    let Expr::Lit(literal) = right else {
        return None;
    };
    let Lit::Str(value) = &literal.lit else {
        return None;
    };
    Some((name, value.value()))
}

fn help_pattern_surface(source: &str) -> Result<Value, String> {
    struct Literals {
        values: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Literals {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            collect_string_literals(node.tokens.clone(), &mut self.values);
            visit::visit_macro(self, node);
        }
    }

    let file = parse_source(source)?;
    let function = find_function(&file, "help")?;
    let mut visitor = Literals { values: Vec::new() };
    visitor.visit_block(&function.block);
    let mut patterns = BTreeSet::new();
    for literal in visitor.values {
        for line in literal.lines().map(str::trim) {
            if !line.starts_with("yanxu") {
                continue;
            }
            let boundary = line
                .as_bytes()
                .windows(2)
                .position(|window| window == b"  ")
                .unwrap_or(line.len());
            patterns.insert(line[..boundary].trim().to_owned());
        }
    }
    Ok(Value::Array(
        patterns.into_iter().map(Value::String).collect(),
    ))
}

fn collect_string_literals(stream: TokenStream, output: &mut Vec<String>) {
    for token in stream {
        match token {
            TokenTree::Group(group) => collect_string_literals(group.stream(), output),
            TokenTree::Literal(literal) => {
                if let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    output.push(value.value());
                }
            }
            _ => {}
        }
    }
}

fn rust_public_surface(view: &RepositoryView) -> Result<Value, String> {
    rust_public_surface_from_sources(&view.rust_sources()?)
}

fn rust_public_surface_from_sources(sources: &BTreeMap<String, String>) -> Result<Value, String> {
    Ok(json!({
        "yanxu": collect_crate_public_surface(sources, "src/lib.rs")?,
        "yanxu_package": collect_crate_public_surface(
            sources,
            "crates/yanxu-package/src/lib.rs",
        )?,
    }))
}

fn collect_crate_public_surface(
    sources: &BTreeMap<String, String>,
    entry: &str,
) -> Result<Value, String> {
    if !sources.contains_key(entry) {
        return Err(format!("cannot find Rust crate entry {entry}"));
    }
    let module_directory = Path::new(entry)
        .parent()
        .ok_or_else(|| format!("Rust crate entry {entry} has no parent directory"))?;
    let mut collector = RustPublicCollector {
        sources,
        surface: Map::new(),
        reachable_types: BTreeSet::new(),
        pending_impls: Vec::new(),
        macro_visited: BTreeSet::new(),
    };
    collector.collect_file(entry, module_directory, &[], &ExportSelection::All)?;
    collector.collect_exported_macros_file(entry, module_directory, &[])?;
    collector.finish_impls();
    Ok(Value::Object(collector.surface))
}

struct RustPublicCollector<'a> {
    sources: &'a BTreeMap<String, String>,
    surface: Map<String, Value>,
    reachable_types: BTreeSet<String>,
    pending_impls: Vec<PendingImpl>,
    macro_visited: BTreeSet<String>,
}

struct PendingImpl {
    owner_candidates: Vec<String>,
    members: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
enum ExportSelection {
    All,
    Names(BTreeSet<String>),
}

impl ExportSelection {
    fn includes(&self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Names(names) => names.contains(name),
        }
    }

    fn merge(&mut self, other: Self) {
        match (&mut *self, other) {
            (Self::All, _) => {}
            (selection, Self::All) => *selection = Self::All,
            (Self::Names(names), Self::Names(other)) => names.extend(other),
        }
    }
}

impl RustPublicCollector<'_> {
    fn collect_file(
        &mut self,
        source_path: &str,
        module_directory: &Path,
        module_path: &[String],
        selection: &ExportSelection,
    ) -> Result<(), String> {
        let source = self
            .sources
            .get(source_path)
            .ok_or_else(|| format!("cannot find Rust module source {source_path}"))?;
        let file = parse_source(source).map_err(|error| format!("{source_path}: {error}"))?;
        self.collect_items(
            &file.items,
            source_path,
            module_directory,
            module_path,
            selection,
        )
    }

    fn collect_items(
        &mut self,
        items: &[Item],
        source_path: &str,
        module_directory: &Path,
        module_path: &[String],
        selection: &ExportSelection,
    ) -> Result<(), String> {
        let modules = items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) => Some((module.ident.to_string(), module)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        for item in items {
            match item {
                Item::Fn(item)
                    if selected_public(&item.sig.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("fn/{}", item.sig.ident),
                        Value::String(compact_tokens(&item.sig)),
                    );
                }
                Item::Struct(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.reachable_types
                        .insert(type_surface_key(module_path, &item.ident.to_string()));
                    let signature = format!(
                        "{} {} {} {}",
                        contract_attributes(&item.attrs),
                        compact_tokens(&item.generics),
                        compact_tokens(&item.generics.where_clause),
                        public_struct_fields(&item.fields)
                    );
                    self.insert(
                        module_path,
                        format!("struct/{}", item.ident),
                        Value::String(signature),
                    );
                }
                Item::Enum(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.reachable_types
                        .insert(type_surface_key(module_path, &item.ident.to_string()));
                    let signature = format!(
                        "{} {} {} {}",
                        contract_attributes(&item.attrs),
                        compact_tokens(&item.generics),
                        compact_tokens(&item.generics.where_clause),
                        public_enum_variants(&item.variants)
                    );
                    self.insert(
                        module_path,
                        format!("enum/{}", item.ident),
                        Value::String(signature),
                    );
                }
                Item::Union(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.reachable_types
                        .insert(type_surface_key(module_path, &item.ident.to_string()));
                    let signature = format!(
                        "{} {} {} {}",
                        contract_attributes(&item.attrs),
                        compact_tokens(&item.generics),
                        compact_tokens(&item.generics.where_clause),
                        public_named_fields(&item.fields),
                    );
                    self.insert(
                        module_path,
                        format!("union/{}", item.ident),
                        Value::String(signature),
                    );
                }
                Item::Type(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("type/{}", item.ident),
                        Value::String(compact_tokens(item)),
                    );
                }
                Item::Const(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("const/{}", item.ident),
                        public_const_surface(item),
                    );
                }
                Item::Static(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("static/{}", item.ident),
                        Value::String(public_static_signature(item)),
                    );
                }
                Item::Trait(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("trait/{}", item.ident),
                        Value::String(public_trait_surface(item)),
                    );
                }
                Item::TraitAlias(item)
                    if selected_public(&item.ident, &item.vis, &item.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("trait_alias/{}", item.ident),
                        Value::String(compact_tokens(item)),
                    );
                }
                Item::Mod(module)
                    if selected_public(&module.ident, &module.vis, &module.attrs, selection) =>
                {
                    self.insert(
                        module_path,
                        format!("mod/{}", module.ident),
                        Value::Bool(true),
                    );
                    self.collect_module(
                        module,
                        source_path,
                        module_directory,
                        module_path,
                        &ExportSelection::All,
                    )?;
                }
                Item::Use(item)
                    if visible_public(&item.vis, &item.attrs)
                        && selection_includes_use(selection, &item.tree) =>
                {
                    self.insert(
                        module_path,
                        format!("use/{}", compact_tokens(&item.tree)),
                        Value::Bool(true),
                    );
                    for (root, nested_selection) in local_use_selections(&item.tree) {
                        if let Some(module) = modules.get(&root) {
                            self.collect_module(
                                module,
                                source_path,
                                module_directory,
                                module_path,
                                &nested_selection,
                            )?;
                        }
                    }
                }
                Item::Impl(item) if item.trait_.is_none() && !is_doc_hidden(&item.attrs) => {
                    if let Some(pending) = pending_public_impl(item, module_path) {
                        self.pending_impls.push(pending);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_module(
        &mut self,
        module: &ItemMod,
        source_path: &str,
        module_directory: &Path,
        parent_module_path: &[String],
        selection: &ExportSelection,
    ) -> Result<(), String> {
        let mut module_path = parent_module_path.to_vec();
        module_path.push(module.ident.to_string());
        if let Some((_, items)) = &module.content {
            return self.collect_items(
                items,
                source_path,
                &module_directory.join(module.ident.to_string()),
                &module_path,
                selection,
            );
        }

        let resolved = resolve_module_source(self.sources, module_directory, module)?;
        let resolved_path = Path::new(&resolved);
        let parent = resolved_path
            .parent()
            .ok_or_else(|| format!("Rust module source {resolved} has no parent directory"))?;
        let child_directory = if resolved_path
            .file_name()
            .is_some_and(|name| name == "mod.rs")
        {
            parent.to_owned()
        } else {
            parent.join(module.ident.to_string())
        };
        self.collect_file(&resolved, &child_directory, &module_path, selection)
    }

    fn collect_exported_macros_file(
        &mut self,
        source_path: &str,
        module_directory: &Path,
        module_path: &[String],
    ) -> Result<(), String> {
        let source = self
            .sources
            .get(source_path)
            .ok_or_else(|| format!("cannot find Rust module source {source_path}"))?;
        let file = parse_source(source).map_err(|error| format!("{source_path}: {error}"))?;
        self.collect_exported_macros_items(&file.items, source_path, module_directory, module_path)
    }

    fn collect_exported_macros_items(
        &mut self,
        items: &[Item],
        source_path: &str,
        module_directory: &Path,
        module_path: &[String],
    ) -> Result<(), String> {
        let visit_key = format!("{source_path}\0{}", module_path.join("::"));
        if !self.macro_visited.insert(visit_key) {
            return Ok(());
        }
        for item in items {
            match item {
                Item::Macro(item)
                    if has_attribute(&item.attrs, "macro_export")
                        && !is_doc_hidden(&item.attrs) =>
                {
                    let Some(ident) = &item.ident else {
                        continue;
                    };
                    self.surface.insert(
                        format!("macro/{ident}"),
                        Value::String(compact_tokens(&item.mac)),
                    );
                }
                Item::Mod(module) => {
                    let mut child_module_path = module_path.to_vec();
                    child_module_path.push(module.ident.to_string());
                    if let Some((_, items)) = &module.content {
                        self.collect_exported_macros_items(
                            items,
                            source_path,
                            &module_directory.join(module.ident.to_string()),
                            &child_module_path,
                        )?;
                    } else {
                        let resolved =
                            resolve_module_source(self.sources, module_directory, module)?;
                        let resolved_path = Path::new(&resolved);
                        let parent = resolved_path.parent().ok_or_else(|| {
                            format!("Rust module source {resolved} has no parent directory")
                        })?;
                        let child_directory = if resolved_path
                            .file_name()
                            .is_some_and(|name| name == "mod.rs")
                        {
                            parent.to_owned()
                        } else {
                            parent.join(module.ident.to_string())
                        };
                        self.collect_exported_macros_file(
                            &resolved,
                            &child_directory,
                            &child_module_path,
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn finish_impls(&mut self) {
        for pending in std::mem::take(&mut self.pending_impls) {
            let owner = pending
                .owner_candidates
                .iter()
                .find(|candidate| self.reachable_types.contains(*candidate))
                .cloned();
            let Some(owner) = owner else {
                continue;
            };
            for (member, value) in pending.members {
                self.surface.insert(format!("impl/{owner}/{member}"), value);
            }
        }
    }

    fn insert(&mut self, module_path: &[String], item: String, value: Value) {
        let key = if module_path.is_empty() {
            item
        } else {
            format!("{}/{}", module_path.join("/"), item)
        };
        self.surface.insert(key, value);
    }
}

fn resolve_module_source(
    sources: &BTreeMap<String, String>,
    module_directory: &Path,
    module: &ItemMod,
) -> Result<String, String> {
    if let Some(explicit) = module_path_attribute(&module.attrs)? {
        let path = repository_path(&module_directory.join(explicit))?;
        return sources.contains_key(&path).then_some(path).ok_or_else(|| {
            format!(
                "cannot find #[path] source for module {} declared under {}",
                module.ident,
                module_directory.display()
            )
        });
    }

    let stem = module_directory.join(module.ident.to_string());
    let candidates = [stem.with_extension("rs"), stem.join("mod.rs")]
        .into_iter()
        .map(|path| repository_path(&path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| sources.contains_key(path))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(format!(
            "cannot find source for module {} declared under {}",
            module.ident,
            module_directory.display()
        )),
        _ => Err(format!(
            "module {} has ambiguous sources: {}",
            module.ident,
            candidates.join(", ")
        )),
    }
}

fn module_path_attribute(attributes: &[Attribute]) -> Result<Option<PathBuf>, String> {
    let mut path = None;
    for attribute in attributes {
        if !attribute.path().is_ident("path") {
            continue;
        }
        let syn::Meta::NameValue(value) = &attribute.meta else {
            return Err("Rust module #[path] must be a string value".into());
        };
        let Expr::Lit(literal) = &value.value else {
            return Err("Rust module #[path] must be a string literal".into());
        };
        let Lit::Str(value) = &literal.lit else {
            return Err("Rust module #[path] must be a string literal".into());
        };
        if path.replace(PathBuf::from(value.value())).is_some() {
            return Err("Rust module has more than one #[path] attribute".into());
        }
    }
    Ok(path)
}

fn repository_path(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop().ok_or_else(|| {
                    format!("repository path escapes its root: {}", path.display())
                })?;
            }
            std::path::Component::Normal(component) => {
                components.push(
                    component.to_str().ok_or_else(|| {
                        format!("repository path is not UTF-8: {}", path.display())
                    })?,
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(format!(
                    "repository path is not relative: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(components.join("/"))
}

#[derive(Debug)]
struct UseTarget {
    path: Vec<String>,
    glob: bool,
}

fn local_use_selections(tree: &UseTree) -> BTreeMap<String, ExportSelection> {
    let mut targets = Vec::new();
    collect_use_targets(tree, &mut Vec::new(), &mut targets);
    let mut selections = BTreeMap::new();
    for mut target in targets {
        while target
            .path
            .first()
            .is_some_and(|name| matches!(name.as_str(), "self" | "crate" | "super"))
        {
            target.path.remove(0);
        }
        if target.path.is_empty() {
            continue;
        }
        let root = target.path.remove(0);
        let selection = if target.glob || target.path.is_empty() {
            ExportSelection::All
        } else {
            ExportSelection::Names(BTreeSet::from([target.path.remove(0)]))
        };
        selections
            .entry(root)
            .and_modify(|existing: &mut ExportSelection| existing.merge(selection.clone()))
            .or_insert(selection);
    }
    selections
}

fn collect_use_targets(tree: &UseTree, prefix: &mut Vec<String>, targets: &mut Vec<UseTarget>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_targets(&path.tree, prefix, targets);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut path = prefix.clone();
            path.push(name.ident.to_string());
            targets.push(UseTarget { path, glob: false });
        }
        UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            path.push(rename.ident.to_string());
            targets.push(UseTarget { path, glob: false });
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_targets(tree, prefix, targets);
            }
        }
        UseTree::Glob(_) => targets.push(UseTarget {
            path: prefix.clone(),
            glob: true,
        }),
    }
}

fn selection_includes_use(selection: &ExportSelection, tree: &UseTree) -> bool {
    let ExportSelection::Names(selected) = selection else {
        return true;
    };
    let mut exported = BTreeSet::new();
    if collect_use_export_names(tree, &mut exported) {
        return true;
    }
    !selected.is_disjoint(&exported)
}

fn collect_use_export_names(tree: &UseTree, names: &mut BTreeSet<String>) -> bool {
    match tree {
        UseTree::Path(path) => collect_use_export_names(&path.tree, names),
        UseTree::Name(name) => {
            names.insert(name.ident.to_string());
            false
        }
        UseTree::Rename(rename) => {
            names.insert(rename.rename.to_string());
            false
        }
        UseTree::Group(group) => group.items.iter().fold(false, |glob, tree| {
            collect_use_export_names(tree, names) || glob
        }),
        UseTree::Glob(_) => true,
    }
}

fn selected_public(
    ident: &syn::Ident,
    visibility: &Visibility,
    attributes: &[Attribute],
    selection: &ExportSelection,
) -> bool {
    visible_public(visibility, attributes) && selection.includes(&ident.to_string())
}

fn visible_public(visibility: &Visibility, attributes: &[Attribute]) -> bool {
    is_public(visibility) && !is_doc_hidden(attributes)
}

fn is_doc_hidden(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("doc") {
            return false;
        }
        let mut hidden = false;
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("hidden") {
                hidden = true;
            }
            Ok(())
        });
        hidden
    })
}

fn pending_public_impl(item: &syn::ItemImpl, module_path: &[String]) -> Option<PendingImpl> {
    let (segments, root_qualified) = self_type_segments(&item.self_ty)?;
    let mut owner_candidates = Vec::new();
    if root_qualified || segments.first().is_some_and(|segment| segment == "crate") {
        owner_candidates.push(
            segments
                .iter()
                .filter(|segment| segment.as_str() != "crate")
                .cloned()
                .collect::<Vec<_>>()
                .join("::"),
        );
    } else if segments.first().is_some_and(|segment| segment == "self") {
        owner_candidates.push(
            module_path
                .iter()
                .cloned()
                .chain(segments.iter().skip(1).cloned())
                .collect::<Vec<_>>()
                .join("::"),
        );
    } else if segments.first().is_some_and(|segment| segment == "super") {
        let mut base = module_path.to_vec();
        let mut remainder = segments.as_slice();
        while remainder.first().is_some_and(|segment| segment == "super") {
            base.pop()?;
            remainder = &remainder[1..];
        }
        owner_candidates.push(
            base.into_iter()
                .chain(remainder.iter().cloned())
                .collect::<Vec<_>>()
                .join("::"),
        );
    } else {
        owner_candidates.push(
            module_path
                .iter()
                .cloned()
                .chain(segments.iter().cloned())
                .collect::<Vec<_>>()
                .join("::"),
        );
        if module_path.is_empty() {
            owner_candidates.push(segments.join("::"));
        }
    }
    owner_candidates.retain(|candidate| !candidate.is_empty());
    owner_candidates.dedup();

    let context = format!(
        "{} {}",
        compact_tokens(&item.generics),
        compact_tokens(&item.generics.where_clause),
    );
    let mut members = Vec::new();
    for member in &item.items {
        match member {
            syn::ImplItem::Fn(method) if visible_public(&method.vis, &method.attrs) => {
                members.push((
                    format!("fn/{}", method.sig.ident),
                    Value::String(format!("{context} {}", compact_tokens(&method.sig))),
                ));
            }
            syn::ImplItem::Const(value) if visible_public(&value.vis, &value.attrs) => {
                members.push((
                    format!("const/{}", value.ident),
                    Value::String(format!("{context} {}", public_impl_const_signature(value))),
                ));
            }
            syn::ImplItem::Type(value) if visible_public(&value.vis, &value.attrs) => {
                members.push((
                    format!("type/{}", value.ident),
                    Value::String(format!("{context} {}", compact_tokens(value))),
                ));
            }
            _ => {}
        }
    }
    (!members.is_empty()).then_some(PendingImpl {
        owner_candidates,
        members,
    })
}

fn self_type_segments(ty: &Type) -> Option<(Vec<String>, bool)> {
    let ty = match ty {
        Type::Group(group) => group.elem.as_ref(),
        Type::Paren(paren) => paren.elem.as_ref(),
        other => other,
    };
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    Some((
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
        path.path.leading_colon.is_some(),
    ))
}

fn type_surface_key(module_path: &[String], name: &str) -> String {
    if module_path.is_empty() {
        name.to_owned()
    } else {
        format!("{}::{name}", module_path.join("::"))
    }
}

fn public_const_surface(item: &syn::ItemConst) -> Value {
    json!({
        "generics": compact_tokens(&item.generics),
        "type": compact_tokens(&item.ty),
        "where": compact_tokens(&item.generics.where_clause),
        "value": compact_tokens(&item.expr),
    })
}

fn public_static_signature(item: &syn::ItemStatic) -> String {
    format!(
        "{} {} {}",
        compact_tokens(&item.mutability),
        compact_tokens(&item.ty),
        compact_tokens(&item.expr),
    )
}

fn public_impl_const_signature(item: &syn::ImplItemConst) -> String {
    format!(
        "{} {} {} {}",
        compact_tokens(&item.generics),
        compact_tokens(&item.ty),
        compact_tokens(&item.generics.where_clause),
        compact_tokens(&item.expr),
    )
}

fn has_attribute(attributes: &[Attribute], name: &str) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident(name))
}

fn public_enum_variants(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> String {
    variants
        .iter()
        .filter(|variant| !is_doc_hidden(&variant.attrs))
        .map(|variant| {
            let discriminant = variant
                .discriminant
                .as_ref()
                .map(|(_, expression)| compact_tokens(expression))
                .unwrap_or_default();
            format!(
                "{} {} {} {discriminant}",
                contract_attributes(&variant.attrs),
                variant.ident,
                compact_tokens(&variant.fields),
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn public_trait_surface(item: &syn::ItemTrait) -> String {
    let members = item
        .items
        .iter()
        .filter(|member| !trait_item_doc_hidden(member))
        .map(compact_tokens)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {} {} {} {members}",
        contract_attributes(&item.attrs),
        compact_tokens(&item.unsafety),
        compact_tokens(&item.auto_token),
        compact_tokens(&item.generics),
        compact_tokens(&item.supertraits),
        compact_tokens(&item.generics.where_clause),
    )
}

fn trait_item_doc_hidden(item: &syn::TraitItem) -> bool {
    match item {
        syn::TraitItem::Const(item) => is_doc_hidden(&item.attrs),
        syn::TraitItem::Fn(item) => is_doc_hidden(&item.attrs),
        syn::TraitItem::Type(item) => is_doc_hidden(&item.attrs),
        syn::TraitItem::Macro(item) => is_doc_hidden(&item.attrs),
        syn::TraitItem::Verbatim(_) => false,
        _ => false,
    }
}

fn contract_attributes(attributes: &[syn::Attribute]) -> String {
    attributes
        .iter()
        .filter(|attribute| {
            attribute.path().is_ident("repr") || attribute.path().is_ident("non_exhaustive")
        })
        .map(compact_tokens)
        .collect::<Vec<_>>()
        .join(" ")
}

fn public_struct_fields(fields: &syn::Fields) -> String {
    fields
        .iter()
        .filter(|field| visible_public(&field.vis, &field.attrs))
        .map(|field| {
            let name = field
                .ident
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            format!("{name}:{}", compact_tokens(&field.ty))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn public_named_fields(fields: &syn::FieldsNamed) -> String {
    fields
        .named
        .iter()
        .filter(|field| visible_public(&field.vis, &field.attrs))
        .map(|field| {
            let name = field
                .ident
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            format!("{name}:{}", compact_tokens(&field.ty))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn header_surface(source: &str) -> Value {
    let without_comments = strip_c_comments(source);
    let mut items = BTreeSet::new();
    let mut declaration = String::new();
    for line in without_comments.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            items.insert(normalize_whitespace(line));
            continue;
        }
        if !declaration.is_empty() {
            declaration.push(' ');
        }
        declaration.push_str(line);
        while let Some(end) = declaration.find(';') {
            let item = declaration[..=end].to_owned();
            declaration = declaration[end + 1..].trim().to_owned();
            items.insert(normalize_whitespace(&item));
        }
    }
    if !declaration.trim().is_empty() {
        items.insert(normalize_whitespace(&declaration));
    }
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn strip_c_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    let mut block = false;
    while index < bytes.len() {
        if block {
            if bytes.get(index..index + 2) == Some(b"*/") {
                block = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            block = true;
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn compact_tokens(value: &impl ToTokens) -> String {
    normalize_whitespace(&value.to_token_stream().to_string())
}

fn normalized(value: Value) -> Value {
    normalize_value(value, &[], None)
}

fn normalize_value(value: Value, path: &[String], parent_type: Option<&str>) -> Value {
    match value {
        Value::Object(object) => {
            let object_type = object
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let mut normalized = Map::new();
            for (key, value) in object {
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                normalized.insert(
                    key,
                    normalize_value(value, &child_path, object_type.as_deref()),
                );
            }
            Value::Object(normalized)
        }
        Value::Array(values) => {
            let ordered = parent_type == Some("SEQ")
                && path.last().is_some_and(|segment| segment == "members");
            let mut normalized = Map::new();
            if ordered {
                for (index, value) in values.into_iter().enumerate() {
                    let key = format!("#{index:04}");
                    let mut child_path = path.to_vec();
                    child_path.push(key.clone());
                    normalized.insert(key, normalize_value(value, &child_path, None));
                }
                return Value::Object(normalized);
            }

            let identities = values
                .iter()
                .map(array_identity)
                .collect::<Option<Vec<_>>>();
            let unique = identities.as_ref().is_some_and(|identities| {
                identities.iter().collect::<BTreeSet<_>>().len() == identities.len()
            });
            for (index, value) in values.into_iter().enumerate() {
                let key = if unique {
                    identities.as_ref().unwrap()[index].clone()
                } else {
                    format!("sha256:{}", value_hash(&value))
                };
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                normalized.insert(key, normalize_value(value, &child_path, None));
            }
            Value::Object(normalized)
        }
        other => other,
    }
}

fn array_identity(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(format!("string:{value}")),
        Value::Bool(value) => Some(format!("bool:{value}")),
        Value::Number(value) => Some(format!("number:{value}")),
        Value::Null => Some("null".into()),
        Value::Object(object) => {
            let mut parts = ["name", "value", "$id", "schema"]
                .into_iter()
                .filter_map(|key| {
                    object
                        .get(key)
                        .filter(|value| !value.is_object() && !value.is_array())
                        .map(|value| format!("{key}={value}"))
                })
                .collect::<Vec<_>>();
            if !parts.is_empty()
                && let Some(value) = object
                    .get("type")
                    .filter(|value| !value.is_object() && !value.is_array())
            {
                parts.insert(0, format!("type={value}"));
            }
            (!parts.is_empty()).then(|| parts.join("|"))
        }
        Value::Array(_) => None,
    }
}

fn value_hash(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON values always serialize");
    format!("{:x}", Sha256::digest(bytes))
}

fn classify(baseline: &Value, current: &Value) -> (RequiredBump, Vec<SurfaceChange>) {
    let mut changes = Vec::new();
    compare_values(baseline, current, &mut Vec::new(), &mut changes);
    let bump = changes
        .iter()
        .map(|change| change.bump)
        .max()
        .unwrap_or(RequiredBump::Patch);
    (bump, changes)
}

fn compare_values(
    baseline: &Value,
    current: &Value,
    path: &mut Vec<String>,
    changes: &mut Vec<SurfaceChange>,
) {
    match (baseline, current) {
        (Value::Object(baseline), Value::Object(current)) => {
            for (key, baseline_value) in baseline {
                path.push(key.clone());
                match current.get(key) {
                    Some(current_value) => {
                        compare_values(baseline_value, current_value, path, changes)
                    }
                    None => changes.push(SurfaceChange {
                        bump: RequiredBump::Major,
                        kind: "removed",
                        path: display_path(path),
                    }),
                }
                path.pop();
            }
            for (key, current_value) in current {
                if baseline.contains_key(key) {
                    continue;
                }
                path.push(key.clone());
                changes.push(SurfaceChange {
                    bump: addition_bump(path, current_value),
                    kind: "added",
                    path: display_path(path),
                });
                path.pop();
            }
        }
        _ if baseline == current => {}
        _ => changes.push(SurfaceChange {
            bump: reviewed_patch_change(path, baseline, current)
                .then_some(RequiredBump::Patch)
                .unwrap_or(RequiredBump::Major),
            kind: "changed",
            path: display_path(path),
        }),
    }
}

fn reviewed_patch_change(path: &[String], baseline: &Value, current: &Value) -> bool {
    let (Some(baseline), Some(current)) = (baseline.as_str(), current.as_str()) else {
        return false;
    };
    [
        (
            "/native_and_embedding_abi/rust/yanxu/stdlib/const/BYTES_MAX_VALUE_BYTES/value",
            "4 * 1024 * 1024",
            "16 * 1024 * 1024",
        ),
        (
            "/native_and_embedding_abi/rust/yanxu/stdlib/const/PROCESS_MAX_TIMEOUT_MILLIS/value",
            "300_000",
            "24 * 60 * 60 * 1_000",
        ),
        (
            "/native_and_embedding_abi/rust/yanxu_package/package/const/DEFAULT_REGISTRY/value",
            "\"https://packages.yanxu.dev/v1\"",
            "\"https://get.yanxu.dev/packages/v1\"",
        ),
    ]
    .into_iter()
    .any(|(approved_path, approved_baseline, approved_current)| {
        display_path(path) == approved_path
            && baseline == approved_baseline
            && current == approved_current
    })
}

fn addition_bump(path: &[String], current: &Value) -> RequiredBump {
    if path
        .iter()
        .any(|segment| segment == "required" || segment == "required_fields")
        || current
            .as_object()
            .and_then(|object| object.get("required"))
            .and_then(Value::as_bool)
            == Some(true)
    {
        RequiredBump::Major
    } else {
        RequiredBump::Minor
    }
}

fn display_path(path: &[String]) -> String {
    if path.is_empty() {
        "/".into()
    } else {
        format!("/{}", path.join("/"))
    }
}

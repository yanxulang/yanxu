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
use syn::{Expr, Item, ItemFn, Lit, Pat, Type, Visibility};

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
    let mut files = Map::new();
    for path in ["src/lib.rs", "src/embed.rs", "src/ffi.rs"] {
        files.insert(path.into(), public_items(&view.read(path)?)?);
    }
    Ok(Value::Object(files))
}

fn public_items(source: &str) -> Result<Value, String> {
    let file = parse_source(source)?;
    let mut items = Map::new();
    for item in file.items {
        match item {
            Item::Fn(item) if is_public(&item.vis) => {
                items.insert(
                    format!("fn/{}", item.sig.ident),
                    Value::String(compact_tokens(&item.sig)),
                );
            }
            Item::Struct(item) if is_public(&item.vis) => {
                let signature = format!(
                    "{} {} {}",
                    contract_attributes(&item.attrs),
                    compact_tokens(&item.generics),
                    public_struct_fields(&item.fields)
                );
                items.insert(format!("struct/{}", item.ident), Value::String(signature));
            }
            Item::Enum(item) if is_public(&item.vis) => {
                let signature = format!(
                    "{} {} {}",
                    contract_attributes(&item.attrs),
                    compact_tokens(&item.generics),
                    compact_tokens(&item.variants)
                );
                items.insert(format!("enum/{}", item.ident), Value::String(signature));
            }
            Item::Type(item) if is_public(&item.vis) => {
                items.insert(
                    format!("type/{}", item.ident),
                    Value::String(compact_tokens(&item)),
                );
            }
            Item::Const(item) if is_public(&item.vis) => {
                items.insert(
                    format!("const/{}", item.ident),
                    Value::String(compact_tokens(&item)),
                );
            }
            Item::Static(item) if is_public(&item.vis) => {
                items.insert(
                    format!("static/{}", item.ident),
                    Value::String(compact_tokens(&item)),
                );
            }
            Item::Trait(item) if is_public(&item.vis) => {
                items.insert(
                    format!("trait/{}", item.ident),
                    Value::String(compact_tokens(&item)),
                );
            }
            Item::Mod(item) if is_public(&item.vis) => {
                items.insert(format!("mod/{}", item.ident), Value::Bool(true));
            }
            Item::Use(item) if is_public(&item.vis) => {
                items.insert(
                    format!("use/{}", compact_tokens(&item.tree)),
                    Value::Bool(true),
                );
            }
            Item::Impl(item) => {
                let owner = compact_tokens(&item.self_ty);
                for member in item.items {
                    match member {
                        syn::ImplItem::Fn(method) if is_public(&method.vis) => {
                            items.insert(
                                format!("impl/{owner}/fn/{}", method.sig.ident),
                                Value::String(compact_tokens(&method.sig)),
                            );
                        }
                        syn::ImplItem::Const(value) if is_public(&value.vis) => {
                            items.insert(
                                format!("impl/{owner}/const/{}", value.ident),
                                Value::String(compact_tokens(&value)),
                            );
                        }
                        syn::ImplItem::Type(value) if is_public(&value.vis) => {
                            items.insert(
                                format!("impl/{owner}/type/{}", value.ident),
                                Value::String(compact_tokens(&value)),
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(Value::Object(items))
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
        .filter(|field| is_public(&field.vis))
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
            bump: RequiredBump::Major,
            kind: "changed",
            path: display_path(path),
        }),
    }
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

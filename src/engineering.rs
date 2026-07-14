//! 言包等工程工具使用的版本化 JSON 协议。
//!
//! 工具可以负责命令体验与流程编排，但清单、锁文件、依赖图和构建语义
//! 必须通过这里进入言序核心，避免形成第二套包语义。

use crate::package::{self, Dependency, Manifest, ResolutionGraph};
use semver::VersionReq;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::PathBuf;

pub const ENGINEERING_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineeringError {
    pub message: String,
}

impl fmt::Display for EngineeringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "工程协议有误：{}", self.message)
    }
}

impl std::error::Error for EngineeringError {}

pub fn handle(request: &Value) -> Result<Value, EngineeringError> {
    let object = request
        .as_object()
        .ok_or_else(|| engineering_error("请求须为 JSON 对象"))?;
    let version = object
        .get("protocol_version")
        .and_then(Value::as_u64)
        .unwrap_or(ENGINEERING_PROTOCOL_VERSION as u64);
    if version != ENGINEERING_PROTOCOL_VERSION as u64 {
        return Err(engineering_error(format!(
            "不支持协议版本 {version}，当前仅支持 {ENGINEERING_PROTOCOL_VERSION}"
        )));
    }
    let operation = required_string(request, "operation")?;
    match operation {
        "handshake" => Ok(handshake()),
        "template" => {
            let name = required_string(request, "name")?;
            let manifest = package::manifest_template(name).map_err(engineering_error)?;
            Ok(json!({
                "manifest": manifest,
                "entry": "言 「你好，言序！」；\n",
                "gitignore": ".yanxu/\nbuild/\n",
            }))
        }
        "inspect" => {
            let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
            Ok(manifest_json(&manifest))
        }
        "edit" => edit_dependency(request),
        "resolve" | "graph" => resolve_graph(request),
        "plan_update" | "outdated" => plan_update(request),
        "why" => why(request),
        "doctor" => doctor(request),
        "workspace" => workspace(request),
        "pack" => pack(request),
        "vendor" => vendor(request),
        "audit" => audit(request),
        other => Err(engineering_error(format!("不识操作“{other}”"))),
    }
}

pub fn response(request: &Value) -> Value {
    match handle(request) {
        Ok(result) => json!({
            "protocol_version": ENGINEERING_PROTOCOL_VERSION,
            "ok": true,
            "result": result,
        }),
        Err(error) => json!({
            "protocol_version": ENGINEERING_PROTOCOL_VERSION,
            "ok": false,
            "error": {
                "code": "ENGINEERING_ERROR",
                "message": error.to_string(),
            },
        }),
    }
}

fn handshake() -> Value {
    json!({
        "yanxu_version": env!("CARGO_PKG_VERSION"),
        "manifest_formats": package::SUPPORTED_MANIFEST_FORMATS,
        "lock_formats": package::SUPPORTED_LOCK_FORMATS,
        "bytecode_formats": [crate::bytecode::BYTECODE_FORMAT_VERSION],
        "yxb_formats": [crate::application::YXB_FORMAT_VERSION],
        "native_abi": [1],
        "native_capabilities": crate::native_abi::capabilities(),
        "target": package::current_target(),
        "operations": ["handshake", "template", "inspect", "edit", "resolve", "graph", "plan_update", "outdated", "why", "doctor", "workspace", "pack", "vendor", "audit"],
    })
}

fn edit_dependency(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let alias = required_string(request, "alias")?;
    let development = optional_bool(request, "development").unwrap_or(false);
    let remove = optional_bool(request, "remove").unwrap_or(false);
    let updated = if remove {
        package::edit_dependency(&manifest.path, alias, None, None, development)
    } else {
        let package_name = optional_string(request, "package");
        let dependency = dependency_from_request(request)?;
        package::edit_dependency(
            &manifest.path,
            alias,
            package_name,
            Some(&dependency),
            development,
        )
    }
    .map_err(package_error)?;
    Ok(manifest_json(&updated))
}

fn dependency_from_request(request: &Value) -> Result<Dependency, EngineeringError> {
    let source = optional_string(request, "source").unwrap_or("registry");
    let requirement = optional_string(request, "version")
        .filter(|requirement| !requirement.is_empty())
        .map(VersionReq::parse)
        .transpose()
        .map_err(|error| engineering_error(format!("版本要求无效：{error}")))?;
    match source {
        "path" => Ok(Dependency::Path {
            path: required_string(request, "source_value")?.into(),
            requirement,
        }),
        "git" => Ok(Dependency::Git {
            url: required_string(request, "source_value")?.into(),
            revision: optional_string(request, "revision")
                .unwrap_or("HEAD")
                .into(),
            requirement,
        }),
        "registry" => Ok(Dependency::Registry {
            requirement: requirement.unwrap_or(VersionReq::STAR),
            registry: optional_string(request, "source_value")
                .unwrap_or(package::DEFAULT_REGISTRY)
                .into(),
        }),
        other => Err(engineering_error(format!(
            "依赖来源只可为 path、git 或 registry，不可为“{other}”"
        ))),
    }
}

fn resolve_graph(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    if optional_bool(request, "update").unwrap_or(false) {
        package::update_lock(&manifest, offline).map_err(package_error)?;
    }
    let graph = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    Ok(graph_json(&manifest, &graph))
}

fn plan_update(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    let current = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let planned = package::plan_update(&manifest, offline).map_err(package_error)?;
    let changes = planned
        .packages
        .iter()
        .filter_map(|(planned_id, planned_dependency)| {
            let current = current.packages.iter().find(|(_, dependency)| {
                dependency.locked.name == planned_dependency.locked.name
                    && dependency.locked.source == planned_dependency.locked.source
            });
            match current {
                Some((_current_id, dependency))
                    if dependency.locked.version == planned_dependency.locked.version
                        && dependency.locked.revision == planned_dependency.locked.revision
                        && dependency.locked.checksum == planned_dependency.locked.checksum =>
                {
                    None
                }
                Some((current_id, dependency)) => Some(json!({
                    "kind": "update",
                    "name": planned_dependency.locked.name,
                    "from_id": current_id,
                    "to_id": planned_id,
                    "from_version": dependency.locked.version,
                    "to_version": planned_dependency.locked.version,
                    "from_revision": dependency.locked.revision,
                    "to_revision": planned_dependency.locked.revision,
                    "source": planned_dependency.locked.source,
                })),
                None => Some(json!({
                    "kind": "add",
                    "name": planned_dependency.locked.name,
                    "to_id": planned_id,
                    "to_version": planned_dependency.locked.version,
                    "source": planned_dependency.locked.source,
                })),
            }
        })
        .collect::<Vec<_>>();
    let removals = current
        .packages
        .iter()
        .filter(|(_, dependency)| {
            !planned.packages.values().any(|planned| {
                planned.locked.name == dependency.locked.name
                    && planned.locked.source == dependency.locked.source
            })
        })
        .map(|(id, dependency)| {
            json!({
                "kind": "remove",
                "name": dependency.locked.name,
                "from_id": id,
                "from_version": dependency.locked.version,
                "source": dependency.locked.source,
            })
        });
    let mut changes = changes;
    changes.extend(removals);
    Ok(json!({
        "changed": !changes.is_empty(),
        "changes": changes,
        "current": graph_json(&manifest, &current),
        "planned": graph_json(&manifest, &planned),
    }))
}

fn pack(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let output = optional_string(request, "output")
        .filter(|path| !path.is_empty())
        .map_or_else(
            || {
                manifest
                    .root
                    .join("build")
                    .join(format!("{}-{}.yxp", manifest.name, manifest.version))
            },
            PathBuf::from,
        );
    let artifact = package::pack_package(&manifest, &output).map_err(package_error)?;
    Ok(json!({
        "path": artifact.path,
        "checksum": artifact.checksum,
        "bytes": artifact.bytes,
        "entries": artifact.entries,
    }))
}

fn vendor(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    let graph = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let destination = optional_string(request, "output")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.root.join("vendor"));
    let vendor = package::vendor_dependencies(&graph, &destination).map_err(package_error)?;
    Ok(json!({
        "path": destination,
        "format": vendor.format_version,
        "target": vendor.target,
        "packages": vendor.packages,
    }))
}

fn audit(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    let graph = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let mut findings = Vec::new();
    let mut versions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for dependency in graph.packages.values() {
        versions
            .entry(&dependency.locked.name)
            .or_default()
            .push(&dependency.locked.version);
        let dependency_manifest =
            package::load(dependency.root.join(package::MANIFEST_NAME)).map_err(package_error)?;
        if dependency_manifest
            .license
            .as_deref()
            .is_none_or(str::is_empty)
        {
            findings.push(json!({
                "severity": "warning",
                "code": "AUDIT_LICENSE_MISSING",
                "package": dependency.locked.name,
                "message": "依赖未声明许可证",
            }));
        }
        if dependency.locked.native.is_some() {
            findings.push(json!({
                "severity": "info",
                "code": "AUDIT_NATIVE",
                "package": dependency.locked.name,
                "message": "依赖包含已校验的原生扩展制品",
            }));
        }
        if dependency.locked.source.starts_with("registry:http://")
            || dependency.locked.source.starts_with("git:http://")
        {
            findings.push(json!({
                "severity": "warning",
                "code": "AUDIT_INSECURE_SOURCE",
                "package": dependency.locked.name,
                "message": "依赖来源未使用 HTTPS",
            }));
        }
    }
    for (name, mut package_versions) in versions {
        package_versions.sort();
        package_versions.dedup();
        if package_versions.len() > 1 {
            findings.push(json!({
                "severity": "warning",
                "code": "AUDIT_DUPLICATE_VERSION",
                "package": name,
                "versions": package_versions,
                "message": "依赖图同时包含同一包的多个版本",
            }));
        }
    }
    let warnings = findings
        .iter()
        .filter(|finding| finding["severity"] == "warning")
        .count();
    Ok(json!({
        "ok": warnings == 0,
        "warnings": warnings,
        "packages": graph.packages.len(),
        "findings": findings,
    }))
}

fn why(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let target = required_string(request, "target")?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    let graph = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let mut queue = VecDeque::new();
    for (alias, id) in graph
        .root_dependencies
        .iter()
        .chain(graph.root_dev_dependencies.iter())
    {
        queue.push_back((id.clone(), vec![manifest.name.clone(), alias.clone()]));
    }
    let mut paths = Vec::new();
    while let Some((id, path)) = queue.pop_front() {
        let Some(dependency) = graph.packages.get(&id) else {
            continue;
        };
        if id == target
            || dependency.locked.name == target
            || path.last().is_some_and(|item| item == target)
        {
            paths.push(json!({"id": id, "package": dependency.locked.name, "path": path}));
        }
        for (alias, child) in &dependency.locked.dependencies {
            let mut child_path = path.clone();
            child_path.push(alias.clone());
            if child_path.len() <= graph.packages.len() + 1 {
                queue.push_back((child.clone(), child_path));
            }
        }
    }
    Ok(json!({"target": target, "paths": paths}))
}

fn doctor(request: &Value) -> Result<Value, EngineeringError> {
    let path = optional_string(request, "path").unwrap_or(".");
    let manifest = package::discover(path).map_err(package_error)?;
    let mut checks = vec![json!({
        "name": "runtime",
        "ok": true,
        "detail": format!("言序 {} / {}", env!("CARGO_PKG_VERSION"), package::current_target()),
    })];
    if let Some(manifest) = manifest {
        checks.push(json!({
            "name": "manifest",
            "ok": true,
            "detail": manifest.path,
        }));
        let lock_path = manifest.root.join(package::LOCK_NAME);
        match package::read_lock(&lock_path) {
            Ok(lock) => checks.push(json!({
                "name": "lock",
                "ok": lock.target == package::current_target(),
                "detail": lock_path,
                "format": lock.lock_version,
                "target": lock.target,
            })),
            Err(error) => checks.push(json!({
                "name": "lock",
                "ok": false,
                "detail": error.to_string(),
            })),
        }
    } else {
        checks.push(json!({
            "name": "manifest",
            "ok": false,
            "detail": format!("从 {path} 起未找到 {}", package::MANIFEST_NAME),
        }));
    }
    Ok(json!({"checks": checks}))
}

fn workspace(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let canonical_root = std::fs::canonicalize(&manifest.root)
        .map_err(|error| engineering_error(format!("不能定位工作区根：{error}")))?;
    let mut projects = vec![manifest_json(&manifest)];
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(canonical_root.clone());
    for member in &manifest.workspace_members {
        let member_root = std::fs::canonicalize(manifest.root.join(member)).map_err(|error| {
            engineering_error(format!("不能定位工作区成员 {}：{error}", member.display()))
        })?;
        if !member_root.starts_with(&canonical_root) {
            return Err(engineering_error(format!(
                "工作区成员 {} 越出工作区根",
                member.display()
            )));
        }
        if !seen.insert(member_root.clone()) {
            return Err(engineering_error(format!(
                "工作区成员 {} 重复",
                member.display()
            )));
        }
        let member_manifest =
            package::load(member_root.join(package::MANIFEST_NAME)).map_err(package_error)?;
        projects.push(manifest_json(&member_manifest));
    }
    Ok(json!({
        "root": canonical_root,
        "projects": projects,
    }))
}

fn discover_manifest(path: &str) -> Result<Manifest, EngineeringError> {
    package::discover(path)
        .map_err(package_error)?
        .ok_or_else(|| engineering_error(format!("从 {path} 起未找到 {}", package::MANIFEST_NAME)))
}

fn manifest_json(manifest: &Manifest) -> Value {
    json!({
        "format": manifest.format_version,
        "name": manifest.name,
        "version": manifest.version.to_string(),
        "minimum_yanxu": manifest.minimum_yanxu.as_ref().map(ToString::to_string),
        "root": manifest.root,
        "manifest": manifest.path,
        "entry": manifest.entry,
        "dependencies": dependency_table_json(&manifest.dependencies, &manifest.dependency_packages),
        "dev_dependencies": dependency_table_json(&manifest.dev_dependencies, &manifest.dev_dependency_packages),
        "exports": manifest.exports,
        "resources": manifest.resources,
        "workspace_members": manifest.workspace_members,
        "build": {"target": manifest.build.target},
        "permissions": {
            "files": manifest.permissions.file_roots(),
            "network": manifest.permissions.network_hosts().collect::<Vec<_>>(),
            "tcp_listen": manifest.permissions.tcp_listen_hosts().collect::<Vec<_>>(),
            "udp_bind": manifest.permissions.udp_bind_hosts().collect::<Vec<_>>(),
            "environment": manifest.permissions.environment_variables().collect::<Vec<_>>(),
            "process": manifest.permissions.process_allowed(),
            "native_extensions": manifest.permissions.native_extensions_allowed(),
        },
        "native": manifest.native.as_ref().map(|native| json!({
            "abi": native.abi_version,
            "artifacts": native.artifacts,
        })),
    })
}

fn dependency_table_json(
    dependencies: &BTreeMap<String, Dependency>,
    package_names: &BTreeMap<String, String>,
) -> Value {
    Value::Object(
        dependencies
            .iter()
            .map(|(alias, dependency)| {
                let mut value = dependency_json(dependency);
                value["package"] = Value::String(
                    package_names
                        .get(alias)
                        .cloned()
                        .unwrap_or_else(|| alias.clone()),
                );
                (alias.clone(), value)
            })
            .collect(),
    )
}

fn dependency_json(dependency: &Dependency) -> Value {
    match dependency {
        Dependency::Path { path, requirement } => json!({
            "source": "path",
            "source_value": path,
            "version": requirement.as_ref().map(ToString::to_string),
        }),
        Dependency::Git {
            url,
            revision,
            requirement,
        } => json!({
            "source": "git",
            "source_value": url,
            "revision": revision,
            "version": requirement.as_ref().map(ToString::to_string),
        }),
        Dependency::Registry {
            requirement,
            registry,
        } => json!({
            "source": "registry",
            "source_value": registry,
            "version": requirement.to_string(),
        }),
    }
}

fn graph_json(manifest: &Manifest, graph: &ResolutionGraph) -> Value {
    json!({
        "root": manifest.name,
        "target": graph.target,
        "dependencies": graph.root_dependencies,
        "dev_dependencies": graph.root_dev_dependencies,
        "packages": graph.packages.iter().map(|(id, dependency)| json!({
            "id": id,
            "name": dependency.locked.name,
            "version": dependency.locked.version,
            "source": dependency.locked.source,
            "revision": dependency.locked.revision,
            "checksum": dependency.locked.checksum,
            "root": dependency.root,
            "entry": dependency.entry,
            "dependencies": dependency.locked.dependencies,
            "exports": dependency.locked.exports,
            "target": dependency.locked.target,
            "native": dependency.locked.native,
        })).collect::<Vec<_>>(),
    })
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, EngineeringError> {
    optional_string(value, key).ok_or_else(|| engineering_error(format!("缺少字符串字段“{key}”")))
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn optional_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn package_error(error: package::ManifestError) -> EngineeringError {
    engineering_error(error.to_string())
}

fn engineering_error(message: impl Into<String>) -> EngineeringError {
    EngineeringError {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn protocol_templates_edits_and_inspects_through_the_shared_core() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-engineering-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let template = handle(&json!({"operation":"template", "name":"协议工程"})).unwrap();
        fs::write(
            root.join(package::MANIFEST_NAME),
            template["manifest"].as_str().unwrap(),
        )
        .unwrap();
        fs::write(root.join("src/主.yx"), template["entry"].as_str().unwrap()).unwrap();
        let edited = handle(&json!({
            "operation": "edit",
            "path": root,
            "alias": "本地",
            "source": "path",
            "source_value": "../本地",
            "development": true,
        }))
        .unwrap();
        assert_eq!(edited["dev_dependencies"]["本地"]["source"], "path");
        let inspected = handle(&json!({"operation":"inspect", "path":root})).unwrap();
        assert_eq!(inspected["format"], 2);
        assert_eq!(inspected["name"], "协议工程");
        assert_eq!(response(&json!({"operation":"unknown"}))["ok"], false);
        fs::remove_dir_all(root).ok();
    }
}

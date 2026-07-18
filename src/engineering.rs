//! 言包等工程工具使用的版本化 JSON 协议。
//!
//! 工具可以负责命令体验与流程编排，但清单、锁文件、依赖图和构建语义
//! 必须通过这里进入言序核心，避免形成第二套包语义。

use crate::package::{
    self, ApplicationConfigEdit, ApplicationKind, Dependency, Manifest, ResolutionGraph,
    WindowConfig,
};
use semver::{Version, VersionReq};
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
            let graphical = optional_bool(request, "gui").unwrap_or(false);
            let manifest = if graphical {
                package::gui_manifest_template(
                    name,
                    optional_string(request, "gui_dependency_path").map(std::path::Path::new),
                )
            } else {
                package::manifest_template(name)
            }
            .map_err(engineering_error)?;
            Ok(json!({
                "manifest": manifest,
                "entry": if graphical { gui_entry_template(name) } else { "言 「你好，言序！」；\n".into() },
                "gitignore": ".yanxu/\nbuild/\n",
            }))
        }
        "inspect" => {
            let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
            Ok(manifest_json(&manifest))
        }
        "edit" => edit_dependency(request),
        "edit_application" => edit_application(request),
        "resolve" | "graph" => resolve_graph(request),
        "plan_update" | "outdated" => plan_update(request),
        "why" => why(request),
        "doctor" => doctor(request),
        "workspace" => workspace(request),
        "pack" => pack(request),
        "bundle" => bundle(request),
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
        "build": crate::build_info::identity(),
        "manifest_formats": package::SUPPORTED_MANIFEST_FORMATS,
        "lock_formats": package::SUPPORTED_LOCK_FORMATS,
        "bytecode_formats": [crate::bytecode::BYTECODE_FORMAT_VERSION],
        "yxb_formats": [crate::application::YXB_FORMAT_VERSION],
        "native_abi": [1, 2],
        "native_capabilities": {
            "v1": crate::native_abi::capabilities(),
            "v2": crate::native_abi_v2::capabilities(),
        },
        "permission_capabilities": package::PERMISSION_CAPABILITIES,
        "target": package::current_target(),
        "operations": ["handshake", "template", "inspect", "edit", "edit_application", "resolve", "graph", "plan_update", "outdated", "why", "doctor", "workspace", "pack", "bundle", "vendor", "audit"],
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

fn edit_application(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    if optional_bool(request, "remove").unwrap_or(false) {
        let updated = package::edit_application(&manifest.path, None).map_err(package_error)?;
        return Ok(manifest_json(&updated));
    }
    let current = manifest.application.as_ref();
    let kind = match optional_string(request, "type")
        .unwrap_or_else(|| current.map_or("命令行", |application| application.kind.as_str()))
    {
        "图形" | "gui" | "graphical" => ApplicationKind::Graphical,
        "命令行" | "cli" | "console" => ApplicationKind::CommandLine,
        other => return Err(engineering_error(format!("不支持应用类型“{other}”"))),
    };
    let name = optional_string(request, "name")
        .map(str::to_owned)
        .or_else(|| current.map(|application| application.name.clone()))
        .unwrap_or_else(|| manifest.name.clone());
    let identifier = optional_string(request, "identifier")
        .map(str::to_owned)
        .or_else(|| current.map(|application| application.identifier.clone()))
        .ok_or_else(|| engineering_error("新增应用配置须给出 identifier"))?;
    let version = optional_string(request, "version")
        .map(str::to_owned)
        .or_else(|| current.map(|application| application.version.to_string()))
        .unwrap_or_else(|| manifest.version.to_string());
    let existing_window = current
        .map(|application| application.window.clone())
        .unwrap_or_default();
    let window = WindowConfig {
        width: optional_u32(request, "width")?.unwrap_or(existing_window.width),
        height: optional_u32(request, "height")?.unwrap_or(existing_window.height),
        minimum_width: optional_u32(request, "minimum_width")?
            .unwrap_or(existing_window.minimum_width),
        minimum_height: optional_u32(request, "minimum_height")?
            .unwrap_or(existing_window.minimum_height),
        maximum_width: optional_u32(request, "maximum_width")?.or(existing_window.maximum_width),
        maximum_height: optional_u32(request, "maximum_height")?.or(existing_window.maximum_height),
        resizable: optional_bool(request, "resizable").unwrap_or(existing_window.resizable),
        high_dpi: optional_bool(request, "high_dpi").unwrap_or(existing_window.high_dpi),
    };
    let edit = ApplicationConfigEdit {
        kind,
        name,
        identifier,
        version,
        icon: optional_string(request, "icon")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .or_else(|| current.and_then(|application| application.icon.clone())),
        company: optional_string(request, "company")
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| current.and_then(|application| application.company.clone())),
        minimum_system_version: optional_string(request, "minimum_system_version")
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| current.and_then(|application| application.minimum_system_version.clone())),
        window,
    };
    let updated = package::edit_application(&manifest.path, Some(&edit)).map_err(package_error)?;
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

fn bundle(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let profile = optional_string(request, "profile").unwrap_or("release");
    if !matches!(profile, "debug" | "release") {
        return Err(engineering_error("Bundle profile 只可为 debug 或 release"));
    }
    let archive = crate::application::compile_application(&manifest.root, profile)
        .map_err(|error| engineering_error(error.to_string()))?;
    let output = match optional_string(request, "output").filter(|path| !path.is_empty()) {
        Some(output) => PathBuf::from(output),
        None => manifest.root.join("build").join(
            crate::gui_bundle::default_output(&archive)
                .map_err(|error| engineering_error(error.to_string()))?,
        ),
    };
    let runtime = match optional_string(request, "runtime").filter(|path| !path.is_empty()) {
        Some(runtime) => PathBuf::from(runtime),
        None => std::env::current_exe()
            .map_err(|error| engineering_error(format!("不能定位言序运行时：{error}")))?,
    };
    let report = crate::gui_bundle::build_bundle(runtime, &archive, &output)
        .map_err(|error| engineering_error(error.to_string()))?;
    Ok(json!({
        "path": report.output,
        "manifest": report.manifest,
        "manifest_sha256": report.manifest_sha256,
        "files": report.files,
        "yxb_checksum": archive.content_checksum,
        "target": archive.target,
        "profile": archive.profile,
    }))
}

fn gui_entry_template(name: &str) -> String {
    format!(
        "引「包:言窗」为 界面；\n\n定 应用 为 界面.应用（{name:?}）；\n定 窗口 为 应用.窗口（{{「标题」：{name:?}，「宽」：800，「高」：600，「最小宽」：480，「最小高」：320}}）；\n定 布局 为 窗口.纵向布局（{{「间距」：12，「内边距」：16}}）；\n布局.文字（「你好，言序 GUI！」）；\n\n法 关闭处理（事件）则 应用.退出（）；终\n窗口.关闭时（关闭处理）；\n窗口.显示（）；\n应用.运行（）；\n"
    )
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

struct AuditFinding {
    severity: String,
    code: String,
    package: String,
    message: String,
    versions: Option<Vec<String>>,
}

impl AuditFinding {
    fn new(
        severity: impl Into<String>,
        code: impl Into<String>,
        package: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity: severity.into(),
            code: code.into(),
            package: package.into(),
            message: message.into(),
            versions: None,
        }
    }

    fn with_versions(mut self, versions: Vec<String>) -> Self {
        self.versions = Some(versions);
        self
    }
}

fn audit(request: &Value) -> Result<Value, EngineeringError> {
    let manifest = discover_manifest(optional_string(request, "path").unwrap_or("."))?;
    let offline = optional_bool(request, "offline").unwrap_or(false);
    let graph = package::ensure_lock_with_dev(&manifest, offline).map_err(package_error)?;
    let findings = audit_findings(&manifest, &graph, offline)?;
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity != "info")
        .count();
    let findings = findings
        .into_iter()
        .map(|finding| {
            if let Some(versions) = finding.versions {
                json!({
                    "severity": finding.severity,
                    "code": finding.code,
                    "package": finding.package,
                    "versions": versions,
                    "message": finding.message,
                })
            } else {
                json!({
                    "severity": finding.severity,
                    "code": finding.code,
                    "package": finding.package,
                    "message": finding.message,
                })
            }
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": warnings == 0,
        "warnings": warnings,
        "packages": graph.packages.len(),
        "findings": findings,
    }))
}

fn audit_findings(
    manifest: &Manifest,
    graph: &ResolutionGraph,
    offline: bool,
) -> Result<Vec<AuditFinding>, EngineeringError> {
    let mut findings = Vec::new();
    let mut versions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    audit_declared_dependencies(manifest, &mut findings);
    for dependency in graph.packages.values() {
        let package_name = dependency.locked.name.as_str();
        versions
            .entry(package_name)
            .or_default()
            .push(&dependency.locked.version);
        let dependency_manifest =
            package::load(dependency.root.join(package::MANIFEST_NAME)).map_err(package_error)?;
        audit_declared_dependencies(&dependency_manifest, &mut findings);
        if dependency_manifest
            .license
            .as_deref()
            .is_none_or(|license| license.trim().is_empty())
        {
            findings.push(AuditFinding::new(
                "warning",
                "AUDIT_LICENSE_MISSING",
                package_name,
                "依赖未声明许可证",
            ));
        } else if dependency_manifest
            .license
            .as_deref()
            .is_some_and(|license| {
                license.len() > 512
                    || license.contains(['\0', '\r', '\n'])
                    || spdx::Expression::parse(license.trim()).is_err()
            })
        {
            findings.push(AuditFinding::new(
                "warning",
                "AUDIT_LICENSE_INVALID",
                package_name,
                "依赖许可证不是有效的 SPDX 表达式",
            ));
        }
        if !valid_audit_sha256(&dependency.locked.checksum) {
            findings.push(AuditFinding::new(
                "error",
                "AUDIT_CHECKSUM_INVALID",
                package_name,
                format!(
                    "锁文件依赖校验和不是合法的 SHA-256：{}",
                    dependency.locked.checksum
                ),
            ));
        }
        if insecure_source(&dependency.locked.source) {
            findings.push(AuditFinding::new(
                "warning",
                "AUDIT_INSECURE_SOURCE",
                package_name,
                format!("依赖来源未使用 HTTPS 或 SSH：{}", dependency.locked.source),
            ));
        }
        if let Some(registry) = dependency.locked.source.strip_prefix("registry:") {
            audit_registry_dependency(registry, &dependency.locked, offline, &mut findings)?;
        }
        if dependency.locked.source.starts_with("git:")
            && dependency
                .locked
                .revision
                .as_deref()
                .is_none_or(|revision| !exact_git_revision(revision))
        {
            findings.push(AuditFinding::new(
                "error",
                "AUDIT_GIT_REVISION_UNPINNED",
                package_name,
                format!(
                    "Git 依赖锁文件未固定 40 位提交修订：{}",
                    dependency.locked.revision.as_deref().unwrap_or("<缺失>")
                ),
            ));
        }
        if dependency.locked.target != graph.target {
            findings.push(AuditFinding::new(
                "error",
                "AUDIT_TARGET_MISMATCH",
                package_name,
                format!(
                    "依赖锁定目标 {} 与当前目标 {} 不一致",
                    dependency.locked.target, graph.target
                ),
            ));
        }
        if let Some(native) = &dependency.locked.native {
            if !matches!(native.abi, 1 | 2) {
                findings.push(AuditFinding::new(
                    "error",
                    "AUDIT_NATIVE_ABI_UNSUPPORTED",
                    package_name,
                    format!("原生制品使用不受支持的 ABI {}", native.abi),
                ));
            }
            if native.target != graph.target || dependency.locked.target != native.target {
                findings.push(AuditFinding::new(
                    "error",
                    "AUDIT_NATIVE_TARGET_MISMATCH",
                    package_name,
                    format!(
                        "原生制品目标 {} 与当前目标 {} 不一致",
                        native.target, graph.target
                    ),
                ));
            }
            if !valid_audit_sha256(&native.checksum) {
                findings.push(AuditFinding::new(
                    "error",
                    "AUDIT_NATIVE_CHECKSUM_INVALID",
                    package_name,
                    format!("原生制品校验和不是合法的 SHA-256：{}", native.checksum),
                ));
            }
            findings.push(AuditFinding::new(
                "warning",
                "AUDIT_NATIVE_UNSIGNED",
                package_name,
                format!(
                    "原生 ABI {} 制品 {} 已通过内容校验，但当前包格式没有可验证的签名或来源证明",
                    native.abi, native.target
                ),
            ));
        }
    }
    for (name, mut package_versions) in versions {
        package_versions.sort();
        package_versions.dedup();
        if package_versions.len() > 1 {
            findings.push(
                AuditFinding::new(
                    "warning",
                    "AUDIT_DUPLICATE_VERSION",
                    name,
                    "依赖图同时包含同一包的多个版本",
                )
                .with_versions(package_versions.into_iter().map(str::to_owned).collect()),
            );
        }
    }
    Ok(findings)
}

fn audit_declared_dependencies(manifest: &Manifest, findings: &mut Vec<AuditFinding>) {
    for (dependencies, package_names) in [
        (&manifest.dependencies, &manifest.dependency_packages),
        (
            &manifest.dev_dependencies,
            &manifest.dev_dependency_packages,
        ),
    ] {
        for (alias, dependency) in dependencies {
            let Dependency::Git { url, revision, .. } = dependency else {
                continue;
            };
            if exact_git_revision(revision) {
                continue;
            }
            let package_name = package_names.get(alias).map_or(alias, |name| name);
            findings.push(AuditFinding::new(
                "warning",
                "AUDIT_GIT_SYMBOLIC_REVISION",
                package_name.as_str(),
                format!(
                    "{} 通过符号修订 {revision} 声明 Git 依赖 {url}；锁文件虽固定提交，显式更新仍可能改变来源",
                    manifest.name
                ),
            ));
        }
    }
}

fn audit_registry_dependency(
    registry: &str,
    locked: &package::LockedPackage,
    offline: bool,
    findings: &mut Vec<AuditFinding>,
) -> Result<(), EngineeringError> {
    let version = Version::parse(&locked.version)
        .map_err(|error| engineering_error(format!("锁定版本无效：{error}")))?;
    let Some(metadata) =
        package::registry_release_metadata(registry, &locked.name, &version, offline)
            .map_err(package_error)?
    else {
        findings.push(AuditFinding::new(
            "warning",
            "AUDIT_REGISTRY_METADATA_MISSING",
            locked.name.as_str(),
            format!("索引中缺少当前锁定版本的可审计元数据：{}", locked.source),
        ));
        return Ok(());
    };
    if !valid_audit_sha256(&metadata.checksum) {
        findings.push(AuditFinding::new(
            "error",
            "AUDIT_REGISTRY_CHECKSUM_INVALID",
            locked.name.as_str(),
            format!("索引制品缺少合法的 SHA-256：{}", metadata.checksum),
        ));
    }
    if !secure_registry_artifact_source(registry, &metadata.url) {
        findings.push(AuditFinding::new(
            "warning",
            "AUDIT_INSECURE_SOURCE",
            locked.name.as_str(),
            format!("索引制品地址未使用 HTTPS：{}", metadata.url),
        ));
    }
    match metadata.yanked {
        Some(true) => findings.push(AuditFinding::new(
            "warning",
            "AUDIT_YANKED",
            locked.name.as_str(),
            format!("索引已撤回锁定版本 {}", locked.version),
        )),
        Some(false) => {}
        None => findings.push(AuditFinding::new(
            "warning",
            "AUDIT_YANKED_METADATA_MISSING",
            locked.name.as_str(),
            "索引未声明锁定版本的撤回状态",
        )),
    }
    let Some(vulnerabilities) = metadata.vulnerabilities else {
        findings.push(AuditFinding::new(
            "warning",
            "AUDIT_VULNERABILITY_METADATA_MISSING",
            locked.name.as_str(),
            "索引未声明锁定版本的漏洞元数据",
        ));
        return Ok(());
    };
    for vulnerability in vulnerabilities {
        if vulnerability.withdrawn {
            continue;
        }
        let Some(severity) = registry_vulnerability_severity(&vulnerability.severity) else {
            findings.push(AuditFinding::new(
                "error",
                "AUDIT_VULNERABILITY_METADATA_INVALID",
                locked.name.as_str(),
                format!(
                    "漏洞 {} 使用未知严重度 {}",
                    vulnerability.id, vulnerability.severity
                ),
            ));
            continue;
        };
        if !valid_vulnerability_id(&vulnerability.id) || vulnerability.summary.trim().is_empty() {
            findings.push(AuditFinding::new(
                "error",
                "AUDIT_VULNERABILITY_METADATA_INVALID",
                locked.name.as_str(),
                "漏洞元数据须包含标识与摘要",
            ));
            continue;
        }
        let code = vulnerability_code(&vulnerability.id);
        let reference = vulnerability
            .url
            .as_deref()
            .map_or_else(String::new, |url| format!("（{url}）"));
        findings.push(AuditFinding::new(
            severity,
            code,
            locked.name.as_str(),
            format!(
                "{}：{}{}",
                vulnerability.id, vulnerability.summary, reference
            ),
        ));
    }
    Ok(())
}

fn secure_registry_artifact_source(registry: &str, source: &str) -> bool {
    if registry.starts_with("https://") {
        source.starts_with("https://")
    } else {
        source.starts_with("https://") || source.starts_with("file://") || !source.contains("://")
    }
}

fn registry_vulnerability_severity(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" | "error" => Some("high"),
        "medium" | "warning" => Some("warning"),
        "low" => Some("low"),
        "info" | "information" => Some("info"),
        _ => None,
    }
}

fn vulnerability_code(id: &str) -> String {
    let normalized = id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("AUDIT_VULNERABILITY_{normalized}")
}

fn valid_vulnerability_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 96 || id == "METADATA" || id.starts_with("METADATA-") {
        return false;
    }
    let mut previous_was_separator = true;
    for byte in id.bytes() {
        if byte.is_ascii_uppercase() || byte.is_ascii_digit() {
            previous_was_separator = false;
        } else if byte == b'-' && !previous_was_separator {
            previous_was_separator = true;
        } else {
            return false;
        }
    }
    !previous_was_separator
}

fn exact_git_revision(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_audit_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn insecure_source(source: &str) -> bool {
    source.starts_with("registry:http://")
        || source.starts_with("git:http://")
        || source.starts_with("git:git://")
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
        "application": manifest.application.as_ref().map(|application| json!({
            "type": application.kind.as_str(),
            "name": application.name,
            "identifier": application.identifier,
            "version": application.version.to_string(),
            "icon": application.icon,
            "company": application.company,
            "minimum_system_version": application.minimum_system_version,
            "window": {
                "width": application.window.width,
                "height": application.window.height,
                "minimum_width": application.window.minimum_width,
                "minimum_height": application.window.minimum_height,
                "maximum_width": application.window.maximum_width,
                "maximum_height": application.window.maximum_height,
                "resizable": application.window.resizable,
                "high_dpi": application.window.high_dpi,
            },
        })),
        "permissions": {
            "files": manifest.permissions.file_roots(),
            "network": manifest.permissions.network_hosts().collect::<Vec<_>>(),
            "local_network": manifest.permissions.local_network_allowed(),
            "tcp_listen": manifest.permissions.tcp_listen_hosts().collect::<Vec<_>>(),
            "udp_bind": manifest.permissions.udp_bind_hosts().collect::<Vec<_>>(),
            "environment": manifest.permissions.environment_variables().collect::<Vec<_>>(),
            "process": manifest.permissions.process_allowed(),
            "native_extensions": manifest.permissions.native_extensions_allowed(),
            "graphical_interface": manifest.permissions.graphical_interface_allowed(),
            "clipboard": manifest.permissions.clipboard_allowed(),
            "file_dialog": manifest.permissions.file_dialog_allowed(),
            "system_notifications": manifest.permissions.system_notifications_allowed(),
            "tray": manifest.permissions.tray_allowed(),
            "open_external_url": manifest.permissions.open_external_url_allowed(),
            "global_shortcuts": manifest.permissions.global_shortcuts_allowed(),
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

fn optional_u32(value: &Value, key: &str) -> Result<Option<u32>, EngineeringError> {
    let Some(value) = value.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .map(Some)
        .ok_or_else(|| engineering_error(format!("字段“{key}”须为非负 32 位整数")))
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

    fn temporary_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "yanxu-engineering-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write(path: impl AsRef<std::path::Path>, contents: impl AsRef<[u8]>) {
        let path = path.as_ref();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

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

        let gui_root = std::env::temp_dir().join(format!(
            "yanxu-engineering-gui-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(gui_root.join("src")).unwrap();
        let template = handle(&json!({
            "operation": "template",
            "name": "协议窗口工程",
            "gui": true,
        }))
        .unwrap();
        fs::write(
            gui_root.join(package::MANIFEST_NAME),
            template["manifest"].as_str().unwrap(),
        )
        .unwrap();
        fs::write(
            gui_root.join("src/主.yx"),
            template["entry"].as_str().unwrap(),
        )
        .unwrap();
        let inspected = handle(&json!({"operation":"inspect", "path":gui_root})).unwrap();
        assert_eq!(inspected["dependencies"]["言窗"]["source"], "registry");
        assert_eq!(
            inspected["dependencies"]["言窗"]["source_value"],
            package::DEFAULT_REGISTRY
        );
        assert_eq!(inspected["dependencies"]["言窗"]["version"], "^1.0");
        fs::remove_dir_all(gui_root).ok();
    }

    #[test]
    fn audit_rejects_invalid_lock_native_target_and_revision_metadata() {
        let root = temporary_root("audit-invalid");
        let application = root.join("应用");
        let dependency_root = root.join("依赖");
        write(
            application.join(package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n依赖={git='https://example.invalid/依赖.git',修订='main'}\n",
        );
        write(application.join("主.yx"), "言「应用」；\n");
        write(
            dependency_root.join(package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='依赖'\n版本='1.2.3'\n入口='主.yx'\n许可='not-a-license'\n",
        );
        write(dependency_root.join("主.yx"), "公 定 值：数 为 1；\n");
        let manifest = package::load(application.join(package::MANIFEST_NAME)).unwrap();
        let current_target = package::current_target();
        let dependency = package::ResolvedDependency {
            locked: package::LockedPackage {
                id: "依赖@1.2.3".into(),
                name: "依赖".into(),
                version: "1.2.3".into(),
                source: "git:http://example.invalid/依赖.git".into(),
                revision: Some("main".into()),
                checksum: "bad".into(),
                entry: "主.yx".into(),
                dependencies: BTreeMap::new(),
                exports: BTreeMap::new(),
                target: "other-target".into(),
                native: Some(package::NativeArtifact {
                    abi: 3,
                    target: "other-target".into(),
                    path: "native/library.bin".into(),
                    checksum: "bad".into(),
                    size: 1,
                }),
                minimum_yanxu: None,
            },
            root: dependency_root.clone(),
            entry: dependency_root.join("主.yx"),
        };
        let graph = package::ResolutionGraph {
            root_dependencies: BTreeMap::from([("依赖".into(), "依赖@1.2.3".into())]),
            root_dev_dependencies: BTreeMap::new(),
            packages: BTreeMap::from([("依赖@1.2.3".into(), dependency)]),
            target: current_target,
        };
        let findings = audit_findings(&manifest, &graph, true).unwrap();
        let codes = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for code in [
            "AUDIT_GIT_SYMBOLIC_REVISION",
            "AUDIT_LICENSE_INVALID",
            "AUDIT_CHECKSUM_INVALID",
            "AUDIT_INSECURE_SOURCE",
            "AUDIT_GIT_REVISION_UNPINNED",
            "AUDIT_TARGET_MISMATCH",
            "AUDIT_NATIVE_ABI_UNSUPPORTED",
            "AUDIT_NATIVE_TARGET_MISMATCH",
            "AUDIT_NATIVE_CHECKSUM_INVALID",
            "AUDIT_NATIVE_UNSIGNED",
        ] {
            assert!(codes.contains(code), "missing audit finding {code}");
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn audit_reads_yanked_and_vulnerability_metadata_from_a_local_registry() {
        let root = temporary_root("audit-registry");
        let application = root.join("应用");
        let registry = root.join("索引");
        let dependency_root = registry.join("索引包/1.2.3");
        write(
            dependency_root.join(package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='索引包'\n版本='1.2.3'\n入口='主.yx'\n许可='MIT'\n",
        );
        write(dependency_root.join("主.yx"), "公 定 值：数 为 1；\n");
        write(
            registry.join("索引包/index.json"),
            serde_json::to_vec_pretty(&json!({
                "versions": [{
                    "version": "1.2.3",
                    "url": "ftp://packages.example.invalid/索引包-1.2.3.tar.gz",
                    "checksum": "a".repeat(64),
                    "yanked": true,
                    "vulnerabilities": [
                        {
                            "id": "YXSA-2026-0001",
                            "severity": "high",
                            "summary": "可达示例漏洞",
                            "url": "https://security.example.invalid/YXSA-2026-0001"
                        },
                        {
                            "id": "YXSA-2026-0000",
                            "severity": "critical",
                            "summary": "已撤回记录",
                            "withdrawn": true
                        },
                        {
                            "id": "不安全公告",
                            "severity": "high",
                            "summary": "无效标识"
                        }
                    ]
                }]
            }))
            .unwrap(),
        );
        write(
            application.join(package::MANIFEST_NAME),
            format!(
                "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='主.yx'\n[依赖]\n索引包={{版='=1.2.3',源={:?}}}\n",
                registry.to_string_lossy()
            ),
        );
        write(application.join("主.yx"), "言「应用」；\n");

        let result = handle(&json!({
            "operation": "audit",
            "path": application,
            "offline": true,
        }))
        .unwrap();
        let codes = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|finding| finding["code"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(codes.contains("AUDIT_YANKED"));
        assert!(codes.contains("AUDIT_INSECURE_SOURCE"));
        assert!(codes.contains("AUDIT_VULNERABILITY_YXSA_2026_0001"));
        assert!(!codes.contains("AUDIT_VULNERABILITY_YXSA_2026_0000"));
        assert!(codes.contains("AUDIT_VULNERABILITY_METADATA_INVALID"));
        assert!(!codes.contains("AUDIT_VULNERABILITY_METADATA_MISSING"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn vulnerability_ids_keep_diagnostic_codes_unambiguous_and_bounded() {
        for id in ["CVE-2026-1234", "GHSA-2345-6789-ABCD", "RUSTSEC-2026-0001"] {
            assert!(valid_vulnerability_id(id));
            assert!(vulnerability_code(id).len() <= 128);
        }
        for id in [
            "cve-2026-1234",
            "YXSA_2026_0001",
            "YXSA.2026.0001",
            "YXSA:2026:0001",
            "METADATA",
            "METADATA-INVALID",
            "METADATA-MISSING",
            "-YXSA-2026-0001",
            "YXSA--2026-0001",
            "YXSA-2026-0001-",
        ] {
            assert!(!valid_vulnerability_id(id));
        }
        assert_eq!(
            vulnerability_code("YXSA-2026-0001"),
            "AUDIT_VULNERABILITY_YXSA_2026_0001"
        );
        assert_ne!(
            vulnerability_code("YXSA-2026-0001"),
            vulnerability_code("YXSA-2026-0002")
        );
        assert!(!valid_vulnerability_id(&"A".repeat(97)));
    }

    #[test]
    fn registry_artifact_sources_follow_remote_and_local_transport_boundaries() {
        assert!(secure_registry_artifact_source(
            "https://packages.example.invalid/v1",
            "https://cdn.example.invalid/package.tar.gz"
        ));
        for source in [
            "http://cdn.example.invalid/package.tar.gz",
            "ftp://cdn.example.invalid/package.tar.gz",
            "HTTPS://cdn.example.invalid/package.tar.gz",
        ] {
            assert!(!secure_registry_artifact_source(
                "https://packages.example.invalid/v1",
                source
            ));
        }
        assert!(secure_registry_artifact_source(
            "file:///tmp/registry",
            "file:///tmp/package.tar.gz"
        ));
        assert!(secure_registry_artifact_source(
            "/tmp/registry",
            "../package.tar.gz"
        ));
        assert!(!secure_registry_artifact_source(
            "/tmp/registry",
            "ftp://cdn.example.invalid/package.tar.gz"
        ));
    }
}

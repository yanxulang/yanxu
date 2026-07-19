//! 从公开声明生成稳定 Markdown API 文档。

use crate::ast::{Parameter, Stmt, StmtKind, TypeKind, TypePath, TypeRef, Visibility};
use crate::type_model::{
    ModuleId, RuntimeType, RuntimeTypePath, TypeDeclarationKind, TypeId, TypeLink,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const BUILTIN_TYPES: &[(&str, &str)] = &[
    ("数", "有限浮点数"),
    ("文", "Unicode 文字"),
    ("字节串", "不可变的任意二进制数据"),
    ("理", "真或假"),
    ("空", "无值"),
    ("列", "可变有序容器"),
    ("元", "不可变定长容器"),
    ("典", "键值映射"),
    ("法", "可调用值"),
    ("遍器", "惰性迭代器"),
    ("误", "结构化错误"),
    ("任务", "可取消的异步计算"),
    ("模块", "模块命名空间"),
    ("任意", "动态未知类型"),
];

pub const MODULE_API_MANIFEST_VERSION: u32 = 2;
pub const MODULE_API_SCHEMA: &str = "https://yanxu.dev/schemas/module-api-v2.json";

pub fn markdown(module_name: &str, statements: &[Stmt]) -> String {
    let context = TypeLinks::standalone(statements);
    markdown_with_context(module_name, statements, &context)
}

pub fn markdown_in_directory(
    module_name: &str,
    statements: &[Stmt],
    directory: &Path,
) -> Result<String, String> {
    let index = DocIndex::from_root(module_name, statements, directory)?;
    let context = TypeLinks::indexed(&index, index.root_module.clone());
    Ok(markdown_with_context(module_name, statements, &context))
}

fn markdown_with_context(
    module_name: &str,
    statements: &[Stmt],
    context: &TypeLinks<'_>,
) -> String {
    let public = statements
        .iter()
        .filter(|statement| statement.public && declaration_name(statement).is_some())
        .collect::<Vec<_>>();
    let mut output = format!(
        "# {module_name}\n\n> 由 `yanxu 文` 生成。所有锚点由声明类别与名称确定，可跨版本稳定引用。\n\n"
    );
    output.push_str("## 模块索引\n\n");
    if public.is_empty() {
        output.push_str("此模块未声明公开 API。\n\n");
    } else {
        output.push_str("| 名称 | 类别 | 类型 |\n| --- | --- | --- |\n");
        for statement in &public {
            let (name, kind, anchor, ty) = declaration_summary(statement, context);
            output.push_str(&format!("| [`{name}`](#{anchor}) | {kind} | {ty} |\n"));
        }
        output.push('\n');
    }

    for statement in public {
        render_declaration(&mut output, statement, context);
    }
    render_builtin_types(&mut output);
    output
}

/// Stable machine-readable API surface used by package tooling and LSP clients.
pub fn api_manifest(module_name: &str, statements: &[Stmt]) -> Value {
    let directory = statements
        .first()
        .and_then(|statement| Path::new(&statement.span.source.name).parent())
        .unwrap_or_else(|| Path::new("."));
    api_manifest_in_directory(module_name, statements, directory).unwrap_or_else(|_| {
        let index = DocIndex::single(module_name, statements);
        api_manifest_with_index(module_name, statements, &index)
    })
}

pub fn api_manifest_in_directory(
    module_name: &str,
    statements: &[Stmt],
    directory: &Path,
) -> Result<Value, String> {
    let index = DocIndex::from_root(module_name, statements, directory)?;
    Ok(api_manifest_with_index(module_name, statements, &index))
}

fn api_manifest_with_index(module_name: &str, statements: &[Stmt], index: &DocIndex) -> Value {
    let module_id = index.root_module.clone();
    let declarations = statements
        .iter()
        .filter(|statement| statement.public)
        .filter_map(|statement| api_declaration(statement, module_name, &module_id, index))
        .collect::<Vec<_>>();
    json!({
        "$schema": MODULE_API_SCHEMA,
        "format_version": MODULE_API_MANIFEST_VERSION,
        "language": "yanxu",
        "module": module_name,
        "module_id": module_id,
        "declarations": declarations,
    })
}

fn api_declaration(
    statement: &Stmt,
    module_name: &str,
    module_id: &ModuleId,
    index: &DocIndex,
) -> Option<Value> {
    let documentation = comment_before(&statement.span).unwrap_or_default();
    let context = ApiContext {
        module_name,
        module_id,
        index,
        owner: None,
    };
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => Some(json!({
            "kind": if *mutable { "variable" } else { "constant" },
            "declaration_kind": if *mutable { "variable" } else { "constant" },
            "name": name,
            "owner_module": module_id,
            "original_module": module_id,
            "qualified_name": qualified_value_name(module_id, name),
            "exposed_path": [module_name, name],
            "type": api_optional_type(type_ref.as_ref(), module_id, index),
            "display_type": type_ref.as_ref().map_or("任意", |ty| ty.name.as_str()),
            "documentation": documentation,
        })),
        StmtKind::Function { .. } => {
            Some(api_function(statement, "function", documentation, &context))
        }
        StmtKind::Class {
            name,
            superclass,
            protocols,
            fields,
            methods,
        } => {
            let type_id = TypeId::new(module_id.clone(), name.clone(), TypeDeclarationKind::Class);
            Some(json!({
                "kind": "class",
                "declaration_kind": "class",
                "name": name,
                "type_id": type_id,
                "owner_module": module_id,
                "original_module": module_id,
                "qualified_name": type_id.qualified_name(),
                "exposed_path": [module_name, name],
                "superclass": superclass.as_ref().map(|path| api_type_link(path, module_id, index)),
                "protocols": protocols.iter().map(|path| api_type_link(path, module_id, index)).collect::<Vec<_>>(),
                "documentation": documentation,
                "fields": fields.iter()
                    .filter(|field| field.visibility == Visibility::Public)
                    .map(|field| json!({
                        "name": field.name,
                        "type": api_type(&field.type_ref.kind, module_id, index),
                        "display_type": field.type_ref.name,
                        "readonly": field.readonly,
                        "static": field.is_static,
                        "documentation": comment_before(&field.span).unwrap_or_default(),
                    }))
                    .collect::<Vec<_>>(),
                "methods": methods.iter()
                    .filter(|method| method.member_visibility == Visibility::Public)
                    .map(|method| api_function(
                        method,
                        "method",
                        comment_before(&method.span).unwrap_or_default(),
                        &context.with_owner(name),
                    ))
                    .collect::<Vec<_>>(),
            }))
        }
        StmtKind::Protocol {
            name,
            fields,
            methods,
        } => {
            let type_id = TypeId::new(
                module_id.clone(),
                name.clone(),
                TypeDeclarationKind::Protocol,
            );
            Some(json!({
                "kind": "protocol",
                "declaration_kind": "protocol",
                "name": name,
                "type_id": type_id,
                "owner_module": module_id,
                "original_module": module_id,
                "qualified_name": type_id.qualified_name(),
                "exposed_path": [module_name, name],
                "documentation": documentation,
                "fields": fields.iter().map(|field| json!({
                    "name": field.name,
                    "type": api_type(&field.type_ref.kind, module_id, index),
                    "display_type": field.type_ref.name,
                })).collect::<Vec<_>>(),
                "methods": methods.iter().map(|method| api_function(
                    method,
                    "method",
                    comment_before(&method.span).unwrap_or_default(),
                    &context.with_owner(name),
                )).collect::<Vec<_>>(),
            }))
        }
        StmtKind::Import { path, alias } => {
            let target = index.imported_module(module_id, alias);
            let exports = target.as_ref().map_or_else(Vec::new, |target| {
                index.exposed_exports(target, &[module_name.to_owned(), alias.clone()])
            });
            Some(json!({
                "kind": "module_reexport",
                "declaration_kind": "module",
                "name": alias,
                "source": path,
                "owner_module": module_id,
                "original_module": target,
                "qualified_name": qualified_value_name(module_id, alias),
                "exposed_path": [module_name, alias],
                "exports": exports,
                "documentation": documentation,
            }))
        }
        _ => None,
    }
}

struct ApiContext<'a> {
    module_name: &'a str,
    module_id: &'a ModuleId,
    index: &'a DocIndex,
    owner: Option<&'a str>,
}

impl<'a> ApiContext<'a> {
    fn with_owner(&self, owner: &'a str) -> Self {
        Self {
            module_name: self.module_name,
            module_id: self.module_id,
            index: self.index,
            owner: Some(owner),
        }
    }

    fn qualified_name(&self, name: &str) -> String {
        self.owner.map_or_else(
            || qualified_value_name(self.module_id, name),
            |owner| format!("{}.{owner}.{name}", self.module_id),
        )
    }

    fn exposed_path(&self, name: &str) -> Vec<String> {
        let mut path = vec![self.module_name.to_owned()];
        if let Some(owner) = self.owner {
            path.push(owner.to_owned());
        }
        path.push(name.to_owned());
        path
    }
}

fn api_function(
    statement: &Stmt,
    kind: &str,
    documentation: String,
    context: &ApiContext<'_>,
) -> Value {
    let StmtKind::Function {
        name,
        params: parameters,
        return_type: result,
        is_async,
        ..
    } = &statement.kind
    else {
        unreachable!("API function renderer receives only function statements")
    };
    let parameters = parameters
        .iter()
        .map(|parameter| {
            json!({
                "name": parameter.name,
                "type": api_optional_type(parameter.type_ref.as_ref(), context.module_id, context.index),
                "display_type": parameter.type_ref.as_ref().map_or("任意", |ty| ty.name.as_str()),
            })
        })
        .collect::<Vec<_>>();
    let result_type = api_optional_type(result.as_ref(), context.module_id, context.index);
    let display_result = result
        .as_ref()
        .map_or_else(|| "任意".to_owned(), |ty| ty.name.clone());
    let signature = format!(
        "法（{}）：{}",
        parameters
            .iter()
            .map(|parameter| parameter["display_type"].as_str().unwrap_or("任意"))
            .collect::<Vec<_>>()
            .join("，"),
        if *is_async {
            format!("任务<{display_result}>")
        } else {
            display_result.clone()
        }
    );
    json!({
        "kind": kind,
        "declaration_kind": kind,
        "name": name,
        "owner_module": context.module_id,
        "original_module": context.module_id,
        "qualified_name": context.qualified_name(name),
        "exposed_path": context.exposed_path(name),
        "parameters": parameters,
        "result": result_type,
        "display_result": display_result,
        "async": is_async,
        "static": statement.is_static,
        "signature": signature,
        "documentation": documentation,
    })
}

fn api_optional_type(type_ref: Option<&TypeRef>, module_id: &ModuleId, index: &DocIndex) -> Value {
    json!(type_ref.map_or_else(
        || RuntimeType::named("任意"),
        |type_ref| api_type(&type_ref.kind, module_id, index)
    ))
}

fn api_type(kind: &TypeKind, module_id: &ModuleId, index: &DocIndex) -> RuntimeType {
    match kind {
        TypeKind::Named(path) => RuntimeType::Named {
            link: api_type_link(path, module_id, index),
        },
        TypeKind::Union(types) => RuntimeType::Union {
            variants: types
                .iter()
                .map(|ty| api_type(ty, module_id, index))
                .collect(),
        },
        TypeKind::Nullable(inner) => RuntimeType::Nullable {
            inner: Box::new(api_type(inner, module_id, index)),
        },
        TypeKind::Generic { base, arguments } => RuntimeType::Generic {
            base: api_type_link(base, module_id, index),
            arguments: arguments
                .iter()
                .map(|ty| api_type(ty, module_id, index))
                .collect(),
        },
        TypeKind::Function { parameters, result } => RuntimeType::Function {
            parameters: parameters
                .iter()
                .map(|ty| api_type(ty, module_id, index))
                .collect(),
            result: Box::new(api_type(result, module_id, index)),
        },
    }
}

fn api_type_link(path: &TypePath, module_id: &ModuleId, index: &DocIndex) -> TypeLink {
    let source = RuntimeTypePath::new(path.names().map(str::to_owned).collect());
    match index.resolve_type(module_id, &source.segments) {
        Some(target) => TypeLink::resolved(source, target),
        None => TypeLink::unresolved(source),
    }
}

fn qualified_value_name(module_id: &ModuleId, name: &str) -> String {
    format!("{module_id}.{name}")
}

#[derive(Clone)]
struct DocModule {
    display_name: String,
    imports: BTreeMap<String, ModuleId>,
    public_imports: BTreeSet<String>,
    local_types: BTreeMap<String, TypeId>,
    public_types: BTreeSet<String>,
    public_symbols: BTreeMap<String, String>,
}

struct DocIndex {
    root_module: ModuleId,
    modules: BTreeMap<ModuleId, DocModule>,
    documented_modules: BTreeSet<ModuleId>,
    trusted_package_roots: crate::package::TrustedPackageRoots,
}

impl DocIndex {
    fn single(module_name: &str, statements: &[Stmt]) -> Self {
        let module_id = module_id_for_statements(statements, module_name);
        let module = DocModule::new(module_name, statements);
        Self {
            root_module: module_id.clone(),
            modules: BTreeMap::from([(module_id, module)]),
            documented_modules: BTreeSet::new(),
            trusted_package_roots: crate::package::TrustedPackageRoots::default(),
        }
    }

    fn from_root(module_name: &str, statements: &[Stmt], directory: &Path) -> Result<Self, String> {
        if fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(format!(
                "文档模块目录不得为符号链接“{}”",
                directory.display()
            ));
        }
        let requested_directory = if directory.is_absolute() {
            directory.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("不能定位当前目录：{error}"))?
                .join(directory)
        };
        let mut trusted_package_roots = trusted_package_roots(&requested_directory)?;
        if let Some(root) = trusted_package_roots.matching_root(&requested_directory)
            && root != requested_directory
        {
            trusted_package_roots
                .authorize_module(&requested_directory, &requested_directory)
                .map_err(|error| error.to_string())?;
        }
        let directory = if trusted_package_roots
            .matching_root(&requested_directory)
            .is_some_and(|root| root == requested_directory)
        {
            fs::canonicalize(&requested_directory).map_err(|error| {
                format!(
                    "不能定位文档模块目录“{}”：{error}",
                    requested_directory.display()
                )
            })?
        } else {
            match trusted_package_roots
                .resolve_existing_module_path(&requested_directory)
                .map_err(|error| error.to_string())?
            {
                Some(path) => path,
                None => fs::canonicalize(&requested_directory).map_err(|error| {
                    format!(
                        "不能定位文档模块目录“{}”：{error}",
                        requested_directory.display()
                    )
                })?,
            }
        };
        trusted_package_roots
            .insert_discovered(&directory)
            .map_err(|error| error.to_string())?;
        if trusted_package_roots.roots().all(|root| root != directory) {
            trusted_package_roots
                .authorize_module(&requested_directory, &directory)
                .map_err(|error| error.to_string())?;
        }
        let root_module = module_id_for_statements(statements, module_name);
        if let Some(source) = statements.first().and_then(|statement| {
            let path = Path::new(&statement.span.source.name);
            path.exists().then(|| fs::canonicalize(path).ok()).flatten()
        }) {
            trusted_package_roots
                .authorize_module(&source, &source)
                .map_err(|error| error.to_string())?;
        }
        let mut index = Self {
            root_module: root_module.clone(),
            modules: BTreeMap::new(),
            documented_modules: BTreeSet::from([root_module.clone()]),
            trusted_package_roots,
        };
        index.load_module(
            root_module,
            module_name.to_owned(),
            statements.to_vec(),
            &directory,
        )?;
        Ok(index)
    }

    fn from_directory(root: &Path, modules: &[(String, Vec<Stmt>)]) -> Result<Self, String> {
        let root_module = modules.first().map_or_else(
            || ModuleId::for_source("<空文档目录>"),
            |(name, statements)| module_id_for_statements(statements, name),
        );
        let mut index = Self {
            root_module,
            modules: BTreeMap::new(),
            documented_modules: BTreeSet::new(),
            trusted_package_roots: trusted_package_roots(root)?,
        };
        for (name, statements) in modules {
            let module_id = module_id_for_statements(statements, name);
            let directory = statements
                .first()
                .and_then(|statement| Path::new(&statement.span.source.name).parent())
                .unwrap_or(root);
            index.load_module(
                module_id.clone(),
                name.clone(),
                statements.clone(),
                directory,
            )?;
            if let Some(module) = index.modules.get_mut(&module_id) {
                module.display_name = name.clone();
            }
            index.documented_modules.insert(module_id);
        }
        Ok(index)
    }

    fn load_module(
        &mut self,
        module_id: ModuleId,
        display_name: String,
        statements: Vec<Stmt>,
        directory: &Path,
    ) -> Result<(), String> {
        if self.modules.contains_key(&module_id) {
            return Ok(());
        }
        let imports = statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                StmtKind::Import { path, alias } => {
                    Some((path.clone(), alias.clone(), statement.public))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        self.modules.insert(
            module_id.clone(),
            DocModule::new(&display_name, &statements),
        );
        for (requested, alias, public) in imports {
            let target = self.load_import(&requested, directory)?;
            let module = self
                .modules
                .get_mut(&module_id)
                .expect("module inserted before imports are loaded");
            module.imports.insert(alias.clone(), target);
            if public {
                module.public_imports.insert(alias);
            }
        }
        Ok(())
    }

    fn load_import(&mut self, requested: &str, directory: &Path) -> Result<ModuleId, String> {
        crate::package::validate_portable_path_text(requested)
            .map_err(|error| error.to_string())?;
        if let Some(name) = requested.strip_prefix("标准:") {
            return Ok(ModuleId::standard(name));
        }
        let (path, package_import) = if let Some(name) = requested.strip_prefix("包:") {
            let dependency = crate::package::resolve_dependency_scoped(None, directory, name)
                .map_err(|error| error.to_string())?;
            self.trusted_package_roots
                .insert(&dependency.root)
                .map_err(|error| error.to_string())?;
            (dependency.entry, true)
        } else {
            let requested = Path::new(requested);
            if requested.is_absolute() {
                (requested.to_path_buf(), false)
            } else {
                (directory.join(requested), false)
            }
        };
        let (resolved, _) = self
            .trusted_package_roots
            .resolve_import_file(directory, &path, package_import)
            .map_err(|error| error.to_string())?;
        let canonical = resolved.path().to_path_buf();
        let module_id = ModuleId::for_path(&canonical);
        if self.modules.contains_key(&module_id) {
            return Ok(module_id);
        }
        let resolved = resolved.open().map_err(|error| error.to_string())?;
        let source = crate::package::read_resolved_module_source_snapshot(resolved)
            .map_err(|error| format!("不能读取文档模块“{}”：{error}", canonical.display()))?;
        let statements = crate::parse_named(&source, canonical.display().to_string())
            .map_err(|error| error.to_string())?;
        let display_name = canonical
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("无名模块")
            .to_owned();
        let child_directory = canonical.parent().unwrap_or(directory);
        self.load_module(module_id.clone(), display_name, statements, child_directory)?;
        Ok(module_id)
    }

    fn imported_module(&self, module_id: &ModuleId, alias: &str) -> Option<ModuleId> {
        self.modules.get(module_id)?.imports.get(alias).cloned()
    }

    fn resolve_type(&self, module_id: &ModuleId, segments: &[String]) -> Option<TypeId> {
        let module = self.modules.get(module_id)?;
        match segments {
            [name] => module.local_types.get(name).cloned(),
            [alias, rest @ ..] => {
                let mut target = module.imports.get(alias)?.clone();
                for segment in &rest[..rest.len().saturating_sub(1)] {
                    let module = self.modules.get(&target)?;
                    if !module.public_imports.contains(segment) {
                        return None;
                    }
                    target = module.imports.get(segment)?.clone();
                }
                let name = rest.last()?;
                let module = self.modules.get(&target)?;
                module
                    .public_types
                    .contains(name)
                    .then(|| module.local_types.get(name).cloned())?
            }
            [] => None,
        }
    }

    fn exposed_exports(&self, module_id: &ModuleId, prefix: &[String]) -> Vec<Value> {
        self.exposed_exports_inner(module_id, prefix, &mut HashSet::new())
    }

    fn exposed_exports_inner(
        &self,
        module_id: &ModuleId,
        prefix: &[String],
        visiting: &mut HashSet<ModuleId>,
    ) -> Vec<Value> {
        if !visiting.insert(module_id.clone()) {
            return Vec::new();
        }
        let Some(module) = self.modules.get(module_id) else {
            visiting.remove(module_id);
            return Vec::new();
        };
        let mut exports = Vec::new();
        for (name, kind) in &module.public_symbols {
            let mut exposed_path = prefix.to_vec();
            exposed_path.push(name.clone());
            let mut export = json!({
                "kind": kind,
                "declaration_kind": kind,
                "name": name,
                "owner_module": module_id,
                "original_module": module_id,
                "qualified_name": qualified_value_name(module_id, name),
                "exposed_path": exposed_path,
            });
            if let Some(type_id) = module.local_types.get(name) {
                export["type_id"] = json!(type_id);
                export["qualified_name"] = json!(type_id.qualified_name());
            }
            exports.push(export);
        }
        for alias in &module.public_imports {
            let Some(target) = module.imports.get(alias) else {
                continue;
            };
            let mut exposed_path = prefix.to_vec();
            exposed_path.push(alias.clone());
            exports.push(json!({
                "kind": "module_reexport",
                "declaration_kind": "module",
                "name": alias,
                "owner_module": module_id,
                "original_module": target,
                "qualified_name": qualified_value_name(module_id, alias),
                "exposed_path": exposed_path,
                "exports": self.exposed_exports_inner(target, &exposed_path, visiting),
            }));
        }
        visiting.remove(module_id);
        exports
    }

    fn type_anchor(&self, type_id: &TypeId) -> Option<String> {
        if !self.documented_modules.contains(&type_id.module) {
            return None;
        }
        let module = self.modules.get(&type_id.module)?;
        Some(stable_anchor(
            &format!(
                "模块-{}-{}",
                module.display_name,
                match type_id.kind {
                    TypeDeclarationKind::Class => "类",
                    TypeDeclarationKind::Protocol => "协",
                }
            ),
            &type_id.name,
        ))
    }
}

impl DocModule {
    fn new(display_name: &str, statements: &[Stmt]) -> Self {
        let module_id = module_id_for_statements(statements, display_name);
        let mut local_types = BTreeMap::new();
        let mut public_types = BTreeSet::new();
        let mut public_symbols = BTreeMap::new();
        for statement in statements {
            let declaration = match &statement.kind {
                StmtKind::Class { name, .. } => Some((name, TypeDeclarationKind::Class)),
                StmtKind::Protocol { name, .. } => Some((name, TypeDeclarationKind::Protocol)),
                _ => None,
            };
            if let Some((name, kind)) = declaration {
                local_types.insert(
                    name.clone(),
                    TypeId::new(module_id.clone(), name.clone(), kind),
                );
                if statement.public {
                    public_types.insert(name.clone());
                }
            }
            if statement.public {
                let symbol = match &statement.kind {
                    StmtKind::Let { name, mutable, .. } => {
                        Some((name, if *mutable { "variable" } else { "constant" }))
                    }
                    StmtKind::Function { name, .. } => Some((name, "function")),
                    StmtKind::Class { name, .. } => Some((name, "class")),
                    StmtKind::Protocol { name, .. } => Some((name, "protocol")),
                    _ => None,
                };
                if let Some((name, kind)) = symbol {
                    public_symbols.insert(name.clone(), kind.to_owned());
                }
            }
        }
        Self {
            display_name: display_name.to_owned(),
            imports: BTreeMap::new(),
            public_imports: BTreeSet::new(),
            local_types,
            public_types,
            public_symbols,
        }
    }
}

fn module_id_for_statements(statements: &[Stmt], fallback: &str) -> ModuleId {
    statements
        .first()
        .map(|statement| ModuleId::for_source(&statement.span.source.name))
        .unwrap_or_else(|| ModuleId::for_source(fallback))
}

pub fn markdown_directory(path: impl AsRef<Path>) -> Result<String, String> {
    let requested = path.as_ref();
    if fs::symlink_metadata(requested).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!("文档入口不得为符号链接“{}”", requested.display()));
    }
    let requested_absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("不能定位当前目录：{error}"))?
            .join(requested)
    };
    let mut trusted_package_roots = trusted_package_roots(&requested_absolute)?;
    if let Some(package_root) = trusted_package_roots.matching_root(&requested_absolute)
        && package_root != requested_absolute
    {
        trusted_package_roots
            .authorize_module(&requested_absolute, &requested_absolute)
            .map_err(|error| error.to_string())?;
    }
    let root = if trusted_package_roots
        .matching_root(&requested_absolute)
        .is_some_and(|root| root == requested_absolute)
    {
        fs::canonicalize(&requested_absolute).map_err(|error| {
            format!(
                "不能定位文档目录“{}”：{error}",
                requested_absolute.display()
            )
        })?
    } else {
        match trusted_package_roots
            .resolve_existing_module_path(&requested_absolute)
            .map_err(|error| error.to_string())?
        {
            Some(path) => path,
            None => fs::canonicalize(&requested_absolute).map_err(|error| {
                format!(
                    "不能定位文档目录“{}”：{error}",
                    requested_absolute.display()
                )
            })?,
        }
    };
    trusted_package_roots
        .insert_discovered(&root)
        .map_err(|error| error.to_string())?;
    if trusted_package_roots
        .roots()
        .all(|package_root| package_root != root)
    {
        trusted_package_roots
            .authorize_module(&requested_absolute, &root)
            .map_err(|error| error.to_string())?;
    }
    let mut files = Vec::new();
    let mut portable_paths = BTreeMap::new();
    visit(
        &root,
        &trusted_package_roots,
        &mut portable_paths,
        &mut files,
    )?;
    files.sort_by_key(|file| documentation_path_key(&trusted_package_roots, file));
    let mut modules = Vec::new();
    for file in files {
        let current_base = file.parent().unwrap_or(&root);
        let (resolved, _) = trusted_package_roots
            .resolve_import_file(current_base, &file, false)
            .map_err(|error| error.to_string())?;
        let canonical = resolved.path().to_path_buf();
        let resolved = resolved.open().map_err(|error| error.to_string())?;
        let source = crate::package::read_resolved_module_source_snapshot(resolved)
            .map_err(|error| format!("不能读取“{}”：{error}", canonical.display()))?;
        let statements = crate::parse_named(&source, canonical.display().to_string())
            .map_err(|error| error.to_string())?;
        let relative = canonical
            .strip_prefix(&root)
            .unwrap_or(&canonical)
            .with_extension("");
        let name =
            crate::package::portable_package_path(&relative).map_err(|error| error.to_string())?;
        modules.push((name, statements));
    }

    let index = DocIndex::from_directory(&root, &modules)?;

    let mut output = "# 言序模块文档\n\n## 模块索引\n\n".to_owned();
    for (name, _) in &modules {
        output.push_str(&format!("- [`{name}`](#模块-{})\n", anchor_text(name)));
    }
    if modules.is_empty() {
        output.push_str("未发现 `.yx` 模块。\n");
    }
    for (name, statements) in &modules {
        output.push_str(&format!(
            "\n<a id=\"模块-{}\"></a>\n\n---\n\n",
            anchor_text(name)
        ));
        let module_id = module_id_for_statements(statements, name);
        let context = TypeLinks::indexed(&index, module_id);
        output.push_str(&markdown_with_context(name, statements, &context));
    }
    Ok(output)
}

fn documentation_path_key(roots: &crate::package::TrustedPackageRoots, path: &Path) -> String {
    roots
        .matching_root(path)
        .and_then(|root| path.strip_prefix(root).ok())
        .and_then(|relative| crate::package::portable_package_path(relative).ok())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

pub fn stable_anchor(kind: &str, name: &str) -> String {
    format!("{}-{}", anchor_text(kind), anchor_text(name))
}

fn render_declaration(output: &mut String, statement: &Stmt, context: &TypeLinks<'_>) {
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => {
            let kind = if *mutable { "变量" } else { "常量" };
            heading(output, kind, name, statement, context);
            output.push_str(&format!(
                "```yanxu\n公 {} {name}{}；\n```\n\n",
                if *mutable { "令" } else { "定" },
                render_type_plain(type_ref.as_ref())
            ));
            output.push_str(&format!(
                "类型：{}\n\n",
                context.render_optional(type_ref.as_ref())
            ));
        }
        StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } => {
            heading(
                output,
                if *is_async { "异法" } else { "法" },
                name,
                statement,
                context,
            );
            output.push_str(&format!(
                "```yanxu\n公 {}法 {name}（{}）{}；\n```\n\n",
                if *is_async { "异 " } else { "" },
                params
                    .iter()
                    .map(render_parameter_plain)
                    .collect::<Vec<_>>()
                    .join("，"),
                render_type_plain(return_type.as_ref())
            ));
            output.push_str(&format!(
                "{}：{}\n\n",
                if *is_async {
                    "任务完成值"
                } else {
                    "归值"
                },
                context.render_optional(return_type.as_ref()),
            ));
            render_parameters(output, params, context);
        }
        StmtKind::Class {
            name,
            superclass,
            protocols,
            fields,
            methods,
        } => {
            heading(output, "类", name, statement, context);
            let inheritance = superclass
                .as_ref()
                .map_or_else(String::new, |parent| format!(" 承 {parent}"));
            let conformance = if protocols.is_empty() {
                String::new()
            } else {
                format!(
                    " 纳 {}",
                    protocols
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("，")
                )
            };
            output.push_str(&format!(
                "```yanxu\n公 类 {name}{inheritance}{conformance}\n```\n\n"
            ));
            if let Some(parent) = superclass {
                output.push_str(&format!(
                    "父类：{}\n\n父类所有者：{}\n\n",
                    context.render_path(parent),
                    context.render_owner(parent)
                ));
            }
            if !protocols.is_empty() {
                output.push_str("协议：\n\n");
                for protocol in protocols {
                    output.push_str(&format!(
                        "- {}（所有者：{}）\n",
                        context.render_path(protocol),
                        context.render_owner(protocol)
                    ));
                }
                output.push('\n');
            }
            for field in fields
                .iter()
                .filter(|field| field.visibility == Visibility::Public)
            {
                let anchor = context.declaration_anchor(&format!("类-{name}-域"), &field.name);
                output.push_str(&format!(
                    "<a id=\"{anchor}\"></a>\n\n### 域 `{}`\n\n",
                    field.name
                ));
                render_comment(output, comment_before(&field.span));
                output.push_str(&format!(
                    "- 类型：{}\n- 属性：{}{}{}\n\n",
                    context.render(&field.type_ref.kind),
                    if field.is_static { "静态" } else { "实例" },
                    if field.readonly { "、只读" } else { "" },
                    if field.visibility == Visibility::Private {
                        "、私有"
                    } else {
                        "、公开"
                    }
                ));
            }
            for method in methods
                .iter()
                .filter(|method| method.member_visibility == Visibility::Public)
            {
                if let StmtKind::Function {
                    name: method_name,
                    params,
                    return_type,
                    is_async,
                    ..
                } = &method.kind
                {
                    let anchor = context.declaration_anchor(&format!("类-{name}-法"), method_name);
                    output.push_str(&format!(
                        "<a id=\"{anchor}\"></a>\n\n### 法 `{method_name}`\n\n"
                    ));
                    render_comment(output, comment_before(&method.span));
                    output.push_str(&format!(
                        "类型：`法`（{}） → {}\n\n",
                        params
                            .iter()
                            .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                            .collect::<Vec<_>>()
                            .join("，"),
                        if *is_async {
                            format!("任务<{}>", context.render_optional(return_type.as_ref()))
                        } else {
                            context.render_optional(return_type.as_ref())
                        }
                    ));
                }
            }
        }
        StmtKind::Protocol {
            name,
            fields,
            methods,
        } => {
            heading(output, "协", name, statement, context);
            for field in fields {
                output.push_str(&format!(
                    "- 域 `{}`：{}\n",
                    field.name,
                    context.render(&field.type_ref.kind)
                ));
            }
            for method in methods {
                if let StmtKind::Function {
                    name,
                    params,
                    return_type,
                    is_async,
                    ..
                } = &method.kind
                {
                    output.push_str(&format!(
                        "- 法 `{name}`（{}）→ {}\n",
                        params
                            .iter()
                            .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                            .collect::<Vec<_>>()
                            .join("，"),
                        if *is_async {
                            format!("任务<{}>", context.render_optional(return_type.as_ref()))
                        } else {
                            context.render_optional(return_type.as_ref())
                        }
                    ));
                }
            }
            output.push('\n');
        }
        StmtKind::Import { path, alias } => {
            heading(output, "模块", alias, statement, context);
            output.push_str(&format!("```yanxu\n公 引「{path}」为 {alias}；\n```\n\n"));
            output.push_str(&format!("原始模块：{}\n\n", context.render_module(alias)));
        }
        _ => {}
    }
}

fn heading(output: &mut String, kind: &str, name: &str, statement: &Stmt, context: &TypeLinks<'_>) {
    let anchor = context.declaration_anchor(kind, name);
    output.push_str(&format!(
        "<a id=\"{anchor}\"></a>\n\n## {kind} `{name}`\n\n"
    ));
    render_comment(output, comment_before(&statement.span));
}

fn render_comment(output: &mut String, comment: Option<String>) {
    if let Some(comment) = comment {
        output.push_str(&comment);
        output.push_str("\n\n");
    }
}

fn render_parameters(output: &mut String, parameters: &[Parameter], context: &TypeLinks<'_>) {
    if parameters.is_empty() {
        return;
    }
    output.push_str("参数：\n\n");
    for parameter in parameters {
        output.push_str(&format!(
            "- `{}`：{}\n",
            parameter.name,
            context.render_optional(parameter.type_ref.as_ref())
        ));
    }
    output.push('\n');
}

fn declaration_summary(
    statement: &Stmt,
    context: &TypeLinks<'_>,
) -> (String, &'static str, String, String) {
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => {
            let kind = if *mutable { "变量" } else { "常量" };
            (
                name.clone(),
                kind,
                context.declaration_anchor(kind, name),
                context.render_optional(type_ref.as_ref()),
            )
        }
        StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } => (
            name.clone(),
            "法",
            context.declaration_anchor("法", name),
            format!(
                "`法`（{}）→ {}",
                params
                    .iter()
                    .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                    .collect::<Vec<_>>()
                    .join("，"),
                if *is_async {
                    format!("任务<{}>", context.render_optional(return_type.as_ref()))
                } else {
                    context.render_optional(return_type.as_ref())
                }
            ),
        ),
        StmtKind::Class { name, .. } => (
            name.clone(),
            "类",
            context.declaration_anchor("类", name),
            context.render_local_named(name),
        ),
        StmtKind::Protocol { name, .. } => (
            name.clone(),
            "协",
            context.declaration_anchor("协", name),
            context.render_local_named(name),
        ),
        StmtKind::Import { path, alias } => (
            alias.clone(),
            "模块",
            context.declaration_anchor("模块", alias),
            context.render_import_summary(alias, path),
        ),
        _ => unreachable!("filtered to declarations"),
    }
}

fn declaration_name(statement: &Stmt) -> Option<&str> {
    match &statement.kind {
        StmtKind::Let { name, .. }
        | StmtKind::Function { name, .. }
        | StmtKind::Class { name, .. }
        | StmtKind::Protocol { name, .. } => Some(name),
        StmtKind::Import { alias, .. } => Some(alias),
        _ => None,
    }
}

struct TypeLinks<'a> {
    declarations: HashMap<String, String>,
    index: Option<&'a DocIndex>,
    module_id: Option<ModuleId>,
    qualified_anchors: bool,
}

impl<'a> TypeLinks<'a> {
    fn standalone(statements: &[Stmt]) -> Self {
        let declarations = statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                StmtKind::Class { name, .. } if statement.public => {
                    Some((name.clone(), stable_anchor("类", name)))
                }
                StmtKind::Protocol { name, .. } if statement.public => {
                    Some((name.clone(), stable_anchor("协", name)))
                }
                _ => None,
            })
            .collect();
        Self {
            declarations,
            index: None,
            module_id: None,
            qualified_anchors: false,
        }
    }

    fn indexed(index: &'a DocIndex, module_id: ModuleId) -> Self {
        Self {
            declarations: HashMap::new(),
            index: Some(index),
            module_id: Some(module_id),
            qualified_anchors: true,
        }
    }

    fn render_optional(&self, type_ref: Option<&TypeRef>) -> String {
        type_ref.map_or_else(
            || self.render_local_named("任意"),
            |ty| self.render(&ty.kind),
        )
    }

    fn render(&self, kind: &TypeKind) -> String {
        match kind {
            TypeKind::Named(path) => self.render_path(path),
            TypeKind::Union(types) => types
                .iter()
                .map(|ty| self.render(ty))
                .collect::<Vec<_>>()
                .join(" | "),
            TypeKind::Nullable(ty) => format!("{} `?`", self.render(ty)),
            TypeKind::Generic { base, arguments } => format!(
                "{}`<`{} `>`",
                self.render_path(base),
                arguments
                    .iter()
                    .map(|argument| self.render(argument))
                    .collect::<Vec<_>>()
                    .join("，")
            ),
            TypeKind::Function { parameters, result } => format!(
                "{}（{}）→ {}",
                self.render_local_named("法"),
                parameters
                    .iter()
                    .map(|parameter| self.render(parameter))
                    .collect::<Vec<_>>()
                    .join("，"),
                self.render(result)
            ),
        }
    }

    fn render_path(&self, path: &TypePath) -> String {
        let name = path.to_string();
        if let (Some(index), Some(module_id)) = (self.index, self.module_id.as_ref())
            && let Some(type_id) = index.resolve_type(
                module_id,
                &path.names().map(str::to_owned).collect::<Vec<_>>(),
            )
            && let Some(anchor) = index.type_anchor(&type_id)
        {
            return format!("[`{name}`](#{anchor})");
        }
        self.render_local_named(&name)
    }

    fn render_local_named(&self, name: &str) -> String {
        if let (Some(index), Some(module_id)) = (self.index, self.module_id.as_ref())
            && let Some(type_id) = index
                .modules
                .get(module_id)
                .and_then(|module| module.local_types.get(name))
            && let Some(anchor) = index.type_anchor(type_id)
        {
            format!("[`{name}`](#{anchor})")
        } else if let Some(anchor) = self.declarations.get(name) {
            format!("[`{name}`](#{anchor})")
        } else if BUILTIN_TYPES.iter().any(|(builtin, _)| *builtin == name) {
            format!("[`{name}`](#类型-{})", anchor_text(name))
        } else {
            format!("`{name}`")
        }
    }

    fn declaration_anchor(&self, kind: &str, name: &str) -> String {
        if self.qualified_anchors
            && let (Some(index), Some(module_id)) = (self.index, self.module_id.as_ref())
            && let Some(module) = index.modules.get(module_id)
        {
            return stable_anchor(&format!("模块-{}-{kind}", module.display_name), name);
        }
        stable_anchor(kind, name)
    }

    fn render_owner(&self, path: &TypePath) -> String {
        if let (Some(index), Some(module_id)) = (self.index, self.module_id.as_ref())
            && let Some(type_id) = index.resolve_type(
                module_id,
                &path.names().map(str::to_owned).collect::<Vec<_>>(),
            )
        {
            return format!("`{}`", type_id.module);
        }
        "`未解析`".into()
    }

    fn render_module(&self, alias: &str) -> String {
        if let (Some(index), Some(module_id)) = (self.index, self.module_id.as_ref())
            && let Some(target) = index.imported_module(module_id, alias)
        {
            if index.documented_modules.contains(&target)
                && let Some(module) = index.modules.get(&target)
            {
                return format!("[`{target}`](#模块-{})", anchor_text(&module.display_name));
            }
            return format!("`{target}`");
        }
        "`未解析`".into()
    }

    fn render_import_summary(&self, alias: &str, path: &str) -> String {
        if self.index.is_some() {
            self.render_module(alias)
        } else {
            format!("`{path}`")
        }
    }
}

fn render_builtin_types(output: &mut String) {
    output.push_str("## 类型索引\n\n");
    for (name, description) in BUILTIN_TYPES {
        output.push_str(&format!(
            "<a id=\"类型-{}\"></a>\n\n- `{name}`：{description}\n",
            anchor_text(name)
        ));
    }
}

fn render_parameter_plain(parameter: &Parameter) -> String {
    format!(
        "{}{}",
        parameter.name,
        render_type_plain(parameter.type_ref.as_ref())
    )
}

fn render_type_plain(type_ref: Option<&TypeRef>) -> String {
    type_ref.map_or_else(String::new, |type_ref| format!("：{}", type_ref.name))
}

fn comment_before(span: &crate::source::Span) -> Option<String> {
    let lines = span.source.text.lines().collect::<Vec<_>>();
    let mut current = span.line.saturating_sub(1);
    let mut comments = Vec::new();
    while current > 0 {
        let text = lines.get(current - 1)?.trim();
        let comment = text
            .strip_prefix("///")
            .or_else(|| text.strip_prefix("#:"))
            .map(str::trim);
        match comment {
            Some(comment) => comments.push(comment.to_owned()),
            None if text.is_empty() && comments.is_empty() => current -= 1,
            None => break,
        }
        current -= 1;
    }
    comments.reverse();
    (!comments.is_empty()).then(|| comments.join("\n"))
}

fn anchor_text(text: &str) -> String {
    let mut anchor = String::new();
    let mut dash = false;
    for character in text.chars() {
        if character.is_alphanumeric() || matches!(character, '_' | '-') || !character.is_ascii() {
            anchor.push(character.to_ascii_lowercase());
            dash = false;
        } else if !dash && !anchor.is_empty() {
            anchor.push('-');
            dash = true;
        }
    }
    anchor.trim_matches('-').to_owned()
}

fn trusted_package_roots(directory: &Path) -> Result<crate::package::TrustedPackageRoots, String> {
    let mut roots = crate::package::TrustedPackageRoots::default();
    roots
        .insert_discovered(directory)
        .map_err(|error| error.to_string())?;
    Ok(roots)
}

fn visit(
    path: &Path,
    trusted_package_roots: &crate::package::TrustedPackageRoots,
    portable_paths: &mut BTreeMap<PathBuf, crate::package::PortablePackagePaths>,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|error| format!("不能读取目录“{}”：{error}", path.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if let Some(root) = trusted_package_roots.matching_root(&path) {
            let relative = path.strip_prefix(root).expect("matching package root");
            match crate::package::package_path_decision(
                relative,
                crate::package::PackagePathPurpose::YxpEntry,
            )
            .map_err(|error| error.to_string())?
            {
                crate::package::PackagePathDecision::Include => {}
                crate::package::PackagePathDecision::Exclude(_) => continue,
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            let paths = portable_paths.entry(root.to_path_buf()).or_default();
            if metadata.is_dir() {
                paths
                    .insert_directory(relative)
                    .map_err(|error| error.to_string())?;
            } else {
                paths.insert(relative).map_err(|error| error.to_string())?;
            }
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("文档目录不得包含符号链接“{}”", path.display()));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            trusted_package_roots
                .authorize_module(&path, &canonical)
                .map_err(|error| error.to_string())?;
            visit(&canonical, trusted_package_roots, portable_paths, files)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "yx")
        {
            trusted_package_roots
                .authorize_module(&path, &canonical)
                .map_err(|error| error.to_string())?;
            files.push(canonical);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn includes_comments_type_links_module_index_and_stable_anchors() {
        let source = r#"
            /// 可相加之物。
            公 协 可加 则 法 相加（值：数）：数；终
            /// 加一并归还。
            公 法 加一（值：数）：数 则 归 值 加 1；终
            定 秘 为 1；
        "#;
        let output = markdown("算书", &crate::parse(source).unwrap());
        assert!(output.contains("## 模块索引"));
        assert!(output.contains("加一并归还"));
        assert!(output.contains("<a id=\"法-加一\"></a>"));
        assert!(output.contains("[`数`](#类型-数)"));
        assert!(!output.contains("`秘`"));
        assert_eq!(stable_anchor("法", "加一"), "法-加一");
    }

    #[test]
    fn links_binary_values_to_the_builtin_type_index() {
        let output = markdown(
            "二进制接口",
            &crate::parse("/// 原始响应。\n公 定 响应：字节串 为 空；").unwrap(),
        );
        assert!(output.contains("[`字节串`](#类型-字节串)"));
        assert!(output.contains("`字节串`：不可变的任意二进制数据"));
    }

    #[test]
    fn directory_generation_builds_a_module_index() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-doc-{unique}"));
        fs::create_dir_all(root.join("子")).unwrap();
        fs::write(root.join("甲.yx"), "公 定 值：数 为 1；").unwrap();
        fs::write(root.join("子/乙.yx"), "公 法 答（）：文 则 归「善」；终").unwrap();
        let output = markdown_directory(&root).unwrap();
        assert!(output.contains("[`甲`](#模块-甲)"));
        assert!(output.contains("[`子/乙`](#模块-子-乙)"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qualified_docs_link_exact_owners_and_reexported_modules() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-qualified-doc-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("base.yx"),
            "公 协 可描述 则 法 描述（）：文；终\n公 类 视图 纳 可描述 则 公 法 描述（）：文 则 归「视图」；终 终\n",
        )
        .unwrap();
        fs::write(
            root.join("controls.yx"),
            "引「base.yx」为 基础；\n公 类 按钮 承 基础.视图 纳 基础.可描述 则 公 域 所属：基础.视图；公 法 包装（项目：列<基础.视图?>）：基础.视图 则 归 此.所属；终 终\n",
        )
        .unwrap();
        fs::write(root.join("facade.yx"), "公 引「controls.yx」为 控件；\n").unwrap();
        fs::write(root.join("a.yx"), "公 类 节点 则 终\n").unwrap();
        fs::write(root.join("b.yx"), "公 类 节点 则 终\n").unwrap();
        fs::write(
            root.join("consumer.yx"),
            "引「a.yx」为 甲；引「b.yx」为 乙；公 法 选择（左：甲.节点，右：乙.节点）：甲.节点 则 归 左；终\n",
        )
        .unwrap();

        let output = markdown_directory(&root).unwrap();
        assert!(
            output.contains("[`基础.视图`](#模块-base-类-视图)"),
            "{output}"
        );
        assert!(output.contains("父类所有者：`文件:"), "{output}");
        assert!(output.contains("[`甲.节点`](#模块-a-类-节点)"), "{output}");
        assert!(output.contains("[`乙.节点`](#模块-b-类-节点)"), "{output}");
        assert!(output.contains("## 模块 `控件`"), "{output}");
        assert!(output.contains("原始模块：[`文件:"), "{output}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn module_api_v2_structures_type_ownership_and_exposed_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-api-v2-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let base_path = root.join("base.yx");
        let controls_path = root.join("controls.yx");
        let facade_path = root.join("facade.yx");
        fs::write(
            &base_path,
            "公 协 可描述 则 法 描述（）：文；终\n公 类 视图 纳 可描述 则 公 法 描述（）：文 则 归「视图」；终 终\n",
        )
        .unwrap();
        fs::write(
            &controls_path,
            "引「base.yx」为 基础；\n公 类 按钮 承 基础.视图 纳 基础.可描述 则 公 域 所属：基础.视图；公 法 包装（项目：列<基础.视图?>）：基础.视图 则 归 此.所属；终 终\n公 法 建立（）：基础.视图 则 归 按钮（）；终\n",
        )
        .unwrap();
        fs::write(&facade_path, "公 引「controls.yx」为 控件；\n").unwrap();

        let controls_source = fs::read_to_string(&controls_path).unwrap();
        let controls =
            crate::parse_named(&controls_source, controls_path.display().to_string()).unwrap();
        let manifest = api_manifest_in_directory("controls", &controls, &root).unwrap();
        assert_eq!(manifest["$schema"], MODULE_API_SCHEMA);
        assert_eq!(manifest["format_version"], MODULE_API_MANIFEST_VERSION);
        let class = manifest["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|declaration| declaration["name"] == "按钮")
            .unwrap();
        assert_eq!(class["declaration_kind"], "class");
        assert_eq!(class["type_id"]["kind"], "class");
        assert_eq!(
            class["superclass"]["source"]["segments"],
            json!(["基础", "视图"])
        );
        assert_eq!(class["superclass"]["target"]["name"], "视图");
        assert_eq!(class["protocols"][0]["target"]["name"], "可描述");
        assert_ne!(
            class["owner_module"],
            class["superclass"]["target"]["module"]
        );
        assert_eq!(class["fields"][0]["type"]["kind"], "named");
        assert!(
            class["methods"][0]["qualified_name"]
                .as_str()
                .unwrap()
                .ends_with(".按钮.包装")
        );
        assert_eq!(
            class["methods"][0]["exposed_path"],
            json!(["controls", "按钮", "包装"])
        );
        assert_eq!(
            class["methods"][0]["parameters"][0]["type"]["arguments"][0]["inner"]["link"]["target"]
                ["name"],
            "视图"
        );

        let facade_source = fs::read_to_string(&facade_path).unwrap();
        let facade = crate::parse_named(&facade_source, facade_path.display().to_string()).unwrap();
        let facade_manifest = api_manifest_in_directory("门面", &facade, &root).unwrap();
        let reexport = &facade_manifest["declarations"][0];
        assert_eq!(reexport["kind"], "module_reexport");
        assert_eq!(reexport["exposed_path"], json!(["门面", "控件"]));
        let exposed_button = reexport["exports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|declaration| declaration["name"] == "按钮")
            .unwrap();
        assert_eq!(
            exposed_button["exposed_path"],
            json!(["门面", "控件", "按钮"])
        );
        assert_eq!(exposed_button["type_id"], class["type_id"]);
        assert!(
            reexport["exports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|declaration| declaration["name"] == "建立"
                    && declaration["kind"] == "function")
        );

        let schema: Value =
            serde_json::from_str(include_str!("../schemas/module-api-v2.json")).unwrap();
        assert_eq!(schema["$id"], MODULE_API_SCHEMA);
        assert_eq!(schema["properties"]["format_version"]["const"], 2);
        assert!(schema["$defs"]["runtime_type"]["oneOf"].is_array());
        fs::remove_dir_all(root).unwrap();
    }
}

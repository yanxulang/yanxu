//! 0.4 静态类型检查器。
//!
//! 运行时仍保留类型防线，本模块在执行前发现显式注解、
//! 运算符和法调用中能够确定的冲突。无法确定的动态成员会降级为 `任意`。

use crate::ast::{
    Expr, ExprKind, Literal, Parameter, Stmt, StmtKind, TypeKind, TypePath, TypeRef, Visibility,
};
use crate::source::Span;
use crate::token::TokenKind;
use crate::type_model::{ModuleId, TypeDeclarationKind, TypeId};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.span.render("类型有误", &self.message))
    }
}

impl TypeError {
    #[doc(hidden)]
    pub fn code(&self) -> &'static str {
        match self.message.split_once(']').map(|(code, _)| code) {
            Some("[PACKAGE_MODULE_RESERVED_PATH") => {
                crate::package::PACKAGE_MODULE_RESERVED_PATH_CODE
            }
            Some("[PACKAGE_PATH_NON_PORTABLE") => crate::package::PACKAGE_PATH_NON_PORTABLE_CODE,
            Some("[PACKAGE_PATH_INVALID") => crate::package::PACKAGE_PATH_INVALID_CODE,
            Some("[PACKAGE_ROOT_INVALID") => crate::package::PACKAGE_ROOT_INVALID_CODE,
            Some("[PACKAGE_MODULE_OUTSIDE_ROOT") => {
                crate::package::PACKAGE_MODULE_OUTSIDE_ROOT_CODE
            }
            Some("[PACKAGE_PATH_RESERVED") => crate::package::PACKAGE_PATH_RESERVED_CODE,
            Some("[PACKAGE_PATH_COLLISION") => crate::package::PACKAGE_PATH_COLLISION_CODE,
            _ => "TYPE000",
        }
    }

    #[doc(hidden)]
    pub fn diagnostic_message(&self) -> &str {
        self.message
            .strip_prefix('[')
            .and_then(|message| message.split_once("] ").map(|(_, message)| message))
            .unwrap_or(&self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StaticType {
    Any,
    Named(NamedType),
    List(Box<TypeSet>),
    Tuple(Vec<TypeSet>),
    Map(Box<TypeSet>, Box<TypeSet>),
    Function(Vec<TypeSet>, Box<TypeSet>),
    Task(Box<TypeSet>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NamedType {
    Builtin(String),
    Declared(TypeId),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TypeSet {
    variants: Vec<StaticType>,
}

impl TypeSet {
    fn named(name: impl Into<String>) -> Self {
        let name = name.into();
        if name == "任意" {
            return Self::any();
        }
        Self {
            variants: vec![StaticType::Named(NamedType::Builtin(name))],
        }
    }

    fn declared(type_id: TypeId) -> Self {
        Self {
            variants: vec![StaticType::Named(NamedType::Declared(type_id))],
        }
    }

    fn any() -> Self {
        Self {
            variants: vec![StaticType::Any],
        }
    }

    fn single(ty: StaticType) -> Self {
        Self { variants: vec![ty] }
    }

    fn union(types: Vec<Self>) -> Self {
        let mut variants = types
            .into_iter()
            .flat_map(|ty| ty.variants)
            .collect::<Vec<_>>();
        if variants.iter().any(|ty| matches!(ty, StaticType::Any)) {
            return Self::any();
        }
        variants.sort();
        variants.dedup();
        if variants.is_empty() {
            Self::any()
        } else {
            Self { variants }
        }
    }

    fn accepts(&self, actual: &Self) -> bool {
        self.variants.iter().any(|ty| matches!(ty, StaticType::Any))
            || actual.variants.iter().all(|actual| {
                self.variants
                    .iter()
                    .any(|expected| accepts_one(expected, actual))
            })
    }

    fn contains(&self, name: &str) -> bool {
        self.variants.iter().any(|ty| match ty {
            StaticType::Any => true,
            StaticType::Named(NamedType::Builtin(actual)) => actual == name,
            StaticType::Named(NamedType::Declared(_)) => false,
            StaticType::List(_) => name == "列",
            StaticType::Tuple(_) => name == "元",
            StaticType::Map(_, _) => name == "典",
            StaticType::Function(_, _) => name == "法",
            StaticType::Task(_) => name == "任务",
        })
    }

    fn function(&self) -> Option<FunctionType> {
        self.variants.iter().find_map(|ty| match ty {
            StaticType::Function(params, result) => Some(FunctionType {
                params: params.clone(),
                result: result.as_ref().clone(),
            }),
            _ => None,
        })
    }

    fn iterable_element(&self) -> Option<Self> {
        let mut elements = Vec::new();
        for ty in &self.variants {
            match ty {
                StaticType::Any => elements.push(Self::any()),
                StaticType::List(element) => elements.push(element.as_ref().clone()),
                StaticType::Tuple(items) => elements.extend(items.iter().cloned()),
                StaticType::Map(key, _) => elements.push(key.as_ref().clone()),
                StaticType::Named(NamedType::Builtin(name)) if name == "文" => {
                    elements.push(Self::named("文"));
                }
                StaticType::Named(NamedType::Builtin(name))
                    if name == "列" || name == "元" || name == "典" =>
                {
                    elements.push(Self::any())
                }
                StaticType::Named(NamedType::Builtin(name))
                    if !matches!(
                        name.as_str(),
                        "数" | "理" | "空" | "法" | "类" | "模块" | "误"
                    ) =>
                {
                    elements.push(Self::any())
                }
                StaticType::Named(NamedType::Declared(_)) => elements.push(Self::any()),
                _ => {}
            }
        }
        (!elements.is_empty()).then(|| Self::union(elements))
    }

    fn without_named(&self, excluded: &str) -> Self {
        let variants = self
            .variants
            .iter()
            .filter(|ty| {
                !matches!(
                    ty,
                    StaticType::Named(NamedType::Builtin(name)) if name == excluded
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        if variants.is_empty() {
            Self::any()
        } else {
            Self { variants }
        }
    }

    fn without(&self, excluded: &Self) -> Self {
        let variants = self
            .variants
            .iter()
            .filter(|ty| !excluded.variants.contains(ty))
            .cloned()
            .collect::<Vec<_>>();
        if variants.is_empty() {
            Self::any()
        } else {
            Self { variants }
        }
    }
}

impl fmt::Display for TypeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.variants
                .iter()
                .map(static_type_name)
                .collect::<Vec<_>>()
                .join("|")
        )
    }
}

fn accepts_one(expected: &StaticType, actual: &StaticType) -> bool {
    match (expected, actual) {
        (StaticType::Any, _) | (_, StaticType::Any) => true,
        (StaticType::Named(expected), StaticType::Named(actual)) => expected == actual,
        (StaticType::Named(NamedType::Builtin(name)), StaticType::List(_))
        | (StaticType::List(_), StaticType::Named(NamedType::Builtin(name))) => name == "列",
        (StaticType::Named(NamedType::Builtin(name)), StaticType::Tuple(_))
        | (StaticType::Tuple(_), StaticType::Named(NamedType::Builtin(name))) => name == "元",
        (StaticType::Named(NamedType::Builtin(name)), StaticType::Map(_, _))
        | (StaticType::Map(_, _), StaticType::Named(NamedType::Builtin(name))) => name == "典",
        (StaticType::Named(NamedType::Builtin(name)), StaticType::Function(_, _))
        | (StaticType::Function(_, _), StaticType::Named(NamedType::Builtin(name))) => name == "法",
        (StaticType::Named(NamedType::Builtin(name)), StaticType::Task(_))
        | (StaticType::Task(_), StaticType::Named(NamedType::Builtin(name))) => name == "任务",
        (StaticType::List(expected), StaticType::List(actual)) => expected.accepts(actual),
        (
            StaticType::Map(expected_key, expected_value),
            StaticType::Map(actual_key, actual_value),
        ) => expected_key.accepts(actual_key) && expected_value.accepts(actual_value),
        (StaticType::Tuple(expected), StaticType::Tuple(actual)) => {
            expected.len() == actual.len()
                && expected
                    .iter()
                    .zip(actual)
                    .all(|(expected, actual)| expected.accepts(actual))
        }
        (
            StaticType::Function(expected_params, expected_result),
            StaticType::Function(actual_params, actual_result),
        ) => {
            expected_params.len() == actual_params.len()
                && expected_params
                    .iter()
                    .zip(actual_params)
                    .all(|(expected, actual)| expected.accepts(actual))
                && expected_result.accepts(actual_result)
        }
        (StaticType::Task(expected), StaticType::Task(actual)) => expected.accepts(actual),
        _ => false,
    }
}

fn static_type_name(ty: &StaticType) -> String {
    match ty {
        StaticType::Any => "任意".into(),
        StaticType::Named(NamedType::Builtin(name)) => name.clone(),
        StaticType::Named(NamedType::Declared(type_id)) => type_id.qualified_name(),
        StaticType::List(element) => format!("列<{element}>"),
        StaticType::Tuple(items) => format!(
            "元<{}>",
            items
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("，")
        ),
        StaticType::Map(key, value) => format!("典<{key}，{value}>"),
        StaticType::Function(params, result) => format!(
            "法（{}）：{result}",
            params
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("，")
        ),
        StaticType::Task(result) => format!("任务<{result}>"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionType {
    params: Vec<TypeSet>,
    result: TypeSet,
}

#[derive(Clone)]
struct Binding {
    ty: TypeSet,
    mutable: bool,
    function: Option<FunctionType>,
    class_id: Option<TypeId>,
    module: Option<ModuleSummary>,
}

#[derive(Clone)]
struct MemberType {
    ty: TypeSet,
    function: Option<FunctionType>,
    is_static: bool,
    readonly: bool,
    visibility: Visibility,
    owner: TypeId,
}

#[derive(Clone, Default)]
struct ObjectShape {
    fields: BTreeMap<String, MemberType>,
    methods: BTreeMap<String, MemberType>,
}

#[allow(dead_code)]
#[derive(Clone)]
enum ExportedSymbol {
    Value {
        binding: Binding,
        declaration: Span,
    },
    Class {
        type_id: TypeId,
        constructor: FunctionType,
        shape: ObjectShape,
        superclass: Option<TypeId>,
        protocols: Vec<TypeId>,
        declaration: Span,
    },
    Protocol {
        type_id: TypeId,
        shape: ObjectShape,
        declaration: Span,
    },
    Module {
        summary: Box<ModuleSummary>,
        declaration: Span,
    },
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct ModuleSummary {
    pub(crate) module_id: ModuleId,
    source_path: Option<PathBuf>,
    exports: BTreeMap<String, ExportedSymbol>,
}

#[derive(Clone)]
struct LocalType {
    type_id: TypeId,
    public: bool,
}

struct ModuleContext {
    module_id: ModuleId,
    local_types: BTreeMap<String, LocalType>,
    imports: BTreeMap<String, ModuleSummary>,
}

type Scope = HashMap<String, Binding>;

pub fn check(statements: &[Stmt]) -> Result<(), Vec<TypeError>> {
    let mut checker = Checker::new();
    checker.check_root_module(statements);
    checker.finish()
}

pub fn check_in_directory(
    statements: &[Stmt],
    directory: impl AsRef<Path>,
) -> Result<(), Vec<TypeError>> {
    let mut checker = Checker::new();
    let directory = directory.as_ref();
    checker.configure_directory(statements, directory);
    checker.check_root_module(statements);
    checker.finish()
}

pub fn check_in_directory_with_permissions(
    statements: &[Stmt],
    directory: impl AsRef<Path>,
    permissions: crate::permissions::PermissionSet,
) -> Result<(), Vec<TypeError>> {
    let mut checker = Checker::new();
    let directory = directory.as_ref();
    checker.configure_directory(statements, directory);
    checker.permissions = Some(permissions);
    checker.check_root_module(statements);
    checker.finish()
}

struct Checker {
    errors: Vec<TypeError>,
    protocols: HashMap<TypeId, ObjectShape>,
    classes: HashMap<TypeId, ObjectShape>,
    class_parents: HashMap<TypeId, TypeId>,
    class_protocols: HashMap<TypeId, BTreeSet<TypeId>>,
    current_class: Option<TypeId>,
    current_method_static: bool,
    current_dir: Option<PathBuf>,
    package_root: Option<PathBuf>,
    package_module_roots: crate::package::TrustedPackageRoots,
    module_cache: HashMap<PathBuf, ModuleSummary>,
    loading_modules: Vec<PathBuf>,
    module_contexts: Vec<ModuleContext>,
    permissions: Option<crate::permissions::PermissionSet>,
}

impl Checker {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            protocols: HashMap::new(),
            classes: HashMap::new(),
            class_parents: HashMap::new(),
            class_protocols: HashMap::new(),
            current_class: None,
            current_method_static: false,
            current_dir: None,
            package_root: None,
            package_module_roots: crate::package::TrustedPackageRoots::default(),
            module_cache: HashMap::new(),
            loading_modules: Vec::new(),
            module_contexts: Vec::new(),
            permissions: None,
        }
    }

    fn configure_directory(&mut self, statements: &[Stmt], directory: &Path) {
        self.current_dir =
            Some(fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf()));
        let span = statements
            .first()
            .map_or_else(Span::synthetic, |statement| statement.span.clone());
        let manifest = match crate::package::discover(directory) {
            Ok(manifest) => manifest,
            Err(error) => {
                self.coded_error(
                    error.code(),
                    format!("{}：{}", error.path.display(), error.diagnostic_message()),
                    span,
                );
                return;
            }
        };
        let Some(manifest) = manifest else {
            return;
        };
        let root = match fs::canonicalize(&manifest.root) {
            Ok(root) => root,
            Err(error) => {
                self.error(
                    format!("不能定位包根目录“{}”：{error}", manifest.root.display()),
                    span,
                );
                return;
            }
        };
        if let Err(error) = self.package_module_roots.insert(&root) {
            self.package_path_error(error, span);
            return;
        }
        if let Some(source) = statements
            .first()
            .and_then(|statement| existing_source_path(&statement.span.source.name))
            && let Err(error) = self.package_module_roots.authorize_module(&source, &source)
        {
            self.package_path_error(error, span);
            return;
        }
        self.package_root = Some(root);
    }

    fn finish(self) -> Result<(), Vec<TypeError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    fn check_root_module(&mut self, statements: &[Stmt]) {
        let source_name = statements
            .first()
            .map(|statement| statement.span.source.name.as_str())
            .unwrap_or("<空模块>");
        let source_path = existing_source_path(source_name);
        let module_id = source_path
            .as_deref()
            .map_or_else(|| ModuleId::for_source(source_name), ModuleId::for_path);
        if let Some(path) = &source_path {
            self.loading_modules.push(path.clone());
        }
        self.check_module(statements, module_id, source_path);
        if !self.loading_modules.is_empty() {
            self.loading_modules.pop();
        }
    }

    fn check_module(
        &mut self,
        statements: &[Stmt],
        module_id: ModuleId,
        source_path: Option<PathBuf>,
    ) -> ModuleSummary {
        let mut imports = BTreeMap::new();
        for statement in statements {
            if let StmtKind::Import { alias, path } = &statement.kind
                && let Some(summary) = self.load_module_summary(path, &statement.span)
            {
                imports.insert(alias.clone(), summary);
            }
        }
        let local_types = statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                StmtKind::Class { name, .. } => Some((
                    name.clone(),
                    LocalType {
                        type_id: TypeId::new(module_id.clone(), name, TypeDeclarationKind::Class),
                        public: statement.public,
                    },
                )),
                StmtKind::Protocol { name, .. } => Some((
                    name.clone(),
                    LocalType {
                        type_id: TypeId::new(
                            module_id.clone(),
                            name,
                            TypeDeclarationKind::Protocol,
                        ),
                        public: statement.public,
                    },
                )),
                _ => None,
            })
            .collect();
        self.module_contexts.push(ModuleContext {
            module_id: module_id.clone(),
            local_types,
            imports,
        });
        self.register_object_declarations(statements);
        let module_scope = self.check_scope(statements, Scope::new(), None);
        let summary = self.module_summary(statements, &module_scope, module_id, source_path);
        self.module_contexts.pop();
        summary
    }

    fn register_object_declarations(&mut self, statements: &[Stmt]) {
        for statement in statements {
            if let StmtKind::Protocol {
                name,
                fields,
                methods,
            } = &statement.kind
                && let Some(type_id) = self.local_type_id(name)
            {
                let shape = self.object_shape(&type_id, fields, methods);
                self.protocols.insert(type_id, shape);
            }
        }
        for statement in statements {
            if let StmtKind::Class {
                name,
                superclass,
                protocols,
                fields,
                methods,
            } = &statement.kind
                && let Some(type_id) = self.local_type_id(name)
            {
                let shape = self.object_shape(&type_id, fields, methods);
                self.classes.insert(type_id.clone(), shape);
                let protocol_ids = protocols
                    .iter()
                    .filter_map(|path| {
                        self.resolve_declared_type(path, Some(TypeDeclarationKind::Protocol))
                    })
                    .collect();
                self.class_protocols.insert(type_id.clone(), protocol_ids);
                if let Some(superclass) = superclass
                    && let Some(parent) =
                        self.resolve_declared_type(superclass, Some(TypeDeclarationKind::Class))
                {
                    self.class_parents.insert(type_id, parent);
                }
            }
        }
    }

    fn local_type_id(&self, name: &str) -> Option<TypeId> {
        self.module_contexts
            .last()?
            .local_types
            .get(name)
            .map(|local| local.type_id.clone())
    }

    fn type_set_from_ref(&mut self, type_ref: &TypeRef) -> TypeSet {
        self.type_set_from_kind(&type_ref.kind)
    }

    fn type_set_from_kind(&mut self, kind: &TypeKind) -> TypeSet {
        match kind {
            TypeKind::Named(path) => {
                if let Some(name) = path.single_name()
                    && is_builtin_type(name)
                {
                    TypeSet::named(name)
                } else {
                    self.resolve_declared_type(path, None)
                        .map_or_else(TypeSet::any, TypeSet::declared)
                }
            }
            TypeKind::Union(types) => {
                TypeSet::union(types.iter().map(|ty| self.type_set_from_kind(ty)).collect())
            }
            TypeKind::Nullable(ty) => {
                TypeSet::union(vec![self.type_set_from_kind(ty), TypeSet::named("空")])
            }
            TypeKind::Generic { base, arguments }
                if base.is_single("列") && arguments.len() == 1 =>
            {
                let element = self.type_set_from_kind(&arguments[0]);
                TypeSet::single(StaticType::List(Box::new(element)))
            }
            TypeKind::Generic { base, arguments }
                if base.is_single("典") && arguments.len() == 2 =>
            {
                let key = self.type_set_from_kind(&arguments[0]);
                let value = self.type_set_from_kind(&arguments[1]);
                TypeSet::single(StaticType::Map(Box::new(key), Box::new(value)))
            }
            TypeKind::Generic { base, arguments }
                if base.is_single("任务") && arguments.len() == 1 =>
            {
                let result = self.type_set_from_kind(&arguments[0]);
                TypeSet::single(StaticType::Task(Box::new(result)))
            }
            TypeKind::Generic { base, arguments } if base.is_single("元") => {
                let items = arguments
                    .iter()
                    .map(|argument| self.type_set_from_kind(argument))
                    .collect();
                TypeSet::single(StaticType::Tuple(items))
            }
            TypeKind::Generic { base, arguments } => {
                for argument in arguments {
                    self.type_set_from_kind(argument);
                }
                self.resolve_declared_type(base, None)
                    .map_or_else(TypeSet::any, TypeSet::declared)
            }
            TypeKind::Function { parameters, result } => {
                let parameters = parameters
                    .iter()
                    .map(|parameter| self.type_set_from_kind(parameter))
                    .collect();
                let result = self.type_set_from_kind(result);
                TypeSet::single(StaticType::Function(parameters, Box::new(result)))
            }
        }
    }

    fn parameter_type(&mut self, parameter: &Parameter) -> TypeSet {
        parameter
            .type_ref
            .as_ref()
            .map_or_else(TypeSet::any, |ty| self.type_set_from_ref(ty))
    }

    fn resolve_declared_type(
        &mut self,
        path: &TypePath,
        expected: Option<TypeDeclarationKind>,
    ) -> Option<TypeId> {
        if let Some(name) = path.single_name() {
            let local = self
                .module_contexts
                .last()
                .and_then(|context| context.local_types.get(name))
                .cloned();
            if let Some(local) = local {
                return self.require_declaration_kind(local.type_id, expected, &path.span);
            }
            let imported_owner = self.module_contexts.last().and_then(|context| {
                context.imports.iter().find_map(|(alias, summary)| {
                    matches!(
                        summary.exports.get(name),
                        Some(ExportedSymbol::Class { .. } | ExportedSymbol::Protocol { .. })
                    )
                    .then_some(alias.clone())
                })
            });
            if let Some(alias) = imported_owner {
                self.error(
                    format!("导入类型“{name}”不可裸写；请使用“{alias}.{name}”"),
                    path.span.clone(),
                );
            } else {
                self.error(format!("本模块未声明类型“{name}”"), path.span.clone());
            }
            return None;
        }

        let first = &path.segments[0];
        let mut summary = self
            .module_contexts
            .last()
            .and_then(|context| context.imports.get(&first.name))
            .cloned();
        let Some(mut summary) = summary.take() else {
            self.error(
                format!("类型路径“{path}”的模块别名“{}”不存在", first.name),
                first.span.clone(),
            );
            return None;
        };
        for (index, segment) in path.segments.iter().enumerate().skip(1) {
            let Some(symbol) = summary.exports.get(&segment.name).cloned() else {
                self.error(
                    format!(
                        "模块“{}”未公开成员“{}”（类型路径“{path}”）",
                        summary.module_id, segment.name
                    ),
                    segment.span.clone(),
                );
                return None;
            };
            let last = index + 1 == path.segments.len();
            if !last {
                match symbol {
                    ExportedSymbol::Module {
                        summary: nested, ..
                    } => summary = *nested,
                    _ => {
                        self.error(
                            format!("类型路径“{path}”的中间段“{}”不是模块", segment.name),
                            segment.span.clone(),
                        );
                        return None;
                    }
                }
                continue;
            }
            let type_id = match symbol {
                ExportedSymbol::Class { type_id, .. }
                | ExportedSymbol::Protocol { type_id, .. } => type_id,
                ExportedSymbol::Module { .. } => {
                    self.error(
                        format!("类型路径“{path}”最终指向模块而非类或协"),
                        segment.span.clone(),
                    );
                    return None;
                }
                ExportedSymbol::Value { .. } => {
                    self.error(
                        format!("模块成员“{}”不是类或协", segment.name),
                        segment.span.clone(),
                    );
                    return None;
                }
            };
            return self.require_declaration_kind(type_id, expected, &segment.span);
        }
        None
    }

    fn require_declaration_kind(
        &mut self,
        type_id: TypeId,
        expected: Option<TypeDeclarationKind>,
        span: &Span,
    ) -> Option<TypeId> {
        if let Some(expected) = expected
            && type_id.kind != expected
        {
            self.error(
                format!(
                    "“{}”声明为{}，不可用作{}",
                    type_id.qualified_name(),
                    type_id.kind,
                    expected
                ),
                span.clone(),
            );
            None
        } else {
            Some(type_id)
        }
    }

    fn object_shape(
        &mut self,
        owner: &TypeId,
        fields: &[crate::ast::FieldDecl],
        methods: &[Stmt],
    ) -> ObjectShape {
        let mut shape = ObjectShape::default();
        for field in fields {
            let ty = self.type_set_from_ref(&field.type_ref);
            shape.fields.insert(
                field.name.clone(),
                MemberType {
                    ty,
                    function: None,
                    is_static: field.is_static,
                    readonly: field.readonly,
                    visibility: field.visibility,
                    owner: owner.clone(),
                },
            );
        }
        for method in methods {
            let StmtKind::Function {
                name,
                params,
                return_type,
                is_async,
                ..
            } = &method.kind
            else {
                continue;
            };
            let mut result = return_type
                .as_ref()
                .map_or_else(TypeSet::any, |ty| self.type_set_from_ref(ty));
            if *is_async {
                result = TypeSet::single(StaticType::Task(Box::new(result)));
            }
            let function = FunctionType {
                params: params
                    .iter()
                    .map(|parameter| self.parameter_type(parameter))
                    .collect(),
                result,
            };
            shape.methods.insert(
                name.clone(),
                MemberType {
                    ty: TypeSet::named("法"),
                    function: Some(function),
                    is_static: method.is_static,
                    readonly: true,
                    visibility: method.member_visibility,
                    owner: owner.clone(),
                },
            );
        }
        shape
    }

    fn module_summary(
        &mut self,
        statements: &[Stmt],
        scope: &Scope,
        module_id: ModuleId,
        source_path: Option<PathBuf>,
    ) -> ModuleSummary {
        let mut exports = BTreeMap::new();
        for statement in statements.iter().filter(|statement| statement.public) {
            match &statement.kind {
                StmtKind::Let { name, .. } | StmtKind::Function { name, .. } => {
                    if let Some(binding) = scope.get(name).cloned() {
                        self.validate_public_binding(name, &binding, &statement.span);
                        exports.insert(
                            name.clone(),
                            ExportedSymbol::Value {
                                binding,
                                declaration: statement.span.clone(),
                            },
                        );
                    }
                }
                StmtKind::Class { name, .. } => {
                    let Some(type_id) = self.local_type_id(name) else {
                        continue;
                    };
                    let Some(class_binding) = scope.get(name) else {
                        continue;
                    };
                    let constructor = class_binding.function.clone().unwrap_or(FunctionType {
                        params: Vec::new(),
                        result: TypeSet::declared(type_id.clone()),
                    });
                    let shape = self.classes.get(&type_id).cloned().unwrap_or_default();
                    let superclass = self.class_parents.get(&type_id).cloned();
                    let mut protocols = self
                        .class_protocols
                        .get(&type_id)
                        .map(|items| items.iter().cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    protocols.sort();
                    for (member_name, member) in shape
                        .fields
                        .iter()
                        .chain(&shape.methods)
                        .filter(|(_, member)| member.visibility == Visibility::Public)
                    {
                        self.validate_public_binding(
                            &format!("{name}.{member_name}"),
                            &Binding {
                                ty: member.ty.clone(),
                                mutable: false,
                                function: member.function.clone(),
                                class_id: None,
                                module: None,
                            },
                            &statement.span,
                        );
                    }
                    for exposed_type in superclass.iter().chain(&protocols) {
                        self.validate_public_binding(
                            name,
                            &binding(TypeSet::declared(exposed_type.clone()), false),
                            &statement.span,
                        );
                    }
                    exports.insert(
                        name.clone(),
                        ExportedSymbol::Class {
                            type_id,
                            constructor,
                            shape,
                            superclass,
                            protocols,
                            declaration: statement.span.clone(),
                        },
                    );
                }
                StmtKind::Protocol { name, .. } => {
                    let Some(type_id) = self.local_type_id(name) else {
                        continue;
                    };
                    let shape = self.protocols.get(&type_id).cloned().unwrap_or_default();
                    for (member_name, member) in shape.fields.iter().chain(&shape.methods) {
                        self.validate_public_binding(
                            &format!("{name}.{member_name}"),
                            &Binding {
                                ty: member.ty.clone(),
                                mutable: false,
                                function: member.function.clone(),
                                class_id: None,
                                module: None,
                            },
                            &statement.span,
                        );
                    }
                    exports.insert(
                        name.clone(),
                        ExportedSymbol::Protocol {
                            type_id,
                            shape,
                            declaration: statement.span.clone(),
                        },
                    );
                }
                StmtKind::Import { alias, .. } => {
                    if let Some(summary) = self
                        .module_contexts
                        .last()
                        .and_then(|context| context.imports.get(alias))
                        .cloned()
                    {
                        exports.insert(
                            alias.clone(),
                            ExportedSymbol::Module {
                                summary: Box::new(summary),
                                declaration: statement.span.clone(),
                            },
                        );
                    }
                }
                _ => {}
            }
        }
        ModuleSummary {
            module_id,
            source_path,
            exports,
        }
    }

    fn validate_public_binding(&mut self, name: &str, binding: &Binding, span: &Span) {
        let mut referenced = Vec::new();
        collect_declared_types(&binding.ty, &mut referenced);
        if let Some(function) = &binding.function {
            for parameter in &function.params {
                collect_declared_types(parameter, &mut referenced);
            }
            collect_declared_types(&function.result, &mut referenced);
        }
        for type_id in referenced {
            let private_local = self
                .module_contexts
                .last()
                .filter(|context| context.module_id == type_id.module)
                .and_then(|context| context.local_types.get(&type_id.name))
                .is_some_and(|local| !local.public);
            if private_local {
                self.error(
                    format!(
                        "公开声明“{name}”泄漏不可访问的私有类型“{}”",
                        type_id.qualified_name()
                    ),
                    span.clone(),
                );
            }
        }
    }

    fn check_scope(
        &mut self,
        statements: &[Stmt],
        mut scope: Scope,
        expected_return: Option<&TypeSet>,
    ) -> Scope {
        self.predeclare(statements, &mut scope);
        for statement in statements {
            self.statement(statement, &mut scope, expected_return);
        }
        scope
    }

    fn predeclare(&mut self, statements: &[Stmt], scope: &mut Scope) {
        for statement in statements {
            if let StmtKind::Protocol { name, .. } = &statement.kind {
                scope.insert(
                    name.clone(),
                    Binding {
                        ty: TypeSet::named("协"),
                        mutable: false,
                        function: None,
                        class_id: None,
                        module: None,
                    },
                );
            }
        }
        for statement in statements {
            match &statement.kind {
                StmtKind::Function {
                    name,
                    params,
                    return_type,
                    is_async,
                    ..
                } => {
                    let result = return_type
                        .as_ref()
                        .map_or_else(TypeSet::any, |ty| self.type_set_from_ref(ty));
                    let function = FunctionType {
                        params: params
                            .iter()
                            .map(|parameter| self.parameter_type(parameter))
                            .collect(),
                        result: if *is_async {
                            TypeSet::single(StaticType::Task(Box::new(result)))
                        } else {
                            result
                        },
                    };
                    scope.insert(
                        name.clone(),
                        Binding {
                            ty: TypeSet::named("法"),
                            mutable: false,
                            function: Some(function),
                            class_id: None,
                            module: None,
                        },
                    );
                }
                StmtKind::Class { name, methods, .. } => {
                    let Some(type_id) = self.local_type_id(name) else {
                        continue;
                    };
                    let initializer = methods.iter().find_map(|method| match &method.kind {
                        StmtKind::Function { name, params, .. } if name == "初始化" => Some(
                            params
                                .iter()
                                .map(|parameter| self.parameter_type(parameter))
                                .collect(),
                        ),
                        _ => None,
                    });
                    scope.insert(
                        name.clone(),
                        Binding {
                            ty: TypeSet::named("类"),
                            mutable: false,
                            function: Some(FunctionType {
                                params: initializer.unwrap_or_default(),
                                result: TypeSet::declared(type_id.clone()),
                            }),
                            class_id: Some(type_id),
                            module: None,
                        },
                    );
                }
                StmtKind::Import { alias, .. } => {
                    let module = self
                        .module_contexts
                        .last()
                        .and_then(|context| context.imports.get(alias))
                        .cloned();
                    let mut imported = binding(TypeSet::named("模块"), false);
                    imported.module = module;
                    scope.insert(alias.clone(), imported);
                }
                StmtKind::Protocol { .. } => {}
                _ => {}
            }
        }
    }

    fn statement(
        &mut self,
        statement: &Stmt,
        scope: &mut Scope,
        expected_return: Option<&TypeSet>,
    ) {
        match &statement.kind {
            StmtKind::Let {
                name,
                type_ref,
                value,
                mutable,
            } => {
                let actual = self.expression(value, scope);
                let declared = type_ref.as_ref().map(|ty| self.type_set_from_ref(ty));
                if let Some(expected) = &declared {
                    self.require(expected, &actual, &value.span, format!("变量“{name}”"));
                }
                scope.insert(name.clone(), binding(declared.unwrap_or(actual), *mutable));
            }
            StmtKind::Set { target, value } => {
                let actual = self.expression(value, scope);
                if let ExprKind::Variable(name) = &target.kind {
                    match scope.get(name) {
                        Some(item) if !item.mutable => {
                            self.error(format!("“{name}”乃定值，不可改写"), target.span.clone())
                        }
                        Some(item) => {
                            self.require(&item.ty, &actual, &value.span, format!("变量“{name}”"))
                        }
                        None => {
                            self.error(format!("不可改写未定义之名“{name}”"), target.span.clone())
                        }
                    }
                } else {
                    if let ExprKind::Get { object, name } = &target.kind
                        && let Some(member) = self.direct_member(object, name, scope)
                        && member.readonly
                        && self.current_class.as_ref() != Some(&member.owner)
                    {
                        self.error(format!("只读成员“{name}”不可改写"), target.span.clone());
                    }
                    let expected = self.expression(target, scope);
                    self.require(&expected, &actual, &value.span, "成员".into());
                }
            }
            StmtKind::Print(expr) | StmtKind::Expression(expr) | StmtKind::Throw(expr) => {
                self.expression(expr, scope);
            }
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition, scope);
                let mut then_scope = scope.clone();
                let mut else_scope = scope.clone();
                self.narrow_condition(condition, &mut then_scope, true);
                self.narrow_condition(condition, &mut else_scope, false);
                self.check_scope(then_branch, then_scope, expected_return);
                self.check_scope(else_branch, else_scope, expected_return);
            }
            StmtKind::While { condition, body } => {
                self.expression(condition, scope);
                self.check_scope(body, scope.clone(), expected_return);
            }
            StmtKind::For {
                name,
                type_ref,
                iterable,
                body,
            } => {
                let iterable_type = self.expression(iterable, scope);
                let inferred = iterable_type.iterable_element();
                if inferred.is_none() {
                    self.error(format!("{}不可遍历", iterable_type), iterable.span.clone());
                }
                let inferred = inferred.unwrap_or_else(TypeSet::any);
                let declared = type_ref.as_ref().map(|ty| self.type_set_from_ref(ty));
                if let Some(expected) = &declared {
                    self.require(expected, &inferred, &iterable.span, format!("逐值“{name}”"));
                }
                let mut child = scope.clone();
                child.insert(name.clone(), binding(declared.unwrap_or(inferred), false));
                self.check_scope(body, child, expected_return);
            }
            StmtKind::Function {
                name,
                params,
                return_type,
                body,
                is_async,
                ..
            } => {
                if name == "初始化" && *is_async {
                    self.error("初始化不可为异法", statement.span.clone());
                }
                let mut child = scope.clone();
                for parameter in params {
                    child.insert(
                        parameter.name.clone(),
                        binding(self.parameter_type(parameter), true),
                    );
                }
                let result = return_type.as_ref().map(|ty| self.type_set_from_ref(ty));
                self.check_scope(body, child, result.as_ref());
            }
            StmtKind::Class {
                name,
                fields,
                methods,
                ..
            } => {
                for field in fields {
                    if let Some(initial) = &field.initial {
                        let actual = self.expression(initial, scope);
                        let expected = self.type_set_from_ref(&field.type_ref);
                        self.require(
                            &expected,
                            &actual,
                            &initial.span,
                            format!("域“{}”", field.name),
                        );
                    }
                }
                let Some(class_id) = self.local_type_id(name) else {
                    return;
                };
                let previous_class = self.current_class.replace(class_id.clone());
                for method in methods {
                    let mut child = scope.clone();
                    if !method.is_static {
                        child.insert(
                            "此".into(),
                            binding(TypeSet::declared(class_id.clone()), false),
                        );
                    }
                    let previous_static =
                        std::mem::replace(&mut self.current_method_static, method.is_static);
                    self.statement(method, &mut child, None);
                    self.current_method_static = previous_static;
                }
                self.current_class = previous_class;
                if let Some(superclass) = self.class_parents.get(&class_id).cloned() {
                    self.verify_overrides(&class_id, &superclass, &statement.span);
                }
                let protocol_ids = self
                    .class_protocols
                    .get(&class_id)
                    .map(|items| items.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.verify_protocols(&class_id, &protocol_ids, &statement.span);
            }
            StmtKind::Protocol { .. } => {}
            StmtKind::Import { .. } => {}
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                self.check_scope(try_branch, scope.clone(), expected_return);
                let mut child = scope.clone();
                child.insert(error_name.clone(), binding(TypeSet::named("误"), false));
                self.check_scope(catch_branch, child, expected_return);
            }
            StmtKind::Return(value) => {
                let actual = value
                    .as_ref()
                    .map_or_else(|| TypeSet::named("空"), |expr| self.expression(expr, scope));
                if let Some(expected) = expected_return {
                    self.require(expected, &actual, &statement.span, "归值".into());
                }
            }
        }
    }

    fn expression(&mut self, expression: &Expr, scope: &Scope) -> TypeSet {
        match &expression.kind {
            ExprKind::Literal(literal) => TypeSet::named(match literal {
                Literal::Number(_) => "数",
                Literal::String(_) => "文",
                Literal::Bool(_) => "理",
                Literal::Nil => "空",
            }),
            ExprKind::Variable(name) => scope
                .get(name)
                .cloned()
                .or_else(|| builtin(name))
                .map_or_else(
                    || {
                        self.error(format!("未曾定义“{name}”"), expression.span.clone());
                        TypeSet::any()
                    },
                    |item| item.ty.clone(),
                ),
            ExprKind::This => scope
                .get("此")
                .map_or_else(TypeSet::any, |item| item.ty.clone()),
            ExprKind::Super { method } => {
                if self.current_method_static {
                    self.error("静法不可使用“父”", expression.span.clone());
                    return TypeSet::any();
                }
                let Some(class_name) = self.current_class.clone() else {
                    self.error("“父”只可用于类之法内", expression.span.clone());
                    return TypeSet::any();
                };
                let Some(parent) = self.class_parents.get(&class_name) else {
                    self.error("无父类之类不可使用“父”", expression.span.clone());
                    return TypeSet::any();
                };
                let Some(member) = self.member(parent, method).cloned() else {
                    self.error(
                        format!("父类“{parent}”无方法“{method}”"),
                        expression.span.clone(),
                    );
                    return TypeSet::any();
                };
                if member.function.is_none() || member.is_static {
                    self.error(
                        format!("父类成员“{method}”不是实例法"),
                        expression.span.clone(),
                    );
                }
                if member.visibility == Visibility::Private && member.owner != class_name {
                    self.error(
                        format!("父类私法“{method}”不可由子类调用"),
                        expression.span.clone(),
                    );
                }
                member_type(&member)
            }
            ExprKind::List(items) => TypeSet::single(StaticType::List(Box::new(TypeSet::union(
                items
                    .iter()
                    .map(|item| self.expression(item, scope))
                    .collect(),
            )))),
            ExprKind::Tuple(items) => TypeSet::single(StaticType::Tuple(
                items
                    .iter()
                    .map(|item| self.expression(item, scope))
                    .collect(),
            )),
            ExprKind::Map(entries) => {
                let (keys, values): (Vec<_>, Vec<_>) = entries
                    .iter()
                    .map(|(key, value)| {
                        (self.expression(key, scope), self.expression(value, scope))
                    })
                    .unzip();
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::union(keys)),
                    Box::new(TypeSet::union(values)),
                ))
            }
            ExprKind::Unary { operator, right } => {
                let right_type = self.expression(right, scope);
                if matches!(operator, TokenKind::Minus) {
                    self.require(
                        &TypeSet::named("数"),
                        &right_type,
                        &right.span,
                        "求负".into(),
                    );
                    TypeSet::named("数")
                } else {
                    TypeSet::named("理")
                }
            }
            ExprKind::Binary {
                left,
                operator,
                right,
            } => {
                let left_type = self.expression(left, scope);
                let right_type = self.expression(right, scope);
                match operator {
                    TokenKind::Plus => {
                        let valid = (left_type.contains("数") && right_type.contains("数"))
                            || (left_type.contains("文") && right_type.contains("文"));
                        if !valid {
                            self.error(
                                format!("不可以{} 与 {} 相加", left_type, right_type),
                                expression.span.clone(),
                            );
                            TypeSet::any()
                        } else {
                            left_type
                        }
                    }
                    TokenKind::Minus | TokenKind::Star | TokenKind::Slash => {
                        let number = TypeSet::named("数");
                        self.require(&number, &left_type, &left.span, "算术左值".into());
                        self.require(&number, &right_type, &right.span, "算术右值".into());
                        number
                    }
                    TokenKind::And | TokenKind::Or => TypeSet::union(vec![left_type, right_type]),
                    _ => TypeSet::named("理"),
                }
            }
            ExprKind::TypeTest { value, type_ref } => {
                self.expression(value, scope);
                self.type_set_from_ref(type_ref);
                TypeSet::named("理")
            }
            ExprKind::Call { callee, arguments } => {
                let callee_type = self.expression(callee, scope);
                let builtin_name = if let ExprKind::Variable(name) = &callee.kind {
                    Some(name.as_str())
                } else {
                    None
                };
                let function = if let Some(name) = builtin_name {
                    scope
                        .get(name)
                        .cloned()
                        .or_else(|| builtin(name))
                        .and_then(|item| item.function)
                } else {
                    callee_type.function()
                };
                if let Some(function) = function {
                    if function.params.len() != arguments.len() {
                        self.error(
                            format!(
                                "调用须给 {} 个参数，实给 {} 个",
                                function.params.len(),
                                arguments.len()
                            ),
                            expression.span.clone(),
                        );
                    }
                    let mut actuals = Vec::with_capacity(arguments.len());
                    for (expected, argument) in function.params.iter().zip(arguments) {
                        let actual = self.expression(argument, scope);
                        self.require(expected, &actual, &argument.span, "参数".into());
                        actuals.push(actual);
                    }
                    for argument in arguments.iter().skip(function.params.len()) {
                        actuals.push(self.expression(argument, scope));
                    }
                    if builtin_name == Some("折叠") {
                        actuals
                            .get(1)
                            .cloned()
                            .unwrap_or_else(|| function.result.clone())
                    } else {
                        function.result
                    }
                } else {
                    for argument in arguments {
                        self.expression(argument, scope);
                    }
                    TypeSet::any()
                }
            }
            ExprKind::Await { task } => {
                let task_type = self.expression(task, scope);
                let results = task_type
                    .variants
                    .iter()
                    .filter_map(|variant| match variant {
                        StaticType::Task(result) => Some(result.as_ref().clone()),
                        StaticType::Any => Some(TypeSet::any()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if results.is_empty() {
                    self.error(format!("“候”须收任务，实为 {task_type}"), task.span.clone());
                    TypeSet::any()
                } else {
                    TypeSet::union(results)
                }
            }
            ExprKind::Get { object, name } => {
                if let Some(module) = Self::module_summary_for_expr(object, scope) {
                    self.expression(object, scope);
                    if let Some(symbol) = module.exports.get(name) {
                        return exported_symbol_type(symbol);
                    }
                    self.error(
                        format!("模块“{}”未公开“{name}”", module.module_id),
                        expression.span.clone(),
                    );
                    return TypeSet::any();
                }
                let object_type = self.expression(object, scope);
                let static_class = self.class_id_for_expr(object, scope);
                let mut results = Vec::new();
                let class_ids = if let Some(class_id) = &static_class {
                    vec![class_id.clone()]
                } else {
                    object_type
                        .variants
                        .iter()
                        .filter_map(|ty| match ty {
                            StaticType::Named(NamedType::Declared(type_id)) => {
                                Some(type_id.clone())
                            }
                            _ => None,
                        })
                        .collect()
                };
                for class_id in class_ids {
                    if let Some(member) = self.member(&class_id, name).cloned() {
                        let wants_static = static_class.is_some();
                        if member.is_static != wants_static {
                            self.error(
                                format!(
                                    "成员“{name}”{}静成员",
                                    if wants_static { "不是" } else { "乃" }
                                ),
                                expression.span.clone(),
                            );
                        }
                        if member.visibility == Visibility::Private
                            && self.current_class.as_ref() != Some(&member.owner)
                        {
                            self.error(
                                format!("私成员“{name}”不可从类外访问"),
                                expression.span.clone(),
                            );
                        }
                        results.push(member_type(&member));
                    }
                }
                if results.is_empty() {
                    TypeSet::any()
                } else {
                    TypeSet::union(results)
                }
            }
            ExprKind::Index { object, index } => {
                let object_type = self.expression(object, scope);
                self.expression(index, scope);
                let mut results = Vec::new();
                for ty in &object_type.variants {
                    match ty {
                        StaticType::List(element) => results.push(element.as_ref().clone()),
                        StaticType::Tuple(items) => {
                            if let ExprKind::Literal(Literal::Number(number)) = &index.kind
                                && *number >= 0.0
                                && number.fract() == 0.0
                            {
                                if let Some(item) = items.get(*number as usize) {
                                    results.push(item.clone());
                                }
                            } else {
                                results.extend(items.iter().cloned());
                            }
                        }
                        StaticType::Map(_, value) => results.push(value.as_ref().clone()),
                        StaticType::Named(NamedType::Builtin(name)) if name == "文" => {
                            results.push(TypeSet::named("文"));
                        }
                        _ => results.push(TypeSet::any()),
                    }
                }
                TypeSet::union(results)
            }
            ExprKind::Slice { object, start, end } => {
                let ty = self.expression(object, scope);
                if let Some(start) = start {
                    self.expression(start, scope);
                }
                if let Some(end) = end {
                    self.expression(end, scope);
                }
                ty
            }
        }
    }

    fn module_summary_for_expr(expression: &Expr, scope: &Scope) -> Option<ModuleSummary> {
        match &expression.kind {
            ExprKind::Variable(name) => scope.get(name)?.module.clone(),
            ExprKind::Get { object, name } => {
                let module = Self::module_summary_for_expr(object, scope)?;
                match module.exports.get(name)? {
                    ExportedSymbol::Module { summary, .. } => Some(summary.as_ref().clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn class_id_for_expr(&self, expression: &Expr, scope: &Scope) -> Option<TypeId> {
        match &expression.kind {
            ExprKind::Variable(name) => scope.get(name)?.class_id.clone(),
            ExprKind::Get { object, name } => {
                let module = Self::module_summary_for_expr(object, scope)?;
                match module.exports.get(name)? {
                    ExportedSymbol::Class { type_id, .. } => Some(type_id.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn load_module_summary(
        &mut self,
        requested: &str,
        import_span: &Span,
    ) -> Option<ModuleSummary> {
        if let Err(error) = crate::package::validate_portable_path_text(requested) {
            self.package_path_error(error, import_span.clone());
            return None;
        }
        if let Some(name) = requested.strip_prefix("标准:") {
            return standard_module_shape(name)
                .map(|shape| standard_summary(name, shape, import_span))
                .or_else(|| {
                    self.error(format!("未有标准模块“{name}”"), import_span.clone());
                    None
                });
        }
        let current_dir = self.current_dir.clone()?;
        let (joined, package_import) = if let Some(name) = requested.strip_prefix("包:") {
            match crate::package::resolve_dependency_scoped_with_capabilities(
                self.package_root.as_deref(),
                &current_dir,
                name,
            ) {
                Ok((dependency, capabilities)) => {
                    if let Err(error) = capabilities.extend(&mut self.package_module_roots) {
                        self.package_path_error(error, import_span.clone());
                        return None;
                    }
                    (dependency.entry, true)
                }
                Err(error) => {
                    self.coded_error(
                        error.code(),
                        format!("{}：{}", error.path.display(), error.diagnostic_message()),
                        import_span.clone(),
                    );
                    return None;
                }
            }
        } else {
            let requested = Path::new(requested);
            if requested.is_absolute() {
                (requested.to_path_buf(), false)
            } else {
                (current_dir.join(requested), false)
            }
        };
        if !package_import
            && self.package_module_roots.matching_root(&joined).is_none()
            && let Some(permissions) = &self.permissions
            && let Err(error) = permissions.check_file(&joined)
        {
            self.error(error.to_string(), import_span.clone());
            return None;
        }
        let (resolved, authority) = match self.package_module_roots.resolve_import_file(
            &current_dir,
            &joined,
            package_import,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.coded_error(
                    error.code(),
                    format!("{}：{}", error.path.display(), error.diagnostic_message()),
                    import_span.clone(),
                );
                return None;
            }
        };
        let canonical = resolved.path().to_path_buf();
        if let Some(permissions) = &self.permissions
            && let Err(error) = permissions.check_file(&canonical)
            && !authority.is_verified()
        {
            self.error(error.to_string(), import_span.clone());
            return None;
        }
        if let Some(summary) = self.module_cache.get(&canonical) {
            return Some(summary.clone());
        }
        if let Some(cycle_start) = self
            .loading_modules
            .iter()
            .position(|loading| loading == &canonical)
        {
            let mut chain = self.loading_modules[cycle_start..]
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            chain.push(canonical.display().to_string());
            self.error(
                format!("模块类型检查循环相引：{}", chain.join(" → ")),
                import_span.clone(),
            );
            return None;
        }
        let resolved = match resolved.open() {
            Ok(resolved) => resolved,
            Err(error) => {
                self.coded_error(
                    error.code(),
                    format!("{}：{}", error.path.display(), error.diagnostic_message()),
                    import_span.clone(),
                );
                return None;
            }
        };
        let source = match crate::package::read_resolved_module_source_snapshot(resolved) {
            Ok(source) => source,
            Err(error) => {
                self.error(
                    format!("不能读取模块“{}”：{error}", canonical.display()),
                    import_span.clone(),
                );
                return None;
            }
        };
        let tokens = match crate::lexer::scan_named(&source, canonical.display().to_string()) {
            Ok(tokens) => tokens,
            Err(error) => {
                self.error(error.message, error.span);
                return None;
            }
        };
        let statements = match crate::parser::parse(tokens) {
            Ok(statements) => statements,
            Err(error) => {
                self.error(error.message, error.span);
                return None;
            }
        };
        if let Err(error) = crate::resolver::resolve(&statements) {
            self.error(error.message, error.span);
            return None;
        }

        self.loading_modules.push(canonical.clone());
        let previous_dir = self.current_dir.replace(
            canonical
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        );
        let summary = self.check_module(
            &statements,
            ModuleId::for_path(&canonical),
            Some(canonical.clone()),
        );
        self.current_dir = previous_dir;
        self.loading_modules.pop();
        self.module_cache.insert(canonical, summary.clone());
        Some(summary)
    }

    fn member(&self, type_id: &TypeId, member_name: &str) -> Option<&MemberType> {
        if let Some(shape) = self.classes.get(type_id)
            && let Some(member) = shape
                .fields
                .get(member_name)
                .or_else(|| shape.methods.get(member_name))
        {
            return Some(member);
        }
        if let Some(parent) = self.class_parents.get(type_id)
            && let Some(member) = self.member(parent, member_name)
        {
            return Some(member);
        }
        self.protocols.get(type_id).and_then(|shape| {
            shape
                .fields
                .get(member_name)
                .or_else(|| shape.methods.get(member_name))
        })
    }

    fn direct_member(&self, object: &Expr, name: &str, scope: &Scope) -> Option<MemberType> {
        if let ExprKind::Variable(object_name) = &object.kind
            && let Some(class_id) = scope
                .get(object_name)
                .and_then(|binding| binding.class_id.as_ref())
        {
            return self.member(class_id, name).cloned();
        }
        let type_id = match &object.kind {
            ExprKind::Variable(object_name) => scope.get(object_name).and_then(|binding| {
                binding.ty.variants.iter().find_map(|ty| match ty {
                    StaticType::Named(NamedType::Declared(type_id)) => Some(type_id.clone()),
                    _ => None,
                })
            }),
            ExprKind::This => self.current_class.clone(),
            _ => None,
        }?;
        self.member(&type_id, name).cloned()
    }

    fn inherited_member(&self, type_id: &TypeId, name: &str) -> Option<(bool, MemberType)> {
        if let Some(shape) = self.classes.get(type_id) {
            if let Some(field) = shape.fields.get(name) {
                return Some((false, field.clone()));
            }
            if let Some(method) = shape.methods.get(name) {
                return Some((true, method.clone()));
            }
        }
        self.class_parents
            .get(type_id)
            .and_then(|parent| self.inherited_member(parent, name))
    }

    fn verify_overrides(&mut self, class_id: &TypeId, superclass: &TypeId, span: &Span) {
        let Some(class) = self.classes.get(class_id).cloned() else {
            return;
        };
        for name in class.fields.keys() {
            if self.inherited_member(superclass, name).is_some() {
                self.error(
                    format!("类“{}”不可重声明继承成员“{name}”为域", class_id.name),
                    span.clone(),
                );
            }
        }
        for (name, method) in &class.methods {
            let Some((parent_is_method, inherited)) = self.inherited_member(superclass, name)
            else {
                continue;
            };
            if !parent_is_method {
                self.error(
                    format!("类“{}”不可将继承域“{name}”覆写为法", class_id.name),
                    span.clone(),
                );
                continue;
            }
            if method.is_static != inherited.is_static {
                self.error(
                    format!("覆写法“{name}”不可改变静法/实例法属性"),
                    span.clone(),
                );
            }
            if inherited.visibility == Visibility::Public
                && method.visibility == Visibility::Private
            {
                self.error(format!("覆写法“{name}”不可收窄为私有"), span.clone());
            }
            if method.function != inherited.function {
                self.error(
                    format!("覆写法“{name}”之参数或归值须与父类签名一致"),
                    span.clone(),
                );
            }
        }
    }

    fn verify_protocols(&mut self, class_id: &TypeId, protocols: &[TypeId], span: &Span) {
        let Some(class) = self.classes.get(class_id).cloned() else {
            return;
        };
        for protocol_id in protocols {
            let Some(protocol) = self.protocols.get(protocol_id).cloned() else {
                self.error(format!("未声明协“{protocol_id}”"), span.clone());
                continue;
            };
            for (name, required) in protocol.fields.iter().chain(&protocol.methods) {
                let actual = class
                    .fields
                    .get(name)
                    .or_else(|| class.methods.get(name))
                    .cloned()
                    .or_else(|| {
                        self.class_parents
                            .get(class_id)
                            .and_then(|parent| self.member(parent, name).cloned())
                    });
                let Some(actual) = actual else {
                    self.error(
                        format!("类“{}”纳协“{protocol_id}”却缺少成员“{name}”", class_id.name),
                        span.clone(),
                    );
                    continue;
                };
                let type_matches = required.ty.accepts(&actual.ty)
                    && actual.ty.accepts(&required.ty)
                    && required.function == actual.function;
                if !type_matches || actual.is_static || actual.visibility == Visibility::Private {
                    self.error(
                        format!(
                            "类“{}”之成员“{name}”不符合协“{protocol_id}”的公开实例签名",
                            class_id.name
                        ),
                        span.clone(),
                    );
                }
            }
        }
    }

    fn require(&mut self, expected: &TypeSet, actual: &TypeSet, span: &Span, subject: String) {
        if !expected.accepts(actual) && !self.named_assignable(expected, actual) {
            self.error(
                format!("{subject}应为 {expected}，实为 {actual}"),
                span.clone(),
            );
        }
    }

    fn named_assignable(&self, expected: &TypeSet, actual: &TypeSet) -> bool {
        actual.variants.iter().all(|actual| {
            let StaticType::Named(NamedType::Declared(class_id)) = actual else {
                return false;
            };
            expected.variants.iter().any(|expected| {
                let StaticType::Named(NamedType::Declared(expected_id)) = expected else {
                    return false;
                };
                self.class_is_a(class_id, expected_id)
            })
        })
    }

    fn class_is_a(&self, class_id: &TypeId, expected_id: &TypeId) -> bool {
        class_id == expected_id
            || self.class_conforms(class_id, expected_id)
            || self
                .class_parents
                .get(class_id)
                .is_some_and(|parent| self.class_is_a(parent, expected_id))
    }

    fn class_conforms(&self, class_id: &TypeId, protocol_id: &TypeId) -> bool {
        self.class_protocols
            .get(class_id)
            .is_some_and(|protocols| protocols.contains(protocol_id))
            || self
                .class_parents
                .get(class_id)
                .is_some_and(|parent| self.class_conforms(parent, protocol_id))
    }

    fn narrow_condition(&mut self, condition: &Expr, scope: &mut Scope, truthy: bool) {
        if let ExprKind::TypeTest { value, type_ref } = &condition.kind
            && let ExprKind::Variable(name) = &value.kind
        {
            let expected = self.type_set_from_ref(type_ref);
            if let Some(binding) = scope.get_mut(name) {
                binding.ty = if truthy {
                    expected
                } else {
                    binding.ty.without(&expected)
                };
                binding.function = binding.ty.function();
            }
            return;
        }
        narrow_value_condition(condition, scope, truthy);
    }

    fn error(&mut self, message: impl Into<String>, span: Span) {
        self.coded_error("TYPE000", message, span);
    }

    fn coded_error(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        let message = message.into();
        self.errors.push(TypeError {
            message: if matches!(code, "TYPE000" | "PACKAGE000") {
                message
            } else {
                format!("[{code}] {message}")
            },
            span,
        });
    }

    fn package_path_error(&mut self, error: crate::package::PackagePathError, span: Span) {
        self.coded_error(error.code, error.diagnostic_message(), span);
    }
}

fn member_type(member: &MemberType) -> TypeSet {
    member.function.as_ref().map_or_else(
        || member.ty.clone(),
        |function| {
            TypeSet::single(StaticType::Function(
                function.params.clone(),
                Box::new(function.result.clone()),
            ))
        },
    )
}

fn binding_type(binding: &Binding) -> TypeSet {
    binding.function.as_ref().map_or_else(
        || binding.ty.clone(),
        |function| {
            TypeSet::single(StaticType::Function(
                function.params.clone(),
                Box::new(function.result.clone()),
            ))
        },
    )
}

fn exported_symbol_type(symbol: &ExportedSymbol) -> TypeSet {
    match symbol {
        ExportedSymbol::Value { binding, .. } => binding_type(binding),
        ExportedSymbol::Class { constructor, .. } => TypeSet::single(StaticType::Function(
            constructor.params.clone(),
            Box::new(constructor.result.clone()),
        )),
        ExportedSymbol::Protocol { .. } => TypeSet::named("协"),
        ExportedSymbol::Module { .. } => TypeSet::named("模块"),
    }
}

fn standard_summary(name: &str, shape: ObjectShape, declaration: &Span) -> ModuleSummary {
    let exports = shape
        .fields
        .into_iter()
        .map(|(name, member)| {
            (
                name,
                ExportedSymbol::Value {
                    binding: Binding {
                        ty: member.ty,
                        mutable: false,
                        function: member.function,
                        class_id: None,
                        module: None,
                    },
                    declaration: declaration.clone(),
                },
            )
        })
        .collect();
    ModuleSummary {
        module_id: ModuleId::standard(name),
        source_path: None,
        exports,
    }
}

fn collect_declared_types(types: &TypeSet, output: &mut Vec<TypeId>) {
    for ty in &types.variants {
        match ty {
            StaticType::Named(NamedType::Declared(type_id)) => output.push(type_id.clone()),
            StaticType::List(element) | StaticType::Task(element) => {
                collect_declared_types(element, output);
            }
            StaticType::Tuple(items) => {
                for item in items {
                    collect_declared_types(item, output);
                }
            }
            StaticType::Map(key, value) => {
                collect_declared_types(key, output);
                collect_declared_types(value, output);
            }
            StaticType::Function(parameters, result) => {
                for parameter in parameters {
                    collect_declared_types(parameter, output);
                }
                collect_declared_types(result, output);
            }
            StaticType::Any | StaticType::Named(NamedType::Builtin(_)) => {}
        }
    }
}

fn existing_source_path(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    path.exists().then(|| fs::canonicalize(path).ok()).flatten()
}

fn is_builtin_type(name: &str) -> bool {
    matches!(
        name,
        "任意"
            | "数"
            | "文"
            | "字节串"
            | "理"
            | "空"
            | "列"
            | "元"
            | "典"
            | "遍器"
            | "任务"
            | "法"
            | "类"
            | "协"
            | "模块"
            | "误"
            | "对象"
            | "套接字"
            | "原生模块"
            | "原生资源"
    )
}

fn standard_module_shape(name: &str) -> Option<ObjectShape> {
    let mut shape = ObjectShape::default();
    match name {
        "数学" => {
            insert_module_member(&mut shape, "圆周率", TypeSet::named("数"), None);
            insert_module_member(
                &mut shape,
                "绝对值",
                TypeSet::named("法"),
                Some(FunctionType {
                    params: vec![TypeSet::named("数")],
                    result: TypeSet::named("数"),
                }),
            );
            insert_module_member(
                &mut shape,
                "平方根",
                TypeSet::named("法"),
                Some(FunctionType {
                    params: vec![TypeSet::named("数")],
                    result: TypeSet::named("数"),
                }),
            );
            insert_module_member(
                &mut shape,
                "幂",
                TypeSet::named("法"),
                Some(FunctionType {
                    params: vec![TypeSet::named("数"), TypeSet::named("数")],
                    result: TypeSet::named("数"),
                }),
            );
            for function in ["下取整", "上取整", "四舍五入", "正弦", "余弦"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("数")],
                    TypeSet::named("数"),
                );
            }
            for function in ["最小", "最大"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("数"), TypeSet::named("数")],
                    TypeSet::named("数"),
                );
            }
        }
        "文字" => {
            for function in ["修剪", "大写", "小写"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("文"),
                );
            }
            for function in ["分割", "字符列"] {
                let params = if function == "分割" {
                    vec![TypeSet::named("文"), TypeSet::named("文")]
                } else {
                    vec![TypeSet::named("文")]
                };
                insert_std_function(&mut shape, function, params, TypeSet::named("列"));
            }
            insert_std_function(
                &mut shape,
                "替换",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                ],
                TypeSet::named("文"),
            );
            for function in ["始于", "终于"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文"), TypeSet::named("文")],
                    TypeSet::named("理"),
                );
            }
            insert_std_function(
                &mut shape,
                "联结",
                vec![TypeSet::named("列"), TypeSet::named("文")],
                TypeSet::named("文"),
            );
        }
        "字节" => {
            for function in ["从文字", "转文字"] {
                let (parameter, result) = if function == "从文字" {
                    ("文", "字节串")
                } else {
                    ("字节串", "文")
                };
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named(parameter)],
                    TypeSet::named(result),
                );
            }
            insert_std_function(
                &mut shape,
                "长度",
                vec![TypeSet::named("字节串")],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "切片",
                vec![
                    TypeSet::named("字节串"),
                    TypeSet::named("数"),
                    TypeSet::named("数"),
                ],
                TypeSet::named("字节串"),
            );
            for function in ["拼接", "查找"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("字节串"), TypeSet::named("字节串")],
                    if function == "拼接" {
                        TypeSet::named("字节串")
                    } else {
                        TypeSet::union(vec![TypeSet::named("数"), TypeSet::named("空")])
                    },
                );
            }
            let number_list = TypeSet::single(StaticType::List(Box::new(TypeSet::named("数"))));
            insert_std_function(
                &mut shape,
                "从数列",
                vec![number_list.clone()],
                TypeSet::named("字节串"),
            );
            insert_std_function(
                &mut shape,
                "转数列",
                vec![TypeSet::named("字节串")],
                number_list,
            );
        }
        "时间" => {
            for function in ["今", "毫秒"] {
                insert_std_function(&mut shape, function, vec![], TypeSet::named("数"));
            }
            insert_std_function(
                &mut shape,
                "等待",
                vec![TypeSet::named("数")],
                TypeSet::named("空"),
            );
        }
        "文件" => {
            insert_std_function(
                &mut shape,
                "读取",
                vec![TypeSet::named("文")],
                TypeSet::named("文"),
            );
            for function in ["写入", "追加"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文"), TypeSet::named("文")],
                    TypeSet::named("数"),
                );
            }
            insert_std_function(
                &mut shape,
                "存在",
                vec![TypeSet::named("文")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "目录",
                vec![TypeSet::named("文")],
                TypeSet::named("列"),
            );
            insert_std_function(
                &mut shape,
                "读取字节",
                vec![TypeSet::named("文")],
                TypeSet::named("字节串"),
            );
            for function in ["写入字节", "追加字节"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文"), TypeSet::named("字节串")],
                    TypeSet::named("数"),
                );
            }
            insert_std_function(
                &mut shape,
                "状态",
                vec![TypeSet::named("文")],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
            insert_std_function(
                &mut shape,
                "创建目录",
                vec![TypeSet::named("文")],
                TypeSet::named("空"),
            );
            insert_std_function(
                &mut shape,
                "删除",
                vec![TypeSet::named("文"), TypeSet::named("理")],
                TypeSet::named("空"),
            );
        }
        "JSON" | "json" => {
            insert_std_function(
                &mut shape,
                "解析",
                vec![TypeSet::named("文")],
                TypeSet::any(),
            );
            insert_std_function(
                &mut shape,
                "序列化",
                vec![TypeSet::any()],
                TypeSet::named("文"),
            );
        }
        "网络" => {
            insert_std_function(
                &mut shape,
                "获取",
                vec![TypeSet::named("文")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "发文",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "请求",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("数"),
                    TypeSet::named("数"),
                ],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
            insert_std_function(
                &mut shape,
                "请求字节",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::single(StaticType::Map(
                        Box::new(TypeSet::named("文")),
                        Box::new(TypeSet::named("文")),
                    )),
                    TypeSet::union(vec![TypeSet::named("字节串"), TypeSet::named("空")]),
                    TypeSet::named("数"),
                    TypeSet::named("数"),
                ],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
        }
        "套接字" => {
            let socket = TypeSet::named("套接字");
            insert_std_function(
                &mut shape,
                "TCP连接",
                vec![TypeSet::named("文"), TypeSet::named("数")],
                socket.clone(),
            );
            insert_std_function(
                &mut shape,
                "TCP监听",
                vec![TypeSet::named("文")],
                socket.clone(),
            );
            insert_std_function(
                &mut shape,
                "接受",
                vec![socket.clone(), TypeSet::named("数")],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
            insert_std_function(
                &mut shape,
                "发送",
                vec![socket.clone(), TypeSet::named("文"), TypeSet::named("数")],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "接收",
                vec![socket.clone(), TypeSet::named("数"), TypeSet::named("数")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "发送字节",
                vec![
                    socket.clone(),
                    TypeSet::named("字节串"),
                    TypeSet::named("数"),
                ],
                TypeSet::named("数"),
            );
            for function in ["接收字节", "精确读取"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![socket.clone(), TypeSet::named("数"), TypeSet::named("数")],
                    if function == "精确读取" {
                        TypeSet::named("字节串")
                    } else {
                        TypeSet::single(StaticType::Map(
                            Box::new(TypeSet::named("文")),
                            Box::new(TypeSet::any()),
                        ))
                    },
                );
            }
            insert_std_function(
                &mut shape,
                "UDP绑定",
                vec![TypeSet::named("文")],
                socket.clone(),
            );
            insert_std_function(
                &mut shape,
                "UDP发送至",
                vec![
                    socket.clone(),
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("数"),
                ],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "UDP接收自",
                vec![socket.clone(), TypeSet::named("数"), TypeSet::named("数")],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::named("文")),
                )),
            );
            insert_std_function(
                &mut shape,
                "UDP发送字节至",
                vec![
                    socket.clone(),
                    TypeSet::named("字节串"),
                    TypeSet::named("文"),
                    TypeSet::named("数"),
                ],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "UDP接收字节自",
                vec![socket.clone(), TypeSet::named("数"), TypeSet::named("数")],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
            insert_std_function(
                &mut shape,
                "本地地址",
                vec![socket.clone()],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "对端地址",
                vec![socket.clone()],
                TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "关闭",
                vec![socket.clone()],
                TypeSet::named("空"),
            );
            insert_std_function(
                &mut shape,
                "关闭写端",
                vec![socket.clone()],
                TypeSet::named("空"),
            );
            insert_std_function(
                &mut shape,
                "TCP无延迟",
                vec![socket, TypeSet::named("理")],
                TypeSet::named("空"),
            );
        }
        "测试" => {
            insert_std_function(
                &mut shape,
                "断言",
                vec![TypeSet::named("理"), TypeSet::named("文")],
                TypeSet::named("空"),
            );
            for function in ["相等", "非空"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::any(), TypeSet::any()],
                    TypeSet::named("空"),
                );
            }
        }
        "路径" => {
            insert_std_function(
                &mut shape,
                "合并",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::named("文"),
            );
            let optional_text = TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]);
            for function in ["父级", "文件名", "扩展名"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    optional_text.clone(),
                );
            }
            insert_std_function(
                &mut shape,
                "是否绝对",
                vec![TypeSet::named("文")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "规范化",
                vec![TypeSet::named("文")],
                TypeSet::named("文"),
            );
        }
        "环境" => {
            insert_std_function(
                &mut shape,
                "读取",
                vec![TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "存在",
                vec![TypeSet::named("文")],
                TypeSet::named("理"),
            );
            for function in ["当前目录", "系统", "架构"] {
                insert_std_function(&mut shape, function, vec![], TypeSet::named("文"));
            }
            insert_std_function(&mut shape, "参数", vec![], TypeSet::named("列"));
        }
        "进程" => {
            insert_std_function(
                &mut shape,
                "执行",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("列"),
                    TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
                    TypeSet::named("数"),
                ],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::any()),
                )),
            );
        }
        "资源" => {
            insert_std_function(
                &mut shape,
                "读取字节",
                vec![TypeSet::named("文")],
                TypeSet::named("字节串"),
            );
            insert_std_function(
                &mut shape,
                "读取文字",
                vec![TypeSet::named("文")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "目录",
                vec![TypeSet::named("文")],
                TypeSet::named("列"),
            );
        }
        "原生" => {
            insert_std_function(
                &mut shape,
                "加载",
                vec![TypeSet::named("文")],
                TypeSet::named("原生模块"),
            );
            insert_std_function(
                &mut shape,
                "调用",
                vec![
                    TypeSet::named("原生模块"),
                    TypeSet::named("文"),
                    TypeSet::named("列"),
                ],
                TypeSet::any(),
            );
            insert_std_function(
                &mut shape,
                "关闭资源",
                vec![TypeSet::named("原生资源")],
                TypeSet::named("空"),
            );
            insert_std_function(
                &mut shape,
                "资源类型",
                vec![TypeSet::named("原生资源")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "泄漏统计",
                vec![],
                TypeSet::single(StaticType::Map(
                    Box::new(TypeSet::named("文")),
                    Box::new(TypeSet::named("数")),
                )),
            );
        }
        "哈希" => {
            insert_std_function(
                &mut shape,
                "SHA256",
                vec![TypeSet::named("文")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "HMACSHA256",
                vec![TypeSet::named("字节串"), TypeSet::named("字节串")],
                TypeSet::named("字节串"),
            );
            insert_std_function(
                &mut shape,
                "恒时相等",
                vec![TypeSet::named("字节串"), TypeSet::named("字节串")],
                TypeSet::named("理"),
            );
        }
        "编码" => {
            for function in ["十六进制", "解十六进制", "百分号", "解百分号"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("文"),
                );
            }
        }
        "统计" => {
            let number_list = TypeSet::single(StaticType::List(Box::new(TypeSet::named("数"))));
            for function in ["总和", "平均", "中位数", "方差", "标准差"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![number_list.clone()],
                    TypeSet::named("数"),
                );
            }
        }
        "CSV" | "csv" => {
            let text_list = TypeSet::single(StaticType::List(Box::new(TypeSet::named("文"))));
            let table = TypeSet::single(StaticType::List(Box::new(text_list)));
            insert_std_function(
                &mut shape,
                "解析",
                vec![TypeSet::named("文")],
                table.clone(),
            );
            insert_std_function(&mut shape, "序列化", vec![table], TypeSet::named("文"));
        }
        "随机" => {
            insert_std_function(
                &mut shape,
                "小数",
                vec![TypeSet::named("数")],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "整数",
                vec![
                    TypeSet::named("数"),
                    TypeSet::named("数"),
                    TypeSet::named("数"),
                ],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "布尔",
                vec![TypeSet::named("数")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "安全字节",
                vec![TypeSet::named("数")],
                TypeSet::named("字节串"),
            );
        }
        "标识" => {
            for function in ["稳定UUID", "是否UUID"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    if function == "是否UUID" {
                        TypeSet::named("理")
                    } else {
                        TypeSet::named("文")
                    },
                );
            }
            insert_std_function(
                &mut shape,
                "稳定短码",
                vec![TypeSet::named("文"), TypeSet::named("数")],
                TypeSet::named("文"),
            );
        }
        "模板" => {
            insert_std_function(
                &mut shape,
                "插值",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                ],
                TypeSet::named("文"),
            );
            for function in ["转义HTML", "反转义HTML"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("文"),
                );
            }
        }
        "校验" => {
            for function in ["电子邮件", "IPv4", "十六进制色", "标识符"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("理"),
                );
            }
        }
        "Base64" => {
            for function in ["编码", "解码", "网址编码", "解网址编码"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("文"),
                );
            }
        }
        "正则" => {
            insert_std_function(
                &mut shape,
                "匹配",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "首项",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "替换全部",
                vec![
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                    TypeSet::named("文"),
                ],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "分割",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::single(StaticType::List(Box::new(TypeSet::named("文")))),
            );
        }
        "URL" => {
            insert_std_function(
                &mut shape,
                "是否合法",
                vec![TypeSet::named("文")],
                TypeSet::named("理"),
            );
            for function in ["协议", "路径"] {
                insert_std_function(
                    &mut shape,
                    function,
                    vec![TypeSet::named("文")],
                    TypeSet::named("文"),
                );
            }
            insert_std_function(
                &mut shape,
                "主机",
                vec![TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "端口",
                vec![TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("数"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "查询值",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("文"), TypeSet::named("空")]),
            );
            insert_std_function(
                &mut shape,
                "合并",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::named("文"),
            );
        }
        "日期" => {
            insert_std_function(
                &mut shape,
                "是否合法",
                vec![TypeSet::named("文")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "是否闰年",
                vec![TypeSet::named("数")],
                TypeSet::named("理"),
            );
            insert_std_function(
                &mut shape,
                "加天",
                vec![TypeSet::named("文"), TypeSet::named("数")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "相差天数",
                vec![TypeSet::named("文"), TypeSet::named("文")],
                TypeSet::named("数"),
            );
            insert_std_function(
                &mut shape,
                "HTTP日期",
                vec![TypeSet::named("数")],
                TypeSet::named("文"),
            );
            insert_std_function(
                &mut shape,
                "解析HTTP日期",
                vec![TypeSet::named("文")],
                TypeSet::union(vec![TypeSet::named("数"), TypeSet::named("空")]),
            );
        }
        _ => return None,
    }
    Some(shape)
}

fn insert_std_function(shape: &mut ObjectShape, name: &str, params: Vec<TypeSet>, result: TypeSet) {
    insert_module_member(
        shape,
        name,
        TypeSet::named("法"),
        Some(FunctionType { params, result }),
    );
}

fn insert_module_member(
    shape: &mut ObjectShape,
    name: &str,
    ty: TypeSet,
    function: Option<FunctionType>,
) {
    shape.fields.insert(
        name.into(),
        MemberType {
            ty,
            function,
            is_static: false,
            readonly: true,
            visibility: Visibility::Public,
            owner: TypeId::new(
                ModuleId::standard("内建摘要"),
                name,
                TypeDeclarationKind::Protocol,
            ),
        },
    );
}

fn binding(ty: TypeSet, mutable: bool) -> Binding {
    let function = ty.function();
    Binding {
        ty,
        mutable,
        function,
        class_id: None,
        module: None,
    }
}

fn narrow_value_condition(condition: &Expr, scope: &mut Scope, truthy: bool) {
    let ExprKind::Binary {
        left,
        operator,
        right,
    } = &condition.kind
    else {
        return;
    };
    let equality = matches!(operator, TokenKind::EqualEqual);
    let inequality = matches!(operator, TokenKind::BangEqual);
    if !equality && !inequality {
        return;
    }
    let matches_branch = if equality { truthy } else { !truthy };

    let nil_name = match (&left.kind, &right.kind) {
        (ExprKind::Variable(name), ExprKind::Literal(Literal::Nil))
        | (ExprKind::Literal(Literal::Nil), ExprKind::Variable(name)) => Some(name.as_str()),
        _ => None,
    };
    if let Some(name) = nil_name {
        narrow_name(scope, name, "空", matches_branch);
        return;
    }

    if let (Some(name), Some(type_name)) = (type_query_name(left), string_literal(right)) {
        narrow_name(scope, name, type_name, matches_branch);
    } else if let (Some(type_name), Some(name)) = (string_literal(left), type_query_name(right)) {
        narrow_name(scope, name, type_name, matches_branch);
    }
}

fn type_query_name(expression: &Expr) -> Option<&str> {
    let ExprKind::Call { callee, arguments } = &expression.kind else {
        return None;
    };
    if arguments.len() != 1 || !matches!(&callee.kind, ExprKind::Variable(name) if name == "类型")
    {
        return None;
    }
    match &arguments[0].kind {
        ExprKind::Variable(name) => Some(name),
        _ => None,
    }
}

fn string_literal(expression: &Expr) -> Option<&str> {
    match &expression.kind {
        ExprKind::Literal(Literal::String(text)) => Some(text),
        _ => None,
    }
}

fn narrow_name(scope: &mut Scope, name: &str, type_name: &str, matches_branch: bool) {
    let Some(binding) = scope.get_mut(name) else {
        return;
    };
    binding.ty = if matches_branch {
        TypeSet::named(type_name)
    } else {
        binding.ty.without_named(type_name)
    };
    binding.function = binding.ty.function();
}

fn builtin(name: &str) -> Option<Binding> {
    let (params, result) = match name {
        "时刻" => (vec![], "数"),
        "长度" => (vec![TypeSet::any()], "数"),
        "类型" => (vec![TypeSet::any()], "文"),
        "追加" => (vec![TypeSet::named("列"), TypeSet::any()], "列"),
        "弹出" => (vec![TypeSet::named("列")], "任意"),
        "有键" => (vec![TypeSet::named("典"), TypeSet::any()], "理"),
        "插入" => (
            vec![TypeSet::named("列"), TypeSet::named("数"), TypeSet::any()],
            "列",
        ),
        "删除" => (vec![TypeSet::named("列"), TypeSet::named("数")], "任意"),
        "键列" => (vec![TypeSet::named("典")], "列"),
        "值列" => (vec![TypeSet::named("典")], "列"),
        "遍" => (vec![TypeSet::any()], "遍器"),
        "续" => (vec![TypeSet::named("遍器")], "元"),
        "范围" => (vec![TypeSet::named("数"), TypeSet::named("数")], "遍器"),
        "步进范围" => (
            vec![
                TypeSet::named("数"),
                TypeSet::named("数"),
                TypeSet::named("数"),
            ],
            "遍器",
        ),
        "映射" | "筛选" => (vec![TypeSet::any(), TypeSet::named("法")], "遍器"),
        "折叠" => (
            vec![TypeSet::any(), TypeSet::any(), TypeSet::named("法")],
            "任意",
        ),
        "排序" | "反转" => (vec![TypeSet::any()], "列"),
        "包含" => (vec![TypeSet::any(), TypeSet::any()], "理"),
        "寻找" => (vec![TypeSet::any(), TypeSet::named("法")], "元"),
        "取消" => (vec![TypeSet::named("任务")], "理"),
        "任务状态" => (vec![TypeSet::named("任务")], "文"),
        "并候" => (vec![TypeSet::named("列")], "列"),
        _ => return None,
    };
    Some(Binding {
        ty: TypeSet::named("法"),
        mutable: false,
        function: Some(FunctionType {
            params,
            result: TypeSet::named(result),
        }),
        class_id: None,
        module: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn check_project(
        name: &str,
        modules: &[(&str, &str)],
        entry: &str,
    ) -> Result<(), Vec<TypeError>> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-types-{name}-{unique}"));
        fs::create_dir_all(&root).unwrap();
        for (path, source) in modules {
            fs::write(root.join(path), source).unwrap();
        }
        let entry_path = root.join("main.yx");
        fs::write(&entry_path, entry).unwrap();
        let statements = crate::parse_named(entry, entry_path.display().to_string()).unwrap();
        let result = check_in_directory(&statements, &root);
        fs::remove_dir_all(root).unwrap();
        result
    }

    #[test]
    fn accepts_union_and_rejects_certain_mismatch() {
        let ok = crate::parse("定 值：数|文 为「善」；").unwrap();
        check(&ok).unwrap();

        let bad = crate::parse("定 值：数 为「非数」；").unwrap();
        let errors = check(&bad).unwrap_err();
        assert!(errors[0].to_string().contains("应为 数"));
    }

    #[test]
    fn any_annotation_accepts_and_propagates_dynamic_values() {
        let source = r#"
            定 初值：任意 为 空；
            令 值：任意 为 1；
            置 值 为「文」；
            法 原样（参数：任意）：任意 则 归 参数；终
            定 结果：任意 为 原样（【1，2】）；
        "#;
        check(&crate::parse(source).unwrap()).unwrap();
    }

    #[test]
    fn checks_function_arguments_without_running() {
        let source = "法 加一（值：数）：数 则 归 值 加 1；终 加一（「一」）；";
        let statements = crate::parse(source).unwrap();
        let errors = check(&statements).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("参数应为 数"))
        );
    }

    #[test]
    fn unannotated_function_result_remains_dynamic() {
        let source =
            "法 递归（数）则 若 数 小于 1 则 归 1；终 归 递归（数 减 1） 加 1；终 言 递归（3）；";
        check(&crate::parse(source).unwrap()).unwrap();
    }

    #[test]
    fn infers_container_elements_and_function_annotations() {
        let ok = r#"
            法 加一（值：数）：数 则 归 值 加 1；终
            法 应用（操作：法（数）：数，值：数）：数 则 归 操作（值）；终
            定 数列：列<数> 为【1，2，3】；
            定 所得：数 为 应用（加一，数列【0】）；
        "#;
        check(&crate::parse(ok).unwrap()).unwrap();

        let bad = crate::parse("定 数列：列<数> 为【1，「二」】；").unwrap();
        let errors = check(&bad).unwrap_err();
        assert!(errors.iter().any(|error| error.message.contains("列<数>")));
    }

    #[test]
    fn narrows_nullable_values_in_control_flow() {
        let source = r#"
            法 加一或零（值：数?）：数 则
                若 值 不等于 空 则 归 值 加 1；终
                归 0；
            终
        "#;
        check(&crate::parse(source).unwrap()).unwrap();
    }

    #[test]
    fn verifies_protocol_conformance_and_member_types() {
        let good = r#"
            协 可命名 则 域 姓名：文；法 显示（）：文；终
            类 用户 纳 可命名 则
                公 只 域 姓名：文；
                法 初始化（姓名：文）则 置 此.姓名 为 姓名；终
                法 显示（）：文 则 归 此.姓名；终
            终
            定 某人：可命名 为 用户（「言序」）；
            定 名字：文 为 某人.显示（）；
        "#;
        check(&crate::parse(good).unwrap()).unwrap();

        let bad = r#"
            协 可命名 则 法 显示（）：文；终
            类 坏 纳 可命名 则 法 显示（）：数 则 归 1；终 终
        "#;
        let errors = check(&crate::parse(bad).unwrap()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("不符合协"))
        );
    }

    #[test]
    fn checks_expanded_standard_module_signatures() {
        let source = r#"
            引「标准:路径」为 路径；
            引「标准:哈希」为 哈希；
            引「标准:统计」为 统计；
            引「标准:CSV」为 CSV；
            引「标准:随机」为 随机；
            引「标准:标识」为 标识；
            引「标准:模板」为 模板；
            引「标准:校验」为 校验；
            引「标准:Base64」为 Base64；
            引「标准:正则」为 正则；
            引「标准:URL」为 URL；
            引「标准:日期」为 日期；
            定 文件：文? 为 路径.文件名（「甲/乙.yx」）；
            定 摘要：文 为 哈希.SHA256（「言序」）；
            定 平均：数 为 统计.平均（【1，2，3】）；
            定 表：列<列<文>> 为 CSV.解析（「甲,乙」）；
            定 项：文 为 表【0】【1】；
            定 随机数：数 为 随机.整数（42，10，20）；
            定 标号：文 为 标识.稳定UUID（「言序」）；
            定 页面：文 为 模板.插值（「{{name}}」，「name」，「言序」）；
            定 地址可用：理 为 校验.电子邮件（「hello@yanxu.dev」）；
            定 编码值：文 为 Base64.编码（「言序」）；
            定 匹配项：文? 为 正则.首项（「[0-9]+」，「甲12乙」）；
            定 地址主机：文? 为 URL.主机（「https://yanxu.dev/」）；
            定 地址端口：数? 为 URL.端口（「https://yanxu.dev:8443/」）；
            定 明日：文 为 日期.加天（「2024-01-01」，1）；
        "#;
        check(&crate::parse(source).unwrap()).unwrap();

        let bad = crate::parse("引「标准:统计」为 统计；定 坏：数 为 统计.平均（【1，「二」】）；")
            .unwrap();
        let errors = check(&bad).unwrap_err();
        assert!(errors.iter().any(|error| error.message.contains("列<数>")));
    }

    #[test]
    fn infers_async_task_results_and_rejects_awaiting_plain_values() {
        let source = r#"
            异 法 加一（值：数）：数 则 归 值 加 1；终
            定 工作：任务<数> 为 加一（1）；
            定 所得：数 为 候 工作；
            定 状态：文 为 任务状态（工作）；
        "#;
        check(&crate::parse(source).unwrap()).unwrap();

        let errors = check(&crate::parse("定 坏：数 为 候 1；").unwrap()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("须收任务"))
        );
    }

    #[test]
    fn infers_fold_result_from_the_initial_accumulator() {
        let source = r#"
            法 相加（合计：数，分数：数）：数 则
                归 合计 加 分数；
            终
            定 总分：数 为 折叠（【1，2，3】，0，相加）；
        "#;
        check(&crate::parse(source).unwrap()).unwrap();
    }

    #[test]
    fn checks_cross_module_inheritance_protocols_and_nested_types() {
        let base = r#"
            公 协 可描述 则 法 描述（）：文；终
            公 类 视图 纳 可描述 则
                公 域 标题：文；
                公 法 描述（）：文 则 归 此.标题；终
                公 静 法 种类（）：文 则 归「视图」；终
            终
        "#;
        let entry = r#"
            引「base.yx」为 基础；
            公 类 按钮 承 基础.视图 纳 基础.可描述 则
                公 域 子项：列<基础.视图>；
                公 域 候选：基础.视图?；
                公 法 描述（）：文 则 归 父.描述（）加「按钮」；终
            终
            公 法 包装（内容：基础.视图）：基础.视图 则 归 内容；终
            定 父值：基础.视图 为 按钮（）；
            定 协值：基础.可描述 为 按钮（）；
            定 嵌套：典<文，元<基础.视图，任务<基础.视图>>> 为 {}；
            定 转换：法（基础.视图）：基础.视图 为 包装；
            令 待判：基础.视图|文 为 按钮（）；
            若 待判 是 按钮 则
                定 已窄：按钮 为 待判；
                定 类名：文 为 基础.视图.种类（）；
            终
            若 父值 是 基础.视图 则 定 仍为父：基础.视图 为 父值；终
        "#;
        check_project("cross-module", &[("base.yx", base)], entry).unwrap();
    }

    #[test]
    fn reports_cross_module_override_and_protocol_failures() {
        let base = r#"
            公 协 可描述 则 法 描述（值：文）：文；终
            公 类 视图 则 公 法 描述（值：文）：文 则 归 值；终 终
        "#;
        let entry = r#"
            引「base.yx」为 基础；
            类 坏覆写 承 基础.视图 则
                法 描述（值：数）：文 则 归「坏」；终
            终
            类 坏协议 纳 基础.可描述 则
                法 描述（值：数）：文 则 归「坏」；终
            终
        "#;
        let errors = check_project("bad-oop", &[("base.yx", base)], entry).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("参数或归值须与父类签名一致"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("不符合协"))
        );
    }

    #[test]
    fn canonical_ids_separate_same_names_and_ignore_import_aliases() {
        let module = "公 类 节点 则 终";
        let entry = r#"
            引「a.yx」为 甲；
            引「b.yx」为 乙；
            引「a.yx」为 核心；
            定 左：甲.节点 为 甲.节点（）；
            定 同一：核心.节点 为 左；
            定 右：乙.节点 为 乙.节点（）；
            若 左 是 核心.节点 则 定 仍同一：甲.节点 为 左；终
        "#;
        check_project("same-name", &[("a.yx", module), ("b.yx", module)], entry).unwrap();

        let bad = r#"
            引「a.yx」为 甲；引「b.yx」为 乙；
            定 左：甲.节点 为 甲.节点（）；
            定 错：乙.节点 为 左；
        "#;
        let errors =
            check_project("same-name-bad", &[("a.yx", module), ("b.yx", module)], bad).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("变量“错”应为"))
        );
    }

    #[test]
    fn diagnoses_private_bare_and_wrong_kind_qualified_paths() {
        let base = r#"
            类 私类 则 终
            协 私协 则 终
            公 协 可协议 则 终
            公 类 公开类 则 终
            公 定 值：数 为 1；
        "#;
        let entry = r#"
            引「base.yx」为 基础；
            定 裸：公开类 为 基础.公开类（）；
            定 私类值：基础.私类 为 基础.公开类（）；
            定 私协值：基础.私协 为 基础.公开类（）；
            定 非类型：基础.值 为 1；
            定 坏中段：基础.值.内部 为 1；
            定 无别名：未知.公开类 为 基础.公开类（）；
            定 缺成员：基础.不存在 为 基础.公开类（）；
            类 错父 承 基础.可协议 则 终
            类 错纳 纳 基础.公开类 则 终
        "#;
        let errors = check_project("path-errors", &[("base.yx", base)], entry).unwrap_err();
        let messages = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|message| message.contains("不可裸写")));
        assert!(
            messages
                .iter()
                .filter(|message| message.contains("未公开成员"))
                .count()
                >= 2
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("不是类或协"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("中间段“值”不是模块"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("模块别名“未知”不存在"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("未公开成员“不存在”"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("不可用作类"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("不可用作协"))
        );
    }

    #[test]
    fn follows_three_level_public_module_reexports() {
        let leaf = "公 类 按钮 则 公 法 名称（）：文 则 归「按钮」；终 终";
        let middle = "公 引「leaf.yx」为 组件；";
        let facade = "公 引「middle.yx」为 场景；";
        let entry = r#"
            引「facade.yx」为 界面；
            类 特殊按钮 承 界面.场景.组件.按钮 则
                法 名称（）：文 则 归 父.名称（）加「特别」；终
            终
            定 根：界面.场景.组件.按钮 为 特殊按钮（）；
        "#;
        check_project(
            "facade",
            &[
                ("leaf.yx", leaf),
                ("middle.yx", middle),
                ("facade.yx", facade),
            ],
            entry,
        )
        .unwrap();
    }

    #[test]
    fn rejects_public_api_leaks_and_reports_reexport_cycles() {
        let leaking = r#"
            类 私密 则 终
            公 法 泄漏（值：私密）：私密 则 归 值；终
            公 类 容器 则 公 域 内容：私密；终
        "#;
        let errors = check_project("leak", &[], leaking).unwrap_err();
        assert!(
            errors
                .iter()
                .filter(|error| error.message.contains("泄漏不可访问的私有类型"))
                .count()
                >= 2
        );

        let errors = check_project(
            "cycle",
            &[
                ("a.yx", "公 引「b.yx」为 乙；"),
                ("b.yx", "公 引「a.yx」为 甲；"),
            ],
            "引「a.yx」为 甲；",
        )
        .unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("模块类型检查循环相引")
                    && error.message.contains('→'))
        );
    }
}

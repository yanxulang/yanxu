use crate::ast::{
    Expr, ExprKind, Literal, Parameter, Stmt, StmtKind, TypeKind, TypePath, TypeRef, Visibility,
};
use crate::source::Span;
use crate::token::TokenKind;
use crate::type_model::{ModuleId, TypeDeclarationKind, TypeId};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type EnvRef = Rc<RefCell<Environment>>;
type NativeBody = fn(&[Value]) -> Result<Value, RuntimeError>;

#[derive(Clone, Copy)]
enum NativeKind {
    Plain(NativeBody),
    Guarded(GuardedNative),
    Append,
    Insert,
    Iterator,
    Next,
    Range,
    SteppedRange,
    Map,
    Filter,
    Fold,
    Sort,
    Reverse,
    Contains,
    Find,
    CancelTask,
    TaskStatus,
    JoinTasks,
}

#[derive(Clone, Copy)]
enum GuardedNative {
    ReadFile,
    ReadBytes,
    WriteFile,
    WriteBytes,
    AppendFile,
    AppendBytes,
    FileStatus,
    PathExists,
    ReadDirectory,
    CreateDirectory,
    RemovePath,
    HttpGet,
    HttpPost,
    HttpRequest,
    HttpBytesRequest,
    SocketTcpConnect,
    SocketTcpListen,
    SocketAccept,
    SocketSend,
    SocketReceive,
    SocketSendBytes,
    SocketReceiveBytes,
    SocketReadExact,
    SocketUdpBind,
    SocketUdpSendTo,
    SocketUdpReceiveFrom,
    SocketUdpSendBytesTo,
    SocketUdpReceiveBytesFrom,
    SocketLocalAddress,
    SocketPeerAddress,
    SocketClose,
    SocketShutdownWrite,
    SocketSetNodelay,
    EnvRead,
    EnvExists,
    Arguments,
    ProcessRun,
    ResourceReadBytes,
    ResourceReadText,
    ResourceList,
}

#[derive(Clone)]
pub enum Value {
    Number(f64),
    String(String),
    Bytes(Rc<Vec<u8>>),
    Bool(bool),
    Nil,
    Function(Rc<Function>),
    Native(Rc<NativeFunction>),
    Class(Rc<YanxuClass>),
    Protocol(Rc<YanxuProtocol>),
    Instance(Rc<RefCell<YanxuInstance>>),
    Module(Rc<YanxuModule>),
    List(Rc<RefCell<Vec<Value>>>),
    Tuple(Rc<Vec<Value>>),
    Map(Rc<RefCell<YanxuMap>>),
    Iterator(Rc<RefCell<YanxuIterator>>),
    Error(Rc<YanxuErrorValue>),
    Task(Rc<RefCell<YanxuTask>>),
    Socket(Rc<RefCell<crate::stdlib::SocketHandle>>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) if number.fract() == 0.0 => write!(f, "{number:.0}"),
            Self::Number(number) => write!(f, "{number}"),
            Self::String(text) => write!(f, "{text}"),
            Self::Bytes(bytes) => write!(f, "<字节串 {} 字节>", bytes.len()),
            Self::Bool(true) => write!(f, "真"),
            Self::Bool(false) => write!(f, "假"),
            Self::Nil => write!(f, "空"),
            Self::Function(function) => write!(f, "<法 {}>", function.name),
            Self::Native(function) => write!(f, "<天授之法 {}>", function.name),
            Self::Class(class) => write!(f, "<类 {}>", class.name),
            Self::Protocol(protocol) => write!(f, "<协 {}>", protocol.name),
            Self::Instance(instance) => write!(f, "<{}之实例>", instance.borrow().class.name),
            Self::Module(module) => write!(f, "<模块 {}>", module.module_id),
            Self::List(items) => {
                let rendered = items
                    .borrow()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("，");
                write!(f, "【{rendered}】")
            }
            Self::Tuple(items) => {
                let rendered = items
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("，");
                write!(f, "（{rendered}）")
            }
            Self::Map(map) => {
                let rendered = map
                    .borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| format!("{key}：{value}"))
                    .collect::<Vec<_>>()
                    .join("，");
                write!(f, "{{{rendered}}}")
            }
            Self::Iterator(_) => write!(f, "<遍器>"),
            Self::Error(error) => write!(f, "<误 {}>", error.message),
            Self::Task(task) => write!(f, "<任务 {}>", task.borrow().status()),
            Self::Socket(socket) => write!(f, "<套接字 {}>", socket.borrow().kind_name()),
        }
    }
}

impl Value {
    pub fn type_name(&self) -> String {
        match self {
            Self::Number(_) => "数".into(),
            Self::String(_) => "文".into(),
            Self::Bytes(_) => "字节串".into(),
            Self::Bool(_) => "理".into(),
            Self::Nil => "空".into(),
            Self::Function(_) | Self::Native(_) => "法".into(),
            Self::Class(_) => "类".into(),
            Self::Protocol(_) => "协".into(),
            Self::Instance(instance) => instance.borrow().class.name.clone(),
            Self::Module(_) => "模块".into(),
            Self::List(_) => "列".into(),
            Self::Tuple(_) => "元".into(),
            Self::Map(_) => "典".into(),
            Self::Iterator(_) => "遍器".into(),
            Self::Error(_) => "误".into(),
            Self::Task(_) => "任务".into(),
            Self::Socket(_) => "套接字".into(),
        }
    }

    fn truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Bool(false))
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeError {
    pub code: &'static str,
    pub message: String,
    pub frames: Vec<String>,
    pub span: Option<Span>,
}

impl RuntimeError {
    fn new(message: impl Into<String>) -> Self {
        Self::coded("RUN000", message)
    }

    fn coded(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            frames: Vec::new(),
            span: None,
        }
    }

    fn package_path(error: crate::package::PackagePathError) -> Self {
        Self::coded(error.code, error.diagnostic_message())
    }

    fn package(error: crate::package::ManifestError) -> Self {
        if error.code() == "PACKAGE000" {
            Self::new(error.to_string())
        } else {
            Self::coded(
                error.code(),
                format!("{}：{}", error.path.display(), error.diagnostic_message()),
            )
        }
    }

    fn network(error: crate::stdlib::NetworkError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            frames: Vec::new(),
            span: None,
        }
    }

    fn socket(error: crate::stdlib::SocketError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            frames: Vec::new(),
            span: None,
        }
    }

    fn bytes(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            frames: Vec::new(),
            span: None,
        }
    }

    fn category(&self) -> &'static str {
        if self.code.starts_with("NET_") {
            "网络"
        } else if self.code.starts_with("SOCKET_") {
            "套接字"
        } else if self.code.starts_with("BYTES_") {
            "字节"
        } else {
            "运行"
        }
    }

    fn with_frame(mut self, frame: impl Into<String>) -> Self {
        self.frames.push(frame.into());
        self
    }

    fn at(mut self, span: Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span);
        }
        self
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(span) = &self.span {
            write!(
                f,
                "{}",
                span.render("运行有误", &format!("[{}] {}", self.code, self.message))
            )?;
        } else {
            write!(f, "运行有误：[{}] {}", self.code, self.message)?;
        }
        for frame in &self.frames {
            write!(f, "\n  经 {frame}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone)]
pub struct Function {
    name: String,
    params: Vec<Parameter>,
    return_type: Option<TypeRef>,
    body: Vec<Stmt>,
    closure: EnvRef,
    module_dir: PathBuf,
    span: Span,
    owner_class: Option<TypeId>,
    is_async: bool,
}

struct FunctionDefinition<'a> {
    name: &'a str,
    params: &'a [Parameter],
    return_type: &'a Option<TypeRef>,
    body: &'a [Stmt],
    span: Span,
    is_async: bool,
}

impl Function {
    fn bind(&self, instance: Rc<RefCell<YanxuInstance>>, closure: EnvRef) -> Self {
        closure
            .borrow_mut()
            .define_unchecked("此".into(), Value::Instance(instance), false);
        Self {
            name: self.name.clone(),
            params: self.params.clone(),
            return_type: self.return_type.clone(),
            body: self.body.clone(),
            closure,
            module_dir: self.module_dir.clone(),
            span: self.span.clone(),
            owner_class: self.owner_class.clone(),
            is_async: self.is_async,
        }
    }
}

pub struct YanxuTask {
    state: YanxuTaskState,
}

enum YanxuTaskState {
    Pending {
        function: Rc<Function>,
        arguments: Vec<Value>,
    },
    Running,
    Completed(Value),
    Failed(RuntimeError),
    Cancelled,
}

impl YanxuTask {
    fn status(&self) -> &'static str {
        match self.state {
            YanxuTaskState::Pending { .. } => "待行",
            YanxuTaskState::Running => "运行",
            YanxuTaskState::Completed(_) => "完成",
            YanxuTaskState::Failed(_) => "失败",
            YanxuTaskState::Cancelled => "取消",
        }
    }
}

pub struct NativeFunction {
    name: &'static str,
    arity: usize,
    kind: NativeKind,
}

pub struct YanxuClass {
    name: String,
    type_id: TypeId,
    methods: HashMap<String, MethodSpec>,
    fields: HashMap<String, FieldSpec>,
    static_fields: RefCell<HashMap<String, Value>>,
    protocols: HashSet<TypeId>,
    superclass: Option<Rc<YanxuClass>>,
}

impl YanxuClass {
    fn method(&self, name: &str) -> Option<Rc<Function>> {
        self.method_spec(name)
            .filter(|method| !method.is_static)
            .map(|method| method.function.clone())
    }

    fn method_spec(&self, name: &str) -> Option<&MethodSpec> {
        self.methods.get(name).or_else(|| {
            self.superclass
                .as_ref()
                .and_then(|class| class.method_spec(name))
        })
    }

    fn field_spec(&self, name: &str) -> Option<&FieldSpec> {
        self.fields.get(name).or_else(|| {
            self.superclass
                .as_ref()
                .and_then(|class| class.field_spec(name))
        })
    }

    fn static_storage(&self, name: &str) -> Option<&RefCell<HashMap<String, Value>>> {
        if self.fields.get(name).is_some_and(|field| field.is_static) {
            Some(&self.static_fields)
        } else {
            self.superclass
                .as_ref()
                .and_then(|class| class.static_storage(name))
        }
    }

    fn has_instance_fields(&self) -> bool {
        self.fields.values().any(|field| !field.is_static)
            || self
                .superclass
                .as_ref()
                .is_some_and(|class| class.has_instance_fields())
    }

    fn is_a(&self, type_id: &TypeId) -> bool {
        &self.type_id == type_id
            || self.protocols.contains(type_id)
            || self
                .superclass
                .as_ref()
                .is_some_and(|class| class.is_a(type_id))
    }

    fn superclass_of(&self, owner: &TypeId) -> Option<Rc<YanxuClass>> {
        if &self.type_id == owner {
            self.superclass.clone()
        } else {
            self.superclass
                .as_ref()
                .and_then(|class| class.superclass_of(owner))
        }
    }

    fn initial_fields(&self) -> HashMap<String, Value> {
        let mut values = self
            .superclass
            .as_ref()
            .map_or_else(HashMap::new, |class| class.initial_fields());
        for (name, field) in &self.fields {
            if !field.is_static
                && let Some(initial) = &field.initial
            {
                values.insert(name.clone(), clone_field_value(initial));
            }
        }
        values
    }
}

pub struct YanxuProtocol {
    name: String,
    type_id: TypeId,
}

struct MethodSpec {
    function: Rc<Function>,
    visibility: Visibility,
    is_static: bool,
    owner: TypeId,
}

#[derive(Clone)]
struct FieldSpec {
    type_ref: TypeRef,
    visibility: Visibility,
    readonly: bool,
    is_static: bool,
    initial: Option<Value>,
    owner: TypeId,
    type_env: EnvRef,
}

pub struct YanxuInstance {
    class: Rc<YanxuClass>,
    fields: HashMap<String, Value>,
}

pub struct YanxuModule {
    name: String,
    module_id: ModuleId,
    environment: EnvRef,
    exports: HashSet<String>,
}

pub struct YanxuMap {
    entries: Vec<(Value, Value)>,
}

/// 所有 `逐` 循环与数据原语共用的惰性迭代状态。
///
/// 容器只保留其共享引用和当前位置；`映射`、`筛选`不会提前求值。
pub enum YanxuIterator {
    List {
        source: Rc<RefCell<Vec<Value>>>,
        index: usize,
    },
    Tuple {
        source: Rc<Vec<Value>>,
        index: usize,
    },
    String {
        source: Rc<Vec<char>>,
        index: usize,
    },
    MapKeys {
        source: Rc<RefCell<YanxuMap>>,
        index: usize,
    },
    Range {
        current: f64,
        end: f64,
        step: f64,
    },
    Object {
        source: Rc<RefCell<YanxuInstance>>,
    },
    Mapped {
        source: Rc<RefCell<YanxuIterator>>,
        mapper: Value,
    },
    Filtered {
        source: Rc<RefCell<YanxuIterator>>,
        predicate: Value,
    },
}

pub struct YanxuErrorValue {
    code: &'static str,
    category: String,
    message: String,
    frames: Vec<String>,
    span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct DebugVariable {
    pub name: String,
    pub value: String,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct DebugFrame {
    pub id: usize,
    pub name: String,
    pub span: Span,
    pub variables: Vec<DebugVariable>,
}

#[derive(Debug, Clone)]
pub struct DebugSnapshot {
    pub span: Span,
    pub frames: Vec<DebugFrame>,
}

pub trait DebugHook {
    /// 在语句执行前调用。返回错误可中止受调试程序。
    fn before_statement(&mut self, snapshot: &DebugSnapshot) -> Result<(), String>;
}

#[derive(Clone)]
struct Binding {
    value: Value,
    type_ref: Option<TypeRef>,
    type_env: Option<Weak<RefCell<Environment>>>,
    mutable: bool,
}

#[derive(Default)]
struct Environment {
    values: HashMap<String, Binding>,
    enclosing: Option<EnvRef>,
}

impl Environment {
    fn child(enclosing: EnvRef) -> EnvRef {
        Rc::new(RefCell::new(Self {
            values: HashMap::new(),
            enclosing: Some(enclosing),
        }))
    }

    fn define_typed(
        &mut self,
        name: String,
        value: Value,
        type_ref: Option<TypeRef>,
        type_env: Weak<RefCell<Environment>>,
        mutable: bool,
    ) {
        self.values.insert(
            name,
            Binding {
                value,
                type_ref,
                type_env: Some(type_env),
                mutable,
            },
        );
    }

    fn define_unchecked(&mut self, name: String, value: Value, mutable: bool) {
        self.values.insert(
            name,
            Binding {
                value,
                type_ref: None,
                type_env: None,
                mutable,
            },
        );
    }

    fn get(&self, name: &str) -> Result<Value, RuntimeError> {
        if let Some(binding) = self.values.get(name) {
            return Ok(binding.value.clone());
        }
        if let Some(enclosing) = &self.enclosing {
            return enclosing.borrow().get(name);
        }
        Err(RuntimeError::new(format!("未曾定义“{name}”")))
    }

    fn get_local(&self, name: &str) -> Option<Value> {
        self.values.get(name).map(|binding| binding.value.clone())
    }
}

fn debug_variables(environment: &EnvRef) -> Vec<DebugVariable> {
    let mut variables = HashMap::<String, DebugVariable>::new();
    let mut current = Some(environment.clone());
    while let Some(scope) = current {
        let borrowed = scope.borrow();
        for (name, binding) in &borrowed.values {
            variables
                .entry(name.clone())
                .or_insert_with(|| DebugVariable {
                    name: name.clone(),
                    value: debug_value(&binding.value),
                    type_name: binding.value.type_name(),
                });
        }
        current = borrowed.enclosing.clone();
    }
    let mut variables = variables.into_values().collect::<Vec<_>>();
    variables.sort_by(|left, right| left.name.cmp(&right.name));
    variables
}

fn debug_value(value: &Value) -> String {
    match value {
        Value::List(items) => format!("<列，{} 项>", items.borrow().len()),
        Value::Tuple(items) => format!("<元，{} 项>", items.len()),
        Value::Map(map) => format!("<典，{} 项>", map.borrow().entries.len()),
        Value::Iterator(_) => "<遍器>".into(),
        Value::Class(class) => format!("<类 {}>", class.type_id),
        Value::Protocol(protocol) => format!("<协 {}>", protocol.type_id),
        Value::Instance(instance) => {
            format!("<{}之实例>", instance.borrow().class.type_id)
        }
        Value::Module(module) => format!("<模块 {}>", module.module_id),
        value => value.to_string(),
    }
}

#[derive(Default)]
struct InterpreterMarks {
    environments: HashSet<usize>,
    objects: HashSet<(u8, usize)>,
}

impl InterpreterMarks {
    fn visit<T>(&mut self, kind: u8, object: *const T) -> bool {
        self.objects.insert((kind, object as usize))
    }
}

fn mark_interpreter_environment(environment: &EnvRef, marks: &mut InterpreterMarks) {
    let id = Rc::as_ptr(environment) as usize;
    if !marks.environments.insert(id) {
        return;
    }
    let environment = environment.borrow();
    if let Some(enclosing) = &environment.enclosing {
        mark_interpreter_environment(enclosing, marks);
    }
    for binding in environment.values.values() {
        mark_interpreter_value(&binding.value, marks);
    }
}

fn mark_interpreter_function(function: &Rc<Function>, marks: &mut InterpreterMarks) {
    if marks.visit(1, Rc::as_ptr(function)) {
        mark_interpreter_environment(&function.closure, marks);
    }
}

fn mark_interpreter_class(class: &Rc<YanxuClass>, marks: &mut InterpreterMarks) {
    if !marks.visit(2, Rc::as_ptr(class)) {
        return;
    }
    if let Some(superclass) = &class.superclass {
        mark_interpreter_class(superclass, marks);
    }
    for method in class.methods.values() {
        mark_interpreter_function(&method.function, marks);
    }
    for field in class.fields.values() {
        mark_interpreter_environment(&field.type_env, marks);
        if let Some(initial) = &field.initial {
            mark_interpreter_value(initial, marks);
        }
    }
    for value in class.static_fields.borrow().values() {
        mark_interpreter_value(value, marks);
    }
}

fn mark_interpreter_value(value: &Value, marks: &mut InterpreterMarks) {
    match value {
        Value::Function(function) => mark_interpreter_function(function, marks),
        Value::Class(class) => mark_interpreter_class(class, marks),
        Value::Instance(instance) => {
            if !marks.visit(3, Rc::as_ptr(instance)) {
                return;
            }
            let instance = instance.borrow();
            mark_interpreter_class(&instance.class, marks);
            for value in instance.fields.values() {
                mark_interpreter_value(value, marks);
            }
        }
        Value::Module(module) => mark_interpreter_environment(&module.environment, marks),
        Value::List(items) => {
            if !marks.visit(4, Rc::as_ptr(items)) {
                return;
            }
            for value in items.borrow().iter() {
                mark_interpreter_value(value, marks);
            }
        }
        Value::Tuple(items) => {
            if !marks.visit(5, Rc::as_ptr(items)) {
                return;
            }
            for value in items.iter() {
                mark_interpreter_value(value, marks);
            }
        }
        Value::Map(map) => {
            if !marks.visit(6, Rc::as_ptr(map)) {
                return;
            }
            for (key, value) in &map.borrow().entries {
                mark_interpreter_value(key, marks);
                mark_interpreter_value(value, marks);
            }
        }
        Value::Iterator(iterator) => {
            if !marks.visit(7, Rc::as_ptr(iterator)) {
                return;
            }
            match &*iterator.borrow() {
                YanxuIterator::List { source, .. } => {
                    mark_interpreter_value(&Value::List(source.clone()), marks)
                }
                YanxuIterator::Tuple { source, .. } => {
                    mark_interpreter_value(&Value::Tuple(source.clone()), marks)
                }
                YanxuIterator::MapKeys { source, .. } => {
                    mark_interpreter_value(&Value::Map(source.clone()), marks)
                }
                YanxuIterator::Object { source } => {
                    mark_interpreter_value(&Value::Instance(source.clone()), marks)
                }
                YanxuIterator::Mapped { source, mapper } => {
                    mark_interpreter_value(&Value::Iterator(source.clone()), marks);
                    mark_interpreter_value(mapper, marks);
                }
                YanxuIterator::Filtered { source, predicate } => {
                    mark_interpreter_value(&Value::Iterator(source.clone()), marks);
                    mark_interpreter_value(predicate, marks);
                }
                YanxuIterator::String { .. } | YanxuIterator::Range { .. } => {}
            }
        }
        Value::Task(task) => {
            if !marks.visit(8, Rc::as_ptr(task)) {
                return;
            }
            match &task.borrow().state {
                YanxuTaskState::Pending {
                    function,
                    arguments,
                } => {
                    mark_interpreter_function(function, marks);
                    for value in arguments {
                        mark_interpreter_value(value, marks);
                    }
                }
                YanxuTaskState::Completed(value) => mark_interpreter_value(value, marks),
                YanxuTaskState::Running | YanxuTaskState::Failed(_) | YanxuTaskState::Cancelled => {
                }
            }
        }
        Value::Number(_)
        | Value::String(_)
        | Value::Bytes(_)
        | Value::Bool(_)
        | Value::Nil
        | Value::Native(_)
        | Value::Protocol(_)
        | Value::Error(_)
        | Value::Socket(_) => {}
    }
}

pub struct Interpreter {
    globals: EnvRef,
    heap_environments: Vec<Weak<RefCell<Environment>>>,
    output: Vec<String>,
    echo: bool,
    current_dir: PathBuf,
    package_root: Option<PathBuf>,
    package_module_roots: crate::package::TrustedPackageRoots,
    module_cache: HashMap<PathBuf, Rc<YanxuModule>>,
    loading_modules: Vec<PathBuf>,
    initialization_order: Vec<PathBuf>,
    tracing: bool,
    trace: Vec<String>,
    access_classes: Vec<TypeId>,
    current_module_id: ModuleId,
    debug_hook: Option<Box<dyn DebugHook>>,
    debug_frames: Vec<ActiveDebugFrame>,
    permissions: crate::permissions::PermissionSet,
    socket_quota: crate::stdlib::SocketQuota,
    resources: crate::budget::ResourceMeter,
    arguments: Vec<String>,
}

struct ActiveDebugFrame {
    name: String,
    span: Span,
    environment: EnvRef,
}

enum Control {
    Continue(Value),
    Return(Value),
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Interpreter {
    fn drop(&mut self) {
        self.debug_frames.clear();
        self.module_cache.clear();
        let environments = self
            .heap_environments
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        for environment in environments {
            let mut environment = environment.borrow_mut();
            environment.values.clear();
            environment.enclosing = None;
        }
    }
}

impl Interpreter {
    pub fn new() -> Self {
        Self::with_echo(true)
    }

    pub fn silent() -> Self {
        Self::with_echo(false)
    }

    pub fn with_permissions(permissions: crate::permissions::PermissionSet) -> Self {
        let mut interpreter = Self::with_echo(true);
        interpreter.permissions = permissions;
        interpreter
    }

    pub fn silent_with_permissions(permissions: crate::permissions::PermissionSet) -> Self {
        let mut interpreter = Self::with_echo(false);
        interpreter.permissions = permissions;
        interpreter
    }

    pub fn set_permissions(&mut self, permissions: crate::permissions::PermissionSet) {
        self.permissions = permissions;
    }

    pub fn debug() -> Self {
        let mut interpreter = Self::with_echo(true);
        interpreter.tracing = true;
        interpreter
    }

    fn with_echo(echo: bool) -> Self {
        let globals = Rc::new(RefCell::new(Environment::default()));
        define_native(&globals, "时刻", 0, native_clock);
        define_native(&globals, "长度", 1, native_length);
        define_native(&globals, "类型", 1, native_type);
        define_intrinsic(&globals, "追加", 2, NativeKind::Append);
        define_native(&globals, "弹出", 1, native_pop);
        define_native(&globals, "有键", 2, native_has_key);
        define_intrinsic(&globals, "插入", 3, NativeKind::Insert);
        define_native(&globals, "删除", 2, native_remove);
        define_native(&globals, "键列", 1, native_keys);
        define_native(&globals, "值列", 1, native_values);
        define_intrinsic(&globals, "遍", 1, NativeKind::Iterator);
        define_intrinsic(&globals, "续", 1, NativeKind::Next);
        define_intrinsic(&globals, "范围", 2, NativeKind::Range);
        define_intrinsic(&globals, "步进范围", 3, NativeKind::SteppedRange);
        define_intrinsic(&globals, "映射", 2, NativeKind::Map);
        define_intrinsic(&globals, "筛选", 2, NativeKind::Filter);
        define_intrinsic(&globals, "折叠", 3, NativeKind::Fold);
        define_intrinsic(&globals, "排序", 1, NativeKind::Sort);
        define_intrinsic(&globals, "反转", 1, NativeKind::Reverse);
        define_intrinsic(&globals, "包含", 2, NativeKind::Contains);
        define_intrinsic(&globals, "寻找", 2, NativeKind::Find);
        define_intrinsic(&globals, "取消", 1, NativeKind::CancelTask);
        define_intrinsic(&globals, "任务状态", 1, NativeKind::TaskStatus);
        define_intrinsic(&globals, "并候", 1, NativeKind::JoinTasks);
        Self {
            globals: globals.clone(),
            heap_environments: vec![Rc::downgrade(&globals)],
            output: Vec::new(),
            echo,
            current_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            package_root: None,
            package_module_roots: crate::package::TrustedPackageRoots::default(),
            module_cache: HashMap::new(),
            loading_modules: Vec::new(),
            initialization_order: Vec::new(),
            tracing: false,
            trace: Vec::new(),
            access_classes: Vec::new(),
            current_module_id: ModuleId::for_source("<文句>"),
            debug_hook: None,
            debug_frames: Vec::new(),
            permissions: crate::permissions::PermissionSet::unrestricted(),
            socket_quota: crate::stdlib::SocketQuota::default(),
            resources: crate::budget::ResourceMeter::new(crate::budget::ExecutionBudget::default()),
            arguments: Vec::new(),
        }
    }

    pub fn set_arguments(&mut self, arguments: Vec<String>) {
        self.arguments = arguments;
    }

    pub fn set_budget(&mut self, budget: crate::budget::ExecutionBudget) {
        self.resources.set_budget(budget);
    }

    pub(crate) fn set_host_resource_limits(&mut self, limits: crate::budget::HostResourceLimits) {
        self.resources.set_host_limits(limits);
    }

    pub fn budget(&self) -> crate::budget::ExecutionBudget {
        self.resources.budget()
    }

    pub fn set_debug_hook(&mut self, hook: Box<dyn DebugHook>) {
        self.debug_hook = Some(hook);
    }

    pub fn clear_debug_hook(&mut self) {
        self.debug_hook = None;
        self.debug_frames.clear();
    }

    pub fn execute(&mut self, statements: &[Stmt]) -> Result<Value, RuntimeError> {
        self.execute_at(statements, None)
    }

    pub fn execute_in_directory(
        &mut self,
        statements: &[Stmt],
        directory: &Path,
    ) -> Result<Value, RuntimeError> {
        self.execute_at(statements, Some(directory))
    }

    fn execute_at(
        &mut self,
        statements: &[Stmt],
        directory: Option<&Path>,
    ) -> Result<Value, RuntimeError> {
        self.resources.reset();
        let execution_directory = directory.map(|directory| {
            let absolute = if directory.is_absolute() {
                directory.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(directory)
            };
            fs::canonicalize(&absolute).unwrap_or(absolute)
        });
        let package_root = execution_directory
            .as_deref()
            .map(|directory| crate::package::discover(directory).map_err(RuntimeError::package))
            .transpose()?
            .flatten()
            .map(|manifest| {
                fs::canonicalize(&manifest.root).map_err(|error| {
                    RuntimeError::new(format!(
                        "不能定位包根目录“{}”：{error}",
                        manifest.root.display()
                    ))
                })
            })
            .transpose()?;
        let mut package_module_roots = crate::package::TrustedPackageRoots::default();
        if let Some(root) = &package_root {
            package_module_roots
                .insert(root)
                .map_err(RuntimeError::package_path)?;
        }
        let module_id = statements
            .first()
            .map(|statement| ModuleId::for_source(&statement.span.source.name))
            .unwrap_or_else(|| ModuleId::for_source("<空模块>"));
        let previous_module_id = std::mem::replace(&mut self.current_module_id, module_id);
        let previous = execution_directory
            .map(|directory| std::mem::replace(&mut self.current_dir, directory));
        let previous_package_root =
            directory.map(|_| std::mem::replace(&mut self.package_root, package_root));
        let previous_package_module_roots = directory
            .map(|_| std::mem::replace(&mut self.package_module_roots, package_module_roots));
        let owns_debug_frame = self.debug_hook.is_some() && self.debug_frames.is_empty();
        if owns_debug_frame {
            self.debug_frames.push(ActiveDebugFrame {
                name: "<顶层>".into(),
                span: statements
                    .first()
                    .map_or_else(Span::synthetic, |statement| statement.span.clone()),
                environment: self.globals.clone(),
            });
        }
        let result = match self.execute_statements(statements, self.globals.clone()) {
            Ok(Control::Continue(value)) => Ok(value),
            Ok(Control::Return(_)) => Err(RuntimeError::new("“归”只能用于法之内")),
            Err(error) => Err(error),
        };
        if owns_debug_frame {
            self.debug_frames.pop();
        }
        if let Some(previous) = previous {
            self.current_dir = previous;
        }
        if let Some(previous) = previous_package_root {
            self.package_root = previous;
        }
        if let Some(previous) = previous_package_module_roots {
            self.package_module_roots = previous;
        }
        self.current_module_id = previous_module_id;
        self.collect_garbage(result.as_ref().ok());
        result
    }

    fn child_env(&mut self, enclosing: EnvRef) -> EnvRef {
        let environment = Environment::child(enclosing);
        self.heap_environments.push(Rc::downgrade(&environment));
        environment
    }

    fn bind_function(
        &mut self,
        function: &Function,
        instance: Rc<RefCell<YanxuInstance>>,
    ) -> Function {
        let closure = self.child_env(function.closure.clone());
        function.bind(instance, closure)
    }

    fn collect_garbage(&mut self, result: Option<&Value>) {
        let mut marks = InterpreterMarks::default();
        mark_interpreter_environment(&self.globals, &mut marks);
        for module in self.module_cache.values() {
            mark_interpreter_environment(&module.environment, &mut marks);
        }
        for frame in &self.debug_frames {
            mark_interpreter_environment(&frame.environment, &mut marks);
        }
        if let Some(result) = result {
            mark_interpreter_value(result, &mut marks);
        }

        let unreachable = self
            .heap_environments
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|environment| {
                !marks
                    .environments
                    .contains(&(Rc::as_ptr(environment) as usize))
            })
            .collect::<Vec<_>>();
        for environment in &unreachable {
            let mut environment = environment.borrow_mut();
            environment.values.clear();
            environment.enclosing = None;
        }
        drop(unreachable);
        self.heap_environments
            .retain(|environment| environment.strong_count() > 0);
    }

    pub fn output(&self) -> &[String] {
        &self.output
    }

    pub fn take_output(&mut self) -> Vec<String> {
        std::mem::take(&mut self.output)
    }

    pub fn trace(&self) -> &[String] {
        &self.trace
    }

    pub fn module_initialization_order(&self) -> &[PathBuf] {
        &self.initialization_order
    }

    fn execute_statements(
        &mut self,
        statements: &[Stmt],
        env: EnvRef,
    ) -> Result<Control, RuntimeError> {
        let mut last = Value::Nil;
        for statement in statements {
            match self.execute_statement(statement, env.clone())? {
                Control::Continue(value) => last = value,
                returned @ Control::Return(_) => return Ok(returned),
            }
        }
        Ok(Control::Continue(last))
    }

    fn execute_statement(
        &mut self,
        statement: &Stmt,
        env: EnvRef,
    ) -> Result<Control, RuntimeError> {
        self.resources
            .charge_step()
            .map_err(RuntimeError::new)
            .map_err(|error| error.at(statement.span.clone()))?;
        self.debug_before(statement, env.clone())?;
        if self.tracing {
            self.trace.push(format!(
                "{} @ {}",
                statement_name(&statement.kind),
                statement.span
            ));
        }
        self.execute_statement_inner(statement, env)
            .map_err(|error| error.at(statement.span.clone()))
    }

    fn debug_before(&mut self, statement: &Stmt, environment: EnvRef) -> Result<(), RuntimeError> {
        if self.debug_hook.is_none() {
            return Ok(());
        }
        if let Some(frame) = self.debug_frames.last_mut() {
            frame.span = statement.span.clone();
            frame.environment = environment;
        }
        let snapshot = self.debug_snapshot(&statement.span);
        let mut hook = self.debug_hook.take().expect("hook checked above");
        let result = hook
            .before_statement(&snapshot)
            .map_err(RuntimeError::new)
            .map_err(|error| error.at(statement.span.clone()));
        self.debug_hook = Some(hook);
        result
    }

    fn debug_snapshot(&self, span: &Span) -> DebugSnapshot {
        let frames = self
            .debug_frames
            .iter()
            .rev()
            .enumerate()
            .map(|(index, frame)| DebugFrame {
                id: index + 1,
                name: frame.name.clone(),
                span: frame.span.clone(),
                variables: debug_variables(&frame.environment),
            })
            .collect();
        DebugSnapshot {
            span: span.clone(),
            frames,
        }
    }

    fn execute_statement_inner(
        &mut self,
        statement: &Stmt,
        env: EnvRef,
    ) -> Result<Control, RuntimeError> {
        match &statement.kind {
            StmtKind::Let {
                name,
                type_ref,
                value,
                mutable,
            } => {
                let value = self.evaluate(value, env.clone())?;
                self.define_variable(env, name.clone(), value.clone(), type_ref.clone(), *mutable)?;
                Ok(Control::Continue(value))
            }
            StmtKind::Set { target, value } => {
                let result = match &target.kind {
                    ExprKind::Variable(name) => {
                        let value = self.evaluate(value, env.clone())?;
                        self.assign_variable(env, name, value.clone())?;
                        value
                    }
                    ExprKind::Get { object, name } => {
                        let object = self.evaluate(object, env.clone())?;
                        let value = self.evaluate(value, env.clone())?;
                        self.set_property(object, name, value.clone(), env)?;
                        value
                    }
                    ExprKind::Index { object, index } => {
                        let object = self.evaluate(object, env.clone())?;
                        let index = self.evaluate(index, env.clone())?;
                        let value = self.evaluate(value, env)?;
                        self.set_index(object, index, value.clone())?;
                        value
                    }
                    _ => unreachable!("parser only permits assignable targets"),
                };
                Ok(Control::Continue(result))
            }
            StmtKind::Print(expr) => {
                let value = self.evaluate(expr, env)?;
                let line = value.to_string();
                if self.echo {
                    println!("{line}");
                }
                self.output.push(line);
                Ok(Control::Continue(value))
            }
            StmtKind::Expression(expr) => self.evaluate(expr, env).map(Control::Continue),
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                if self.evaluate(condition, env.clone())?.truthy() {
                    let branch_env = self.child_env(env);
                    self.execute_statements(then_branch, branch_env)
                } else {
                    let branch_env = self.child_env(env);
                    self.execute_statements(else_branch, branch_env)
                }
            }
            StmtKind::While { condition, body } => {
                while self.evaluate(condition, env.clone())?.truthy() {
                    let body_env = self.child_env(env.clone());
                    if let returned @ Control::Return(_) =
                        self.execute_statements(body, body_env)?
                    {
                        return Ok(returned);
                    }
                }
                Ok(Control::Continue(Value::Nil))
            }
            StmtKind::For {
                name,
                type_ref,
                iterable,
                body,
            } => {
                let iterable = self.evaluate(iterable, env.clone())?;
                let iterator = self.make_iterator(iterable)?;
                while let Some(item) = self.next_iterator(&iterator)? {
                    let iteration_env = self.child_env(env.clone());
                    self.define_variable(
                        iteration_env.clone(),
                        name.clone(),
                        item,
                        type_ref.clone(),
                        false,
                    )?;
                    if let returned @ Control::Return(_) =
                        self.execute_statements(body, iteration_env)?
                    {
                        return Ok(returned);
                    }
                }
                Ok(Control::Continue(Value::Nil))
            }
            StmtKind::Function {
                name,
                params,
                return_type,
                body,
                is_async,
            } => {
                let function = self.make_function(
                    FunctionDefinition {
                        name,
                        params,
                        return_type,
                        body,
                        span: statement.span.clone(),
                        is_async: *is_async,
                    },
                    env.clone(),
                );
                let value = Value::Function(Rc::new(function));
                env.borrow_mut()
                    .define_unchecked(name.clone(), value.clone(), false);
                Ok(Control::Continue(value))
            }
            StmtKind::Class {
                name,
                superclass,
                protocols,
                fields,
                methods,
            } => {
                let class_id = TypeId::new(
                    self.current_module_id.clone(),
                    name,
                    TypeDeclarationKind::Class,
                );
                let superclass = superclass
                    .as_ref()
                    .map(
                        |parent| match self.resolve_type_path(env.clone(), parent)? {
                            Value::Class(class) => Ok(class),
                            value => Err(RuntimeError::new(format!(
                                "“{parent}”为{}，不可作父类",
                                value.type_name()
                            ))),
                        },
                    )
                    .transpose()?;
                let protocol_names = protocols
                    .iter()
                    .map(
                        |protocol| match self.resolve_type_path(env.clone(), protocol)? {
                            Value::Protocol(protocol) => Ok(protocol.type_id.clone()),
                            value => Err(RuntimeError::new(format!(
                                "“{protocol}”为{}，不可作为协",
                                value.type_name()
                            ))),
                        },
                    )
                    .collect::<Result<HashSet<_>, _>>()?;
                let mut method_map = HashMap::new();
                for method in methods {
                    let StmtKind::Function {
                        name: method_name,
                        params,
                        return_type,
                        body,
                        is_async,
                    } = &method.kind
                    else {
                        unreachable!("class body only contains methods")
                    };
                    let mut function = self.make_function(
                        FunctionDefinition {
                            name: method_name,
                            params,
                            return_type,
                            body,
                            span: method.span.clone(),
                            is_async: *is_async,
                        },
                        env.clone(),
                    );
                    function.owner_class = Some(class_id.clone());
                    method_map.insert(
                        method_name.clone(),
                        MethodSpec {
                            function: Rc::new(function),
                            visibility: method.member_visibility,
                            is_static: method.is_static,
                            owner: class_id.clone(),
                        },
                    );
                }
                let mut field_map = HashMap::new();
                let mut static_fields = HashMap::new();
                for field in fields {
                    let initial = field
                        .initial
                        .as_ref()
                        .map(|initial| self.evaluate(initial, env.clone()))
                        .transpose()?;
                    if let Some(initial) = &initial {
                        self.ensure_type(
                            &format!("域“{}”", field.name),
                            Some(&field.type_ref),
                            initial,
                            env.clone(),
                        )?;
                    }
                    if field.is_static
                        && let Some(initial) = &initial
                    {
                        static_fields.insert(field.name.clone(), initial.clone());
                    }
                    field_map.insert(
                        field.name.clone(),
                        FieldSpec {
                            type_ref: field.type_ref.clone(),
                            visibility: field.visibility,
                            readonly: field.readonly,
                            is_static: field.is_static,
                            initial,
                            owner: class_id.clone(),
                            type_env: env.clone(),
                        },
                    );
                }
                let class = Value::Class(Rc::new(YanxuClass {
                    name: name.clone(),
                    type_id: class_id,
                    methods: method_map,
                    fields: field_map,
                    static_fields: RefCell::new(static_fields),
                    protocols: protocol_names,
                    superclass,
                }));
                env.borrow_mut()
                    .define_unchecked(name.clone(), class.clone(), false);
                Ok(Control::Continue(class))
            }
            StmtKind::Protocol { name, .. } => {
                let protocol = Value::Protocol(Rc::new(YanxuProtocol {
                    name: name.clone(),
                    type_id: TypeId::new(
                        self.current_module_id.clone(),
                        name,
                        TypeDeclarationKind::Protocol,
                    ),
                }));
                env.borrow_mut()
                    .define_unchecked(name.clone(), protocol.clone(), false);
                Ok(Control::Continue(protocol))
            }
            StmtKind::Import { path, alias } => {
                let module = self.load_module(path)?;
                let value = Value::Module(module);
                env.borrow_mut()
                    .define_unchecked(alias.clone(), value.clone(), false);
                Ok(Control::Continue(value))
            }
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                let try_env = self.child_env(env.clone());
                match self.execute_statements(try_branch, try_env) {
                    Ok(control) => Ok(control),
                    Err(error) => {
                        let catch_env = self.child_env(env);
                        let error_value = Value::Error(Rc::new(YanxuErrorValue {
                            code: error.code,
                            category: error.category().into(),
                            message: error.message,
                            frames: error.frames,
                            span: error.span,
                        }));
                        catch_env.borrow_mut().define_unchecked(
                            error_name.clone(),
                            error_value,
                            false,
                        );
                        self.execute_statements(catch_branch, catch_env)
                    }
                }
            }
            StmtKind::Throw(expr) => {
                let value = self.evaluate(expr, env)?;
                match value {
                    Value::Error(error) => Err(RuntimeError {
                        code: error.code,
                        message: error.message.clone(),
                        frames: error.frames.clone(),
                        span: error.span.clone(),
                    }),
                    value => Err(RuntimeError::new(value.to_string())),
                }
            }
            StmtKind::Return(expr) => {
                let value = match expr {
                    Some(expr) => self.evaluate(expr, env)?,
                    None => Value::Nil,
                };
                Ok(Control::Return(value))
            }
        }
    }

    fn make_function(&self, definition: FunctionDefinition<'_>, closure: EnvRef) -> Function {
        Function {
            name: definition.name.into(),
            params: definition.params.to_vec(),
            return_type: definition.return_type.clone(),
            body: definition.body.to_vec(),
            closure,
            module_dir: self.current_dir.clone(),
            span: definition.span,
            owner_class: None,
            is_async: definition.is_async,
        }
    }

    fn evaluate(&mut self, expr: &Expr, env: EnvRef) -> Result<Value, RuntimeError> {
        self.resources
            .charge_step()
            .map_err(RuntimeError::new)
            .map_err(|error| error.at(expr.span.clone()))?;
        let value = self
            .evaluate_inner(expr, env)
            .map_err(|error| error.at(expr.span.clone()))?;
        self.ensure_value_budget(&value)
            .map_err(|error| error.at(expr.span.clone()))?;
        Ok(value)
    }

    fn evaluate_inner(&mut self, expr: &Expr, env: EnvRef) -> Result<Value, RuntimeError> {
        match &expr.kind {
            ExprKind::Literal(literal) => Ok(match literal {
                Literal::Number(value) => Value::Number(*value),
                Literal::String(value) => Value::String(value.clone()),
                Literal::Bool(value) => Value::Bool(*value),
                Literal::Nil => Value::Nil,
            }),
            ExprKind::Variable(name) => env.borrow().get(name),
            ExprKind::This => env.borrow().get("此"),
            ExprKind::Super { method } => {
                let Value::Instance(instance) = env.borrow().get("此")? else {
                    return Err(RuntimeError::new("“父”只可用于实例法"));
                };
                let owner = self
                    .access_classes
                    .last()
                    .ok_or_else(|| RuntimeError::new("“父”只可用于类之法内"))?;
                let parent = instance
                    .borrow()
                    .class
                    .superclass_of(owner)
                    .ok_or_else(|| RuntimeError::new(format!("类“{owner}”没有父类")))?;
                let spec = parent.method_spec(method).ok_or_else(|| {
                    RuntimeError::new(format!("父类“{}”无方法“{method}”", parent.name))
                })?;
                if spec.is_static {
                    return Err(RuntimeError::new(format!(
                        "父类方法“{method}”乃静法，不可绑定此实例"
                    )));
                }
                if spec.visibility == Visibility::Private && spec.owner != *owner {
                    return Err(RuntimeError::new(format!(
                        "父类私法“{method}”不可由子类调用"
                    )));
                }
                Ok(Value::Function(Rc::new(
                    self.bind_function(&spec.function, instance),
                )))
            }
            ExprKind::List(items) => {
                let values = items
                    .iter()
                    .map(|item| self.evaluate(item, env.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::List(Rc::new(RefCell::new(values))))
            }
            ExprKind::Tuple(items) => {
                let values = items
                    .iter()
                    .map(|item| self.evaluate(item, env.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::Tuple(Rc::new(values)))
            }
            ExprKind::Map(entries) => {
                let mut map = YanxuMap {
                    entries: Vec::new(),
                };
                for (key, value) in entries {
                    let key = self.evaluate(key, env.clone())?;
                    let value = self.evaluate(value, env.clone())?;
                    map_insert(&mut map, key, value)?;
                }
                Ok(Value::Map(Rc::new(RefCell::new(map))))
            }
            ExprKind::Unary { operator, right } => {
                let right = self.evaluate(right, env)?;
                match operator {
                    TokenKind::Bang | TokenKind::Not => Ok(Value::Bool(!right.truthy())),
                    TokenKind::Minus => match right {
                        Value::Number(number) => Ok(Value::Number(-number)),
                        value => Err(RuntimeError::new(format!(
                            "不可求负于{}",
                            value.type_name()
                        ))),
                    },
                    _ => unreachable!("parser only creates valid unary operators"),
                }
            }
            ExprKind::Binary {
                left,
                operator,
                right,
            } => {
                let left = self.evaluate(left, env.clone())?;
                if matches!(operator, TokenKind::Or) && left.truthy() {
                    return Ok(left);
                }
                if matches!(operator, TokenKind::And) && !left.truthy() {
                    return Ok(left);
                }
                let right = self.evaluate(right, env)?;
                self.binary(left, operator, right)
            }
            ExprKind::TypeTest { value, type_ref } => {
                let value = self.evaluate(value, env.clone())?;
                Ok(Value::Bool(self.value_matches_type(
                    &value,
                    &type_ref.kind,
                    env,
                )?))
            }
            ExprKind::Call { callee, arguments } => {
                let callee = self.evaluate(callee, env.clone())?;
                let arguments = arguments
                    .iter()
                    .map(|argument| self.evaluate(argument, env.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                self.call(callee, arguments)
            }
            ExprKind::Get { object, name } => {
                let object = self.evaluate(object, env)?;
                self.get_property(object, name)
            }
            ExprKind::Index { object, index } => {
                let object = self.evaluate(object, env.clone())?;
                let index = self.evaluate(index, env)?;
                self.get_index(object, index)
            }
            ExprKind::Slice { object, start, end } => {
                let object = self.evaluate(object, env.clone())?;
                let start = start
                    .as_deref()
                    .map(|start| self.evaluate(start, env.clone()))
                    .transpose()?;
                let end = end
                    .as_deref()
                    .map(|end| self.evaluate(end, env))
                    .transpose()?;
                self.get_slice(object, start, end)
            }
            ExprKind::Await { task } => {
                let task = self.evaluate(task, env)?;
                let Value::Task(task) = task else {
                    return Err(RuntimeError::new(format!(
                        "“候”须收任务，不可收{}",
                        task.type_name()
                    )));
                };
                self.await_task(&task)
            }
        }
    }

    fn binary(
        &self,
        left: Value,
        operator: &TokenKind,
        right: Value,
    ) -> Result<Value, RuntimeError> {
        match operator {
            TokenKind::EqualEqual => Ok(Value::Bool(values_equal(&left, &right))),
            TokenKind::BangEqual => Ok(Value::Bool(!values_equal(&left, &right))),
            TokenKind::Plus => match (left, right) {
                (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
                (Value::String(a), Value::String(b)) => Ok(Value::String(a + &b)),
                (a, b) => Err(type_pair_error("相加", &a, &b)),
            },
            TokenKind::Minus => numeric_pair(left, right, "相减", |a, b| a - b),
            TokenKind::Star => numeric_pair(left, right, "相乘", |a, b| a * b),
            TokenKind::Slash => {
                if matches!(right, Value::Number(0.0)) {
                    return Err(RuntimeError::new("不可除以零"));
                }
                numeric_pair(left, right, "相除", |a, b| a / b)
            }
            TokenKind::Greater => compare_pair(left, right, "比较", |a, b| a > b),
            TokenKind::GreaterEqual => compare_pair(left, right, "比较", |a, b| a >= b),
            TokenKind::Less => compare_pair(left, right, "比较", |a, b| a < b),
            TokenKind::LessEqual => compare_pair(left, right, "比较", |a, b| a <= b),
            TokenKind::And | TokenKind::Or => Ok(right),
            _ => unreachable!("parser only creates valid binary operators"),
        }
    }

    fn call(&mut self, callee: Value, arguments: Vec<Value>) -> Result<Value, RuntimeError> {
        match callee {
            Value::Function(function) if function.is_async => {
                if arguments.len() != function.params.len() {
                    return Err(arity_error(
                        &function.name,
                        function.params.len(),
                        arguments.len(),
                    ));
                }
                Ok(Value::Task(Rc::new(RefCell::new(YanxuTask {
                    state: YanxuTaskState::Pending {
                        function,
                        arguments,
                    },
                }))))
            }
            Value::Function(function) => self.call_function(&function, arguments),
            Value::Native(function) => {
                if arguments.len() != function.arity {
                    return Err(arity_error(function.name, function.arity, arguments.len()));
                }
                self.call_native(function.kind, &arguments)
                    .map_err(|error| error.with_frame(format!("天授之法“{}”", function.name)))
            }
            Value::Class(class) => {
                let instance = Rc::new(RefCell::new(YanxuInstance {
                    class: class.clone(),
                    fields: class.initial_fields(),
                }));
                if let Some(initializer) = class.method("初始化") {
                    let bound = self.bind_function(&initializer, instance.clone());
                    if bound.is_async {
                        return Err(RuntimeError::new("初始化不可为异法"));
                    }
                    self.call_function(&bound, arguments)?;
                } else if !arguments.is_empty() {
                    return Err(arity_error(&class.name, 0, arguments.len()));
                }
                Ok(Value::Instance(instance))
            }
            value => Err(RuntimeError::new(format!("{}不可调用", value.type_name()))),
        }
    }

    fn call_native(
        &mut self,
        kind: NativeKind,
        arguments: &[Value],
    ) -> Result<Value, RuntimeError> {
        match kind {
            NativeKind::Plain(body) => body(arguments),
            NativeKind::Guarded(function) => self.call_guarded_native(function, arguments),
            NativeKind::Append => match &arguments[0] {
                Value::List(items) => {
                    self.resources
                        .check_collection(items.borrow().len().saturating_add(1))
                        .map_err(RuntimeError::new)?;
                    items.borrow_mut().push(arguments[1].clone());
                    Ok(arguments[0].clone())
                }
                value => Err(RuntimeError::new(format!(
                    "“追加”不适用于{}",
                    value.type_name()
                ))),
            },
            NativeKind::Insert => match &arguments[0] {
                Value::List(items) => {
                    let index = list_index(&arguments[1])?;
                    let mut items = items.borrow_mut();
                    if index > items.len() {
                        return Err(RuntimeError::new(format!("列下标 {index} 超出可插入范围")));
                    }
                    self.resources
                        .check_collection(items.len().saturating_add(1))
                        .map_err(RuntimeError::new)?;
                    items.insert(index, arguments[2].clone());
                    Ok(arguments[0].clone())
                }
                value => Err(RuntimeError::new(format!(
                    "“插入”不适用于{}",
                    value.type_name()
                ))),
            },
            NativeKind::Iterator => self
                .make_iterator(arguments[0].clone())
                .map(Value::Iterator),
            NativeKind::Next => {
                let Value::Iterator(iterator) = &arguments[0] else {
                    return Err(RuntimeError::new(format!(
                        "“续”须收遍器，不可收{}",
                        arguments[0].type_name()
                    )));
                };
                Ok(iterator_result(self.next_iterator(iterator)?))
            }
            NativeKind::Range => self.make_range(&arguments[0], &arguments[1], None),
            NativeKind::SteppedRange => {
                self.make_range(&arguments[0], &arguments[1], Some(&arguments[2]))
            }
            NativeKind::Map => {
                ensure_callable(&arguments[1], "映射之法")?;
                let source = self.make_iterator(arguments[0].clone())?;
                Ok(Value::Iterator(Rc::new(RefCell::new(
                    YanxuIterator::Mapped {
                        source,
                        mapper: arguments[1].clone(),
                    },
                ))))
            }
            NativeKind::Filter => {
                ensure_callable(&arguments[1], "筛选之法")?;
                let source = self.make_iterator(arguments[0].clone())?;
                Ok(Value::Iterator(Rc::new(RefCell::new(
                    YanxuIterator::Filtered {
                        source,
                        predicate: arguments[1].clone(),
                    },
                ))))
            }
            NativeKind::Fold => {
                ensure_callable(&arguments[2], "折叠之法")?;
                let iterator = self.make_iterator(arguments[0].clone())?;
                let mut accumulator = arguments[1].clone();
                while let Some(item) = self.next_iterator(&iterator)? {
                    accumulator = self.call(arguments[2].clone(), vec![accumulator, item])?;
                }
                Ok(accumulator)
            }
            NativeKind::Sort => {
                let iterator = self.make_iterator(arguments[0].clone())?;
                let mut values = self.collect_iterator(&iterator)?;
                values.sort_by(compare_values_for_sort);
                Ok(Value::List(Rc::new(RefCell::new(values))))
            }
            NativeKind::Reverse => {
                let iterator = self.make_iterator(arguments[0].clone())?;
                let mut values = self.collect_iterator(&iterator)?;
                values.reverse();
                Ok(Value::List(Rc::new(RefCell::new(values))))
            }
            NativeKind::Contains => {
                let iterator = self.make_iterator(arguments[0].clone())?;
                while let Some(item) = self.next_iterator(&iterator)? {
                    if values_equal(&item, &arguments[1]) {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            NativeKind::Find => {
                ensure_callable(&arguments[1], "寻找之法")?;
                let iterator = self.make_iterator(arguments[0].clone())?;
                while let Some(item) = self.next_iterator(&iterator)? {
                    if self
                        .call(arguments[1].clone(), vec![item.clone()])?
                        .truthy()
                    {
                        return Ok(iterator_result(Some(item)));
                    }
                }
                Ok(iterator_result(None))
            }
            NativeKind::CancelTask => {
                let Value::Task(task) = &arguments[0] else {
                    return Err(RuntimeError::new(format!(
                        "“取消”须收任务，不可收{}",
                        arguments[0].type_name()
                    )));
                };
                let mut task = task.borrow_mut();
                let cancelled = matches!(task.state, YanxuTaskState::Pending { .. });
                if cancelled {
                    task.state = YanxuTaskState::Cancelled;
                }
                Ok(Value::Bool(cancelled))
            }
            NativeKind::TaskStatus => {
                let Value::Task(task) = &arguments[0] else {
                    return Err(RuntimeError::new(format!(
                        "“任务状态”须收任务，不可收{}",
                        arguments[0].type_name()
                    )));
                };
                Ok(Value::String(task.borrow().status().into()))
            }
            NativeKind::JoinTasks => self.join_tasks(&arguments[0]),
        }
    }

    fn call_guarded_native(
        &mut self,
        function: GuardedNative,
        arguments: &[Value],
    ) -> Result<Value, RuntimeError> {
        match function {
            GuardedNative::ReadFile => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "读取")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_read_file(arguments)
            }
            GuardedNative::ReadBytes => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "文件.读取字节")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_read_bytes(arguments)
            }
            GuardedNative::WriteFile => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "写入")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_write_file(arguments)
            }
            GuardedNative::WriteBytes => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "文件.写入字节")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_write_bytes(arguments)
            }
            GuardedNative::AppendFile => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "追加")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_append_file(arguments)
            }
            GuardedNative::AppendBytes => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "文件.追加字节")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_append_bytes(arguments)
            }
            GuardedNative::FileStatus => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "文件.状态")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_file_status(arguments)
            }
            GuardedNative::PathExists => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "存在")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_path_exists(arguments)
            }
            GuardedNative::ReadDirectory => {
                self.permissions
                    .check_file(string_argument(arguments, 0, "目录")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_read_directory(arguments)
            }
            GuardedNative::CreateDirectory => {
                let path = string_argument(arguments, 0, "文件.创建目录")?;
                self.permissions
                    .check_file(path)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                crate::stdlib::create_directory(Path::new(path))
                    .map(|()| Value::Nil)
                    .map_err(RuntimeError::new)
            }
            GuardedNative::RemovePath => {
                let path = string_argument(arguments, 0, "文件.删除")?;
                self.permissions
                    .check_file(path)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                crate::stdlib::remove_path(
                    Path::new(path),
                    bool_argument(arguments, 1, "文件.删除")?,
                )
                .map(|()| Value::Nil)
                .map_err(RuntimeError::new)
            }
            GuardedNative::HttpGet => {
                native_http_get(arguments, &self.permissions, self.resources.host_limits())
            }
            GuardedNative::HttpPost => {
                native_http_post(arguments, &self.permissions, self.resources.host_limits())
            }
            GuardedNative::HttpRequest => {
                native_http_request(arguments, &self.permissions, self.resources.host_limits())
            }
            GuardedNative::HttpBytesRequest => native_http_bytes_request(
                arguments,
                &self.permissions,
                self.resources.host_limits(),
            ),
            GuardedNative::SocketTcpConnect => {
                native_socket_tcp_connect(arguments, &self.permissions, &self.socket_quota)
            }
            GuardedNative::SocketTcpListen => {
                native_socket_tcp_listen(arguments, &self.permissions, &self.socket_quota)
            }
            GuardedNative::SocketAccept => native_socket_accept(arguments),
            GuardedNative::SocketSend => native_socket_send(arguments),
            GuardedNative::SocketReceive => native_socket_receive(
                arguments,
                self.resources.host_limits().max_socket_read_bytes(),
            ),
            GuardedNative::SocketSendBytes => native_socket_send_bytes(arguments),
            GuardedNative::SocketReceiveBytes => native_socket_receive_bytes(
                arguments,
                self.resources.host_limits().max_socket_read_bytes(),
            ),
            GuardedNative::SocketReadExact => native_socket_read_exact(
                arguments,
                self.resources.host_limits().max_socket_read_bytes(),
            ),
            GuardedNative::SocketUdpBind => {
                native_socket_udp_bind(arguments, &self.permissions, &self.socket_quota)
            }
            GuardedNative::SocketUdpSendTo => {
                native_socket_udp_send_to(arguments, &self.permissions)
            }
            GuardedNative::SocketUdpReceiveFrom => native_socket_udp_receive_from(
                arguments,
                self.resources.host_limits().max_socket_read_bytes(),
            ),
            GuardedNative::SocketUdpSendBytesTo => {
                native_socket_udp_send_bytes_to(arguments, &self.permissions)
            }
            GuardedNative::SocketUdpReceiveBytesFrom => native_socket_udp_receive_bytes_from(
                arguments,
                self.resources.host_limits().max_socket_read_bytes(),
            ),
            GuardedNative::SocketLocalAddress => native_socket_local_address(arguments),
            GuardedNative::SocketPeerAddress => native_socket_peer_address(arguments),
            GuardedNative::SocketClose => native_socket_close(arguments),
            GuardedNative::SocketShutdownWrite => native_socket_shutdown_write(arguments),
            GuardedNative::SocketSetNodelay => native_socket_set_nodelay(arguments),
            GuardedNative::EnvRead => {
                self.permissions
                    .check_environment(string_argument(arguments, 0, "环境.读取")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_env_read(arguments)
            }
            GuardedNative::EnvExists => {
                self.permissions
                    .check_environment(string_argument(arguments, 0, "环境.存在")?)
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_env_exists(arguments)
            }
            GuardedNative::Arguments => Ok(Value::List(Rc::new(RefCell::new(
                self.arguments.iter().cloned().map(Value::String).collect(),
            )))),
            GuardedNative::ProcessRun => {
                self.permissions
                    .check_process()
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                native_process_run(arguments)
            }
            GuardedNative::ResourceReadBytes | GuardedNative::ResourceReadText => {
                let requested = string_argument(arguments, 0, "资源.读取")?;
                let path = crate::application::resolve_declared_resource(
                    self.package_root.as_deref(),
                    requested,
                )
                .map_err(|error| RuntimeError::new(error.to_string()))?;
                let bytes = crate::stdlib::read_file_bytes(&path).map_err(|error| {
                    RuntimeError::new(format!("不能读取资源“{requested}”：{error:?}"))
                })?;
                if matches!(function, GuardedNative::ResourceReadBytes) {
                    Ok(Value::Bytes(Rc::new(bytes)))
                } else {
                    String::from_utf8(bytes)
                        .map(Value::String)
                        .map_err(|_| RuntimeError::new("资源不是 UTF-8 文字"))
                }
            }
            GuardedNative::ResourceList => {
                let requested = string_argument(arguments, 0, "资源.目录")?;
                let path = crate::application::resolve_declared_resource(
                    self.package_root.as_deref(),
                    requested,
                )
                .map_err(|error| RuntimeError::new(error.to_string()))?;
                let mut entries = fs::read_dir(path)
                    .map_err(|error| RuntimeError::new(error.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| RuntimeError::new(error.to_string()))?;
                entries.sort_by_key(std::fs::DirEntry::file_name);
                Ok(Value::List(Rc::new(RefCell::new(
                    entries
                        .into_iter()
                        .map(|entry| {
                            Value::String(entry.file_name().to_string_lossy().into_owned())
                        })
                        .collect(),
                ))))
            }
        }
    }

    fn await_task(&mut self, task: &Rc<RefCell<YanxuTask>>) -> Result<Value, RuntimeError> {
        let state = std::mem::replace(&mut task.borrow_mut().state, YanxuTaskState::Running);
        match state {
            YanxuTaskState::Pending {
                function,
                arguments,
            } => match self.call_function(&function, arguments) {
                Ok(value) => {
                    task.borrow_mut().state = YanxuTaskState::Completed(value.clone());
                    Ok(value)
                }
                Err(error) => {
                    task.borrow_mut().state = YanxuTaskState::Failed(error.clone());
                    Err(error)
                }
            },
            YanxuTaskState::Completed(value) => {
                task.borrow_mut().state = YanxuTaskState::Completed(value.clone());
                Ok(value)
            }
            YanxuTaskState::Failed(error) => {
                task.borrow_mut().state = YanxuTaskState::Failed(error.clone());
                Err(error)
            }
            YanxuTaskState::Cancelled => {
                task.borrow_mut().state = YanxuTaskState::Cancelled;
                Err(RuntimeError::new("任务已取消，不可等候"))
            }
            YanxuTaskState::Running => {
                task.borrow_mut().state = YanxuTaskState::Running;
                Err(RuntimeError::new("任务正在运行，不可自相等候"))
            }
        }
    }

    fn join_tasks(&mut self, value: &Value) -> Result<Value, RuntimeError> {
        let values = match value {
            Value::List(values) => values.borrow().clone(),
            Value::Tuple(values) => values.as_ref().clone(),
            value => {
                return Err(RuntimeError::new(format!(
                    "“并候”须收任务列，不可收{}",
                    value.type_name()
                )));
            }
        };
        let tasks = values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::Task(task) => Ok(task.clone()),
                value => Err(RuntimeError::new(format!(
                    "“并候”第 {} 项须为任务，不可为{}",
                    index + 1,
                    value.type_name()
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut results = Vec::with_capacity(tasks.len());
        for (index, task) in tasks.iter().enumerate() {
            match self.await_task(task) {
                Ok(value) => results.push(value),
                Err(error) => {
                    for pending in &tasks[index + 1..] {
                        let mut pending = pending.borrow_mut();
                        if matches!(pending.state, YanxuTaskState::Pending { .. }) {
                            pending.state = YanxuTaskState::Cancelled;
                        }
                    }
                    return Err(error.with_frame("结构化并候"));
                }
            }
        }
        Ok(Value::List(Rc::new(RefCell::new(results))))
    }

    fn call_function(
        &mut self,
        function: &Function,
        arguments: Vec<Value>,
    ) -> Result<Value, RuntimeError> {
        self.resources.enter_call().map_err(RuntimeError::new)?;
        let result = self.call_function_inner(function, arguments);
        self.resources.leave_call();
        result
    }

    fn call_function_inner(
        &mut self,
        function: &Function,
        arguments: Vec<Value>,
    ) -> Result<Value, RuntimeError> {
        if arguments.len() != function.params.len() {
            return Err(arity_error(
                &function.name,
                function.params.len(),
                arguments.len(),
            ));
        }
        let env = self.child_env(function.closure.clone());
        let frame = format!("法“{}”（{}）", function.name, function.span);
        for (parameter, value) in function.params.iter().zip(arguments) {
            self.define_variable(
                env.clone(),
                parameter.name.clone(),
                value,
                parameter.type_ref.clone(),
                true,
            )
            .map_err(|error| error.with_frame(frame.clone()))?;
        }
        let previous = std::mem::replace(&mut self.current_dir, function.module_dir.clone());
        if let Some(owner) = &function.owner_class {
            self.access_classes.push(owner.clone());
        }
        if self.debug_hook.is_some() {
            self.debug_frames.push(ActiveDebugFrame {
                name: format!("法“{}”", function.name),
                span: function.span.clone(),
                environment: env.clone(),
            });
        }
        let result = self.execute_statements(&function.body, env.clone());
        if self.debug_hook.is_some() {
            self.debug_frames.pop();
        }
        if function.owner_class.is_some() {
            self.access_classes.pop();
        }
        self.current_dir = previous;
        let value = match result.map_err(|error| error.with_frame(frame.clone()))? {
            Control::Return(value) => value,
            Control::Continue(_) => Value::Nil,
        };
        self.ensure_type(
            &format!("法“{}”之归值", function.name),
            function.return_type.as_ref(),
            &value,
            function.closure.clone(),
        )
        .map_err(|error| error.with_frame(frame))?;
        Ok(value)
    }

    fn get_property(&mut self, object: Value, name: &str) -> Result<Value, RuntimeError> {
        match object {
            Value::Instance(instance) => {
                let class = instance.borrow().class.clone();
                if let Some(field) = class.field_spec(name)
                    && !self.can_access(field.visibility, &field.owner)
                {
                    return Err(RuntimeError::new(format!("私域“{name}”不可从类外读取")));
                }
                if let Some(value) = instance.borrow().fields.get(name).cloned() {
                    return Ok(value);
                }
                let method = class
                    .method_spec(name)
                    .filter(|method| !method.is_static)
                    .ok_or_else(|| RuntimeError::new(format!("实例无成员“{name}”")))?;
                if !self.can_access(method.visibility, &method.owner) {
                    return Err(RuntimeError::new(format!("私法“{name}”不可从类外调用")));
                }
                let function = method.function.clone();
                Ok(Value::Function(Rc::new(
                    self.bind_function(&function, instance),
                )))
            }
            Value::Class(class) => {
                if let Some(field) = class.field_spec(name).filter(|field| field.is_static) {
                    if !self.can_access(field.visibility, &field.owner) {
                        return Err(RuntimeError::new(format!("私静域“{name}”不可从类外读取")));
                    }
                    return class
                        .static_storage(name)
                        .expect("static field has storage")
                        .borrow()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| RuntimeError::new(format!("静域“{name}”尚未赋值")));
                }
                let method = class
                    .method_spec(name)
                    .filter(|method| method.is_static)
                    .ok_or_else(|| {
                        RuntimeError::new(format!("类“{}”无静成员“{name}”", class.name))
                    })?;
                if !self.can_access(method.visibility, &method.owner) {
                    return Err(RuntimeError::new(format!("私静法“{name}”不可从类外调用")));
                }
                Ok(Value::Function(method.function.clone()))
            }
            Value::Module(module) => {
                if !module.exports.contains(name) {
                    return Err(RuntimeError::new(format!(
                        "模块“{}”未导出“{name}”",
                        module.name
                    )));
                }
                module.environment.borrow().get_local(name).ok_or_else(|| {
                    RuntimeError::new(format!("模块“{}”未导出“{name}”", module.name))
                })
            }
            Value::Error(error) => match name {
                "代码" => Ok(Value::String(error.code.into())),
                "类别" => Ok(Value::String(error.category.clone())),
                "消息" => Ok(Value::String(error.message.clone())),
                "踪迹" => Ok(Value::List(Rc::new(RefCell::new(
                    error.frames.iter().cloned().map(Value::String).collect(),
                )))),
                "位置" => Ok(error
                    .span
                    .as_ref()
                    .map_or(Value::Nil, |span| Value::String(span.to_string()))),
                _ => Err(RuntimeError::new(format!("误值无成员“{name}”"))),
            },
            value => Err(RuntimeError::new(format!(
                "{}无可访问之成员“{name}”",
                value.type_name()
            ))),
        }
    }

    fn resolve_type_path(&self, env: EnvRef, path: &TypePath) -> Result<Value, RuntimeError> {
        let Some(first) = path.segments.first() else {
            return Err(RuntimeError::new("类型路径不可为空"));
        };
        let mut value = env.borrow().get(&first.name)?;
        for segment in path.segments.iter().skip(1) {
            let Value::Module(module) = value else {
                return Err(RuntimeError::new(format!(
                    "类型路径“{path}”的中间成员不是模块"
                )));
            };
            if !module.exports.contains(&segment.name) {
                return Err(RuntimeError::new(format!(
                    "模块“{}”未导出“{}”（类型路径“{path}”）",
                    module.name, segment.name
                )));
            }
            value = module
                .environment
                .borrow()
                .get_local(&segment.name)
                .ok_or_else(|| {
                    RuntimeError::new(format!(
                        "模块“{}”未导出“{}”（类型路径“{path}”）",
                        module.name, segment.name
                    ))
                })?;
        }
        Ok(value)
    }

    fn define_variable(
        &self,
        env: EnvRef,
        name: String,
        value: Value,
        type_ref: Option<TypeRef>,
        mutable: bool,
    ) -> Result<(), RuntimeError> {
        self.ensure_type(
            &format!("变量“{name}”"),
            type_ref.as_ref(),
            &value,
            env.clone(),
        )?;
        let type_env = Rc::downgrade(&env);
        env.borrow_mut()
            .define_typed(name, value, type_ref, type_env, mutable);
        Ok(())
    }

    fn assign_variable(&self, env: EnvRef, name: &str, value: Value) -> Result<(), RuntimeError> {
        let mut current = env;
        loop {
            let contains = current.borrow().values.contains_key(name);
            if contains {
                let (mutable, type_ref, type_env) = {
                    let environment = current.borrow();
                    let binding = environment.values.get(name).expect("binding checked above");
                    (
                        binding.mutable,
                        binding.type_ref.clone(),
                        binding.type_env.as_ref().and_then(Weak::upgrade),
                    )
                };
                if !mutable {
                    return Err(RuntimeError::new(format!("“{name}”乃定值，不可改写")));
                }
                self.ensure_type(
                    &format!("变量“{name}”"),
                    type_ref.as_ref(),
                    &value,
                    type_env.unwrap_or_else(|| current.clone()),
                )?;
                current
                    .borrow_mut()
                    .values
                    .get_mut(name)
                    .expect("binding checked above")
                    .value = value;
                return Ok(());
            }
            let enclosing = current.borrow().enclosing.clone();
            let Some(enclosing) = enclosing else {
                return Err(RuntimeError::new(format!("不可改写未定义之名“{name}”")));
            };
            current = enclosing;
        }
    }

    fn ensure_type(
        &self,
        subject: &str,
        expected: Option<&TypeRef>,
        value: &Value,
        env: EnvRef,
    ) -> Result<(), RuntimeError> {
        let Some(expected) = expected else {
            return Ok(());
        };
        if self.value_matches_type(value, &expected.kind, env)? {
            return Ok(());
        }
        Err(RuntimeError::new(format!(
            "{subject}注为{}，不可纳入{}",
            expected.name,
            value.type_name()
        )))
    }

    fn value_matches_type(
        &self,
        value: &Value,
        expected: &TypeKind,
        env: EnvRef,
    ) -> Result<bool, RuntimeError> {
        match expected {
            TypeKind::Union(types) => {
                for ty in types {
                    if self.value_matches_type(value, ty, env.clone())? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            TypeKind::Nullable(ty) => {
                Ok(matches!(value, Value::Nil) || self.value_matches_type(value, ty, env)?)
            }
            TypeKind::Function { .. } => Ok(matches!(value, Value::Function(_) | Value::Native(_))),
            TypeKind::Generic { base, arguments } => {
                let Some(base_name) = base.single_name() else {
                    let target = self.resolve_type_path(env, base)?;
                    return Ok(matches!(
                        (value, target),
                        (Value::Instance(instance), Value::Class(class))
                            if instance.borrow().class.is_a(&class.type_id)
                    ));
                };
                match (base_name, value) {
                    ("列", Value::List(items)) if arguments.len() == 1 => {
                        for item in items.borrow().iter() {
                            if !self.value_matches_type(item, &arguments[0], env.clone())? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("典", Value::Map(map)) if arguments.len() == 2 => {
                        for (key, item) in &map.borrow().entries {
                            if !self.value_matches_type(key, &arguments[0], env.clone())?
                                || !self.value_matches_type(item, &arguments[1], env.clone())?
                            {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("元", Value::Tuple(items)) if arguments.len() == items.len() => {
                        for (item, expected) in items.iter().zip(arguments) {
                            if !self.value_matches_type(item, expected, env.clone())? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("遍器", Value::Iterator(_)) if arguments.len() == 1 => Ok(true),
                    ("任务", Value::Task(_)) if arguments.len() == 1 => Ok(true),
                    ("套接字", Value::Socket(_)) if arguments.is_empty() => Ok(true),
                    _ => Ok(false),
                }
            }
            TypeKind::Named(path) => {
                if let Some(expected) = path.single_name() {
                    let builtin = match expected {
                        "任意" => Some(true),
                        "数" => Some(matches!(value, Value::Number(_))),
                        "文" => Some(matches!(value, Value::String(_))),
                        "字节串" => Some(matches!(value, Value::Bytes(_))),
                        "理" => Some(matches!(value, Value::Bool(_))),
                        "空" => Some(matches!(value, Value::Nil)),
                        "法" => Some(matches!(value, Value::Function(_) | Value::Native(_))),
                        "类" => Some(matches!(value, Value::Class(_))),
                        "协" => Some(matches!(value, Value::Protocol(_))),
                        "模块" => Some(matches!(value, Value::Module(_))),
                        "对象" => Some(matches!(value, Value::Instance(_))),
                        "列" => Some(matches!(value, Value::List(_))),
                        "元" => Some(matches!(value, Value::Tuple(_))),
                        "典" => Some(matches!(value, Value::Map(_))),
                        "遍器" => Some(matches!(value, Value::Iterator(_))),
                        "误" => Some(matches!(value, Value::Error(_))),
                        "任务" => Some(matches!(value, Value::Task(_))),
                        "套接字" => Some(matches!(value, Value::Socket(_))),
                        _ => None,
                    };
                    if let Some(matches) = builtin {
                        return Ok(matches);
                    }
                }
                match self.resolve_type_path(env, path)? {
                    Value::Class(class) => Ok(matches!(value, Value::Instance(instance)
                        if instance.borrow().class.is_a(&class.type_id))),
                    Value::Protocol(protocol) => Ok(matches!(value, Value::Instance(instance)
                        if instance.borrow().class.is_a(&protocol.type_id))),
                    other => Err(RuntimeError::new(format!(
                        "类型路径“{path}”指向{}而非类或协",
                        other.type_name()
                    ))),
                }
            }
        }
    }

    fn set_property(
        &self,
        object: Value,
        name: &str,
        value: Value,
        _environment: EnvRef,
    ) -> Result<(), RuntimeError> {
        match object {
            Value::Instance(instance) => {
                let class = instance.borrow().class.clone();
                if let Some(field) = class.field_spec(name).cloned() {
                    if field.is_static {
                        return Err(RuntimeError::new(format!("“{name}”乃静域，须经类名改写")));
                    }
                    if !self.can_access(field.visibility, &field.owner) {
                        return Err(RuntimeError::new(format!("私域“{name}”不可从类外改写")));
                    }
                    if field.readonly && instance.borrow().fields.contains_key(name) {
                        return Err(RuntimeError::new(format!("只读域“{name}”不可再次改写")));
                    }
                    self.ensure_type(
                        &format!("域“{name}”"),
                        Some(&field.type_ref),
                        &value,
                        field.type_env,
                    )?;
                } else if class.has_instance_fields() {
                    return Err(RuntimeError::new(format!(
                        "类“{}”未声明域“{name}”",
                        class.name
                    )));
                }
                instance.borrow_mut().fields.insert(name.into(), value);
                Ok(())
            }
            Value::Class(class) => {
                let field = class
                    .field_spec(name)
                    .filter(|field| field.is_static)
                    .cloned()
                    .ok_or_else(|| {
                        RuntimeError::new(format!("类“{}”无静域“{name}”", class.name))
                    })?;
                if !self.can_access(field.visibility, &field.owner) {
                    return Err(RuntimeError::new(format!("私静域“{name}”不可从类外改写")));
                }
                let storage = class
                    .static_storage(name)
                    .expect("static field has storage");
                if field.readonly && storage.borrow().contains_key(name) {
                    return Err(RuntimeError::new(format!("只读静域“{name}”不可再次改写")));
                }
                self.ensure_type(
                    &format!("静域“{name}”"),
                    Some(&field.type_ref),
                    &value,
                    field.type_env,
                )?;
                storage.borrow_mut().insert(name.into(), value);
                Ok(())
            }
            Value::Module(module) => Err(RuntimeError::new(format!(
                "模块“{}”之成员不可从外部改写",
                module.name
            ))),
            value => Err(RuntimeError::new(format!(
                "{}不可拥有字段“{name}”",
                value.type_name()
            ))),
        }
    }

    fn can_access(&self, visibility: Visibility, owner: &TypeId) -> bool {
        visibility == Visibility::Public
            || self
                .access_classes
                .last()
                .is_some_and(|current| current == owner)
    }

    fn get_index(&self, object: Value, index: Value) -> Result<Value, RuntimeError> {
        match object {
            Value::List(items) => {
                let index = list_index(&index)?;
                items
                    .borrow()
                    .get(index)
                    .cloned()
                    .ok_or_else(|| RuntimeError::new(format!("列下标 {index} 超出范围")))
            }
            Value::Tuple(items) => {
                let index = list_index(&index)?;
                items
                    .get(index)
                    .cloned()
                    .ok_or_else(|| RuntimeError::new(format!("元组下标 {index} 超出范围")))
            }
            Value::String(text) => {
                let index = list_index(&index)?;
                text.chars()
                    .nth(index)
                    .map(|character| Value::String(character.to_string()))
                    .ok_or_else(|| RuntimeError::new(format!("文字下标 {index} 超出范围")))
            }
            Value::Map(map) => map
                .borrow()
                .entries
                .iter()
                .find(|(key, _)| values_equal(key, &index))
                .map(|(_, value)| value.clone())
                .ok_or_else(|| RuntimeError::new(format!("典中未有键“{index}”"))),
            value => Err(RuntimeError::new(format!(
                "{}不可用下标读取",
                value.type_name()
            ))),
        }
    }

    fn get_slice(
        &self,
        object: Value,
        start: Option<Value>,
        end: Option<Value>,
    ) -> Result<Value, RuntimeError> {
        match object {
            Value::List(items) => {
                let items = items.borrow();
                let (start, end) = slice_bounds(start.as_ref(), end.as_ref(), items.len())?;
                Ok(Value::List(Rc::new(RefCell::new(
                    items[start..end].to_vec(),
                ))))
            }
            Value::Tuple(items) => {
                let (start, end) = slice_bounds(start.as_ref(), end.as_ref(), items.len())?;
                Ok(Value::Tuple(Rc::new(items[start..end].to_vec())))
            }
            Value::String(text) => {
                let characters: Vec<char> = text.chars().collect();
                let (start, end) = slice_bounds(start.as_ref(), end.as_ref(), characters.len())?;
                Ok(Value::String(characters[start..end].iter().collect()))
            }
            value => Err(RuntimeError::new(format!("{}不可切片", value.type_name()))),
        }
    }

    fn set_index(&mut self, object: Value, index: Value, value: Value) -> Result<(), RuntimeError> {
        match object {
            Value::List(items) => {
                let index = list_index(&index)?;
                let mut items = items.borrow_mut();
                let slot = items
                    .get_mut(index)
                    .ok_or_else(|| RuntimeError::new(format!("列下标 {index} 超出范围")))?;
                *slot = value;
                Ok(())
            }
            Value::Map(map) => {
                let adds_key = !map
                    .borrow()
                    .entries
                    .iter()
                    .any(|(key, _)| values_equal(key, &index));
                if adds_key {
                    self.resources
                        .check_collection(map.borrow().entries.len().saturating_add(1))
                        .map_err(RuntimeError::new)?;
                }
                map_insert(&mut map.borrow_mut(), index, value)
            }
            Value::String(_) => Err(RuntimeError::new("文字不可按下标改写")),
            value => Err(RuntimeError::new(format!(
                "{}不可用下标改写",
                value.type_name()
            ))),
        }
    }

    fn make_iterator(&mut self, value: Value) -> Result<Rc<RefCell<YanxuIterator>>, RuntimeError> {
        let iterator = match value {
            Value::Iterator(iterator) => return Ok(iterator),
            Value::List(source) => YanxuIterator::List { source, index: 0 },
            Value::Tuple(source) => YanxuIterator::Tuple { source, index: 0 },
            Value::String(text) => YanxuIterator::String {
                source: Rc::new(text.chars().collect()),
                index: 0,
            },
            Value::Map(source) => YanxuIterator::MapKeys { source, index: 0 },
            Value::Instance(source) => {
                let start = source.borrow().class.method("遍始");
                if let Some(start) = start {
                    let bound = self.bind_function(&start, source.clone());
                    let started = self.call_function(&bound, Vec::new())?;
                    if matches!(&started, Value::Instance(instance) if Rc::ptr_eq(instance, &source))
                    {
                        if source.borrow().class.method("遍次").is_none() {
                            return Err(RuntimeError::new("“遍始”归还自身，但未实现“遍次”"));
                        }
                        YanxuIterator::Object { source }
                    } else {
                        return self.make_iterator(started);
                    }
                } else if source.borrow().class.method("遍次").is_some() {
                    YanxuIterator::Object { source }
                } else {
                    return Err(RuntimeError::new(format!(
                        "{}未实现“遍始/遍次”协议",
                        source.borrow().class.name
                    )));
                }
            }
            value => return Err(RuntimeError::new(format!("{}不可遍历", value.type_name()))),
        };
        Ok(Rc::new(RefCell::new(iterator)))
    }

    fn next_iterator(
        &mut self,
        iterator: &Rc<RefCell<YanxuIterator>>,
    ) -> Result<Option<Value>, RuntimeError> {
        match &mut *iterator.borrow_mut() {
            YanxuIterator::List { source, index } => {
                let value = source.borrow().get(*index).cloned();
                *index += usize::from(value.is_some());
                Ok(value)
            }
            YanxuIterator::Tuple { source, index } => {
                let value = source.get(*index).cloned();
                *index += usize::from(value.is_some());
                Ok(value)
            }
            YanxuIterator::String { source, index } => {
                let value = source
                    .get(*index)
                    .map(|character| Value::String(character.to_string()));
                *index += usize::from(value.is_some());
                Ok(value)
            }
            YanxuIterator::MapKeys { source, index } => {
                let value = source
                    .borrow()
                    .entries
                    .get(*index)
                    .map(|(key, _)| key.clone());
                *index += usize::from(value.is_some());
                Ok(value)
            }
            YanxuIterator::Range { current, end, step } => {
                let in_bounds = if *step > 0.0 {
                    *current < *end
                } else {
                    *current > *end
                };
                if !in_bounds {
                    return Ok(None);
                }
                let value = *current;
                *current += *step;
                Ok(Some(Value::Number(value)))
            }
            YanxuIterator::Object { source } => {
                let next = source.borrow().class.method("遍次").ok_or_else(|| {
                    RuntimeError::new(format!("{}未实现“遍次”", source.borrow().class.name))
                })?;
                let bound = self.bind_function(&next, source.clone());
                let result = self.call_function(&bound, Vec::new())?;
                parse_iterator_result(result)
            }
            YanxuIterator::Mapped { source, mapper } => self
                .next_iterator(source)?
                .map(|value| self.call(mapper.clone(), vec![value]))
                .transpose(),
            YanxuIterator::Filtered { source, predicate } => loop {
                let Some(value) = self.next_iterator(source)? else {
                    return Ok(None);
                };
                if self.call(predicate.clone(), vec![value.clone()])?.truthy() {
                    return Ok(Some(value));
                }
            },
        }
    }

    fn make_range(
        &self,
        start: &Value,
        end: &Value,
        step: Option<&Value>,
    ) -> Result<Value, RuntimeError> {
        let start = finite_number(start, "范围起点")?;
        let end = finite_number(end, "范围终点")?;
        let step = step.map_or(Ok(1.0), |value| finite_number(value, "范围步长"))?;
        if step == 0.0 {
            return Err(RuntimeError::new("范围步长不可为零"));
        }
        Ok(Value::Iterator(Rc::new(RefCell::new(
            YanxuIterator::Range {
                current: start,
                end,
                step,
            },
        ))))
    }

    fn collect_iterator(
        &mut self,
        iterator: &Rc<RefCell<YanxuIterator>>,
    ) -> Result<Vec<Value>, RuntimeError> {
        let mut values = Vec::new();
        while let Some(value) = self.next_iterator(iterator)? {
            self.resources
                .check_collection(values.len().saturating_add(1))
                .map_err(RuntimeError::new)?;
            values.push(value);
        }
        Ok(values)
    }

    fn ensure_value_budget(&self, value: &Value) -> Result<(), RuntimeError> {
        self.ensure_value_budget_inner(value, &mut HashSet::new())
    }

    fn ensure_value_budget_inner(
        &self,
        value: &Value,
        visited: &mut HashSet<usize>,
    ) -> Result<(), RuntimeError> {
        match value {
            Value::List(items) => {
                if !visited.insert(Rc::as_ptr(items) as usize) {
                    return Ok(());
                }
                let items = items.borrow();
                self.resources
                    .check_collection(items.len())
                    .map_err(RuntimeError::new)?;
                for item in items.iter() {
                    self.ensure_value_budget_inner(item, visited)?;
                }
            }
            Value::Tuple(items) => {
                if !visited.insert(Rc::as_ptr(items) as usize) {
                    return Ok(());
                }
                self.resources
                    .check_collection(items.len())
                    .map_err(RuntimeError::new)?;
                for item in items.iter() {
                    self.ensure_value_budget_inner(item, visited)?;
                }
            }
            Value::Map(map) => {
                if !visited.insert(Rc::as_ptr(map) as usize) {
                    return Ok(());
                }
                let map = map.borrow();
                self.resources
                    .check_collection(map.entries.len())
                    .map_err(RuntimeError::new)?;
                for (key, item) in &map.entries {
                    self.ensure_value_budget_inner(key, visited)?;
                    self.ensure_value_budget_inner(item, visited)?;
                }
            }
            Value::Bytes(bytes)
                if bytes.len() as u64 > self.resources.host_limits().max_byte_value_bytes() =>
            {
                return Err(RuntimeError::bytes(
                    "BYTES_LIMIT",
                    format!(
                        "字节串不得超过宿主 {} 字节上限",
                        self.resources.host_limits().max_byte_value_bytes()
                    ),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn load_module(&mut self, requested: &str) -> Result<Rc<YanxuModule>, RuntimeError> {
        crate::package::validate_portable_path_text(requested)
            .map_err(RuntimeError::package_path)?;
        if let Some(name) = requested.strip_prefix("标准:") {
            return standard_module(name);
        }
        let (joined, package_import) = if let Some(name) = requested.strip_prefix("包:") {
            let dependency = crate::package::resolve_dependency_scoped(
                self.package_root.as_deref(),
                &self.current_dir,
                name,
            )
            .map_err(RuntimeError::package)?;
            self.package_module_roots
                .insert(&dependency.root)
                .map_err(RuntimeError::package_path)?;
            (dependency.entry, true)
        } else {
            let requested_path = Path::new(requested);
            if requested_path.is_absolute() {
                (requested_path.to_path_buf(), false)
            } else {
                (self.current_dir.join(requested_path), false)
            }
        };
        if !package_import && self.package_module_roots.matching_root(&joined).is_none() {
            self.permissions
                .check_file(&joined)
                .map_err(|error| RuntimeError::new(error.to_string()))?;
        }
        let (resolved, authority) = self
            .package_module_roots
            .resolve_import_file(&self.current_dir, &joined, package_import)
            .map_err(RuntimeError::package)?;
        let canonical = resolved.path().to_path_buf();
        if let Err(error) = self.permissions.check_file(&canonical)
            && !authority.is_verified()
        {
            return Err(RuntimeError::new(error.to_string()));
        }

        if let Some(module) = self.module_cache.get(&canonical) {
            return Ok(module.clone());
        }
        if let Some(start) = self
            .loading_modules
            .iter()
            .position(|loading| loading == &canonical)
        {
            let mut chain = self.loading_modules[start..]
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            chain.push(canonical.display().to_string());
            return Err(RuntimeError::new(format!(
                "模块循环相引：{}",
                chain.join(" → ")
            )));
        }
        let resolved = resolved.open().map_err(RuntimeError::package)?;
        self.loading_modules.push(canonical.clone());

        let result = self.load_module_uncached(resolved);
        self.loading_modules.pop();
        let module = result?;
        self.initialization_order.push(canonical.clone());
        self.module_cache.insert(canonical, module.clone());
        Ok(module)
    }

    fn load_module_uncached(
        &mut self,
        resolved: crate::package::ResolvedPackageFile,
    ) -> Result<Rc<YanxuModule>, RuntimeError> {
        let path = resolved.path().to_path_buf();
        let source =
            crate::package::read_resolved_module_source_snapshot(resolved).map_err(|error| {
                RuntimeError::new(format!("不能读取模块“{}”：{error}", path.display()))
            })?;
        let tokens = crate::lexer::scan_named(&source, path.display().to_string())
            .map_err(|error| RuntimeError::new(error.message).at(error.span))?;
        let statements = crate::parser::parse(tokens)
            .map_err(|error| RuntimeError::new(error.message).at(error.span))?;
        crate::resolver::resolve(&statements)
            .map_err(|error| RuntimeError::new(error.message).at(error.span))?;

        let module_env = self.child_env(self.globals.clone());
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let previous = std::mem::replace(&mut self.current_dir, directory.to_path_buf());
        let module_id = ModuleId::for_path(&path);
        let previous_module_id = std::mem::replace(&mut self.current_module_id, module_id.clone());
        let execution = self
            .execute_statements(&statements, module_env.clone())
            .map_err(|error| error.with_frame(format!("模块“{}”", path.display())));
        self.current_dir = previous;
        self.current_module_id = previous_module_id;
        match execution? {
            Control::Return(_) => return Err(RuntimeError::new("模块顶层不可用“归”")),
            Control::Continue(_) => {}
        }

        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("无名")
            .to_owned();
        let exports = statements
            .iter()
            .filter_map(|statement| {
                if !statement.public {
                    return None;
                }
                match &statement.kind {
                    StmtKind::Let { name, .. }
                    | StmtKind::Function { name, .. }
                    | StmtKind::Class { name, .. }
                    | StmtKind::Protocol { name, .. }
                    | StmtKind::Import { alias: name, .. } => Some(name.clone()),
                    _ => None,
                }
            })
            .collect();
        Ok(Rc::new(YanxuModule {
            name,
            module_id,
            environment: module_env,
            exports,
        }))
    }
}

fn statement_name(statement: &StmtKind) -> &'static str {
    match statement {
        StmtKind::Let { .. } => "声明",
        StmtKind::Set { .. } => "改写",
        StmtKind::Print(_) => "输出",
        StmtKind::Expression(_) => "求值",
        StmtKind::If { .. } => "分支",
        StmtKind::While { .. } => "当循环",
        StmtKind::For { .. } => "逐循环",
        StmtKind::Function { .. } => "法声明",
        StmtKind::Class { .. } => "类声明",
        StmtKind::Protocol { .. } => "协声明",
        StmtKind::Import { .. } => "引模块",
        StmtKind::Try { .. } => "尝试",
        StmtKind::Throw(_) => "抛误",
        StmtKind::Return(_) => "归值",
    }
}

// 标准模块表须与 VM、静态类型摘要和机器 API 清单同步。
fn standard_module(name: &str) -> Result<Rc<YanxuModule>, RuntimeError> {
    let environment = Rc::new(RefCell::new(Environment::default()));
    let mut exports = HashSet::new();
    match name {
        "数学" => {
            define_export_value(
                &environment,
                &mut exports,
                "圆周率".into(),
                Value::Number(std::f64::consts::PI),
            );
            define_export_native(&environment, &mut exports, "绝对值", 1, native_abs);
            define_export_native(&environment, &mut exports, "平方根", 1, native_sqrt);
            define_export_native(&environment, &mut exports, "幂", 2, native_pow);
            define_export_native(&environment, &mut exports, "下取整", 1, native_floor);
            define_export_native(&environment, &mut exports, "上取整", 1, native_ceil);
            define_export_native(&environment, &mut exports, "四舍五入", 1, native_round);
            define_export_native(&environment, &mut exports, "正弦", 1, native_sin);
            define_export_native(&environment, &mut exports, "余弦", 1, native_cos);
            define_export_native(&environment, &mut exports, "最小", 2, native_min);
            define_export_native(&environment, &mut exports, "最大", 2, native_max);
        }
        "文字" => {
            define_export_native(&environment, &mut exports, "修剪", 1, native_trim);
            define_export_native(&environment, &mut exports, "分割", 2, native_split);
            define_export_native(&environment, &mut exports, "替换", 3, native_replace);
            define_export_native(&environment, &mut exports, "始于", 2, native_starts_with);
            define_export_native(&environment, &mut exports, "终于", 2, native_ends_with);
            define_export_native(&environment, &mut exports, "大写", 1, native_uppercase);
            define_export_native(&environment, &mut exports, "小写", 1, native_lowercase);
            define_export_native(&environment, &mut exports, "字符列", 1, native_characters);
            define_export_native(&environment, &mut exports, "联结", 2, native_join);
        }
        "字节" => {
            define_export_native(
                &environment,
                &mut exports,
                "从文字",
                1,
                native_bytes_from_text,
            );
            define_export_native(
                &environment,
                &mut exports,
                "转文字",
                1,
                native_bytes_to_text,
            );
            define_export_native(&environment, &mut exports, "长度", 1, native_bytes_length);
            define_export_native(&environment, &mut exports, "切片", 3, native_bytes_slice);
            define_export_native(&environment, &mut exports, "拼接", 2, native_bytes_concat);
            define_export_native(&environment, &mut exports, "查找", 2, native_bytes_find);
            define_export_native(
                &environment,
                &mut exports,
                "从数列",
                1,
                native_bytes_from_numbers,
            );
            define_export_native(
                &environment,
                &mut exports,
                "转数列",
                1,
                native_bytes_to_numbers,
            );
        }
        "时间" => {
            define_export_native(&environment, &mut exports, "今", 0, native_clock);
            define_export_native(&environment, &mut exports, "毫秒", 0, native_millis);
            define_export_native(&environment, &mut exports, "等待", 1, native_sleep);
        }
        "文件" => {
            define_export_intrinsic(
                &environment,
                &mut exports,
                "读取",
                1,
                NativeKind::Guarded(GuardedNative::ReadFile),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "写入",
                2,
                NativeKind::Guarded(GuardedNative::WriteFile),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "追加",
                2,
                NativeKind::Guarded(GuardedNative::AppendFile),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "存在",
                1,
                NativeKind::Guarded(GuardedNative::PathExists),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "目录",
                1,
                NativeKind::Guarded(GuardedNative::ReadDirectory),
            );
            for (name, arity, function) in [
                ("读取字节", 1, GuardedNative::ReadBytes),
                ("写入字节", 2, GuardedNative::WriteBytes),
                ("追加字节", 2, GuardedNative::AppendBytes),
                ("状态", 1, GuardedNative::FileStatus),
                ("创建目录", 1, GuardedNative::CreateDirectory),
                ("删除", 2, GuardedNative::RemovePath),
            ] {
                define_export_intrinsic(
                    &environment,
                    &mut exports,
                    name,
                    arity,
                    NativeKind::Guarded(function),
                );
            }
        }
        "JSON" | "json" => {
            define_export_native(&environment, &mut exports, "解析", 1, native_json_parse);
            define_export_native(
                &environment,
                &mut exports,
                "序列化",
                1,
                native_json_stringify,
            );
        }
        "网络" => {
            define_export_intrinsic(
                &environment,
                &mut exports,
                "获取",
                1,
                NativeKind::Guarded(GuardedNative::HttpGet),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "发文",
                2,
                NativeKind::Guarded(GuardedNative::HttpPost),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "请求",
                5,
                NativeKind::Guarded(GuardedNative::HttpRequest),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "请求字节",
                6,
                NativeKind::Guarded(GuardedNative::HttpBytesRequest),
            );
        }
        "套接字" => {
            for (name, arity, function) in [
                ("TCP连接", 2, GuardedNative::SocketTcpConnect),
                ("TCP监听", 1, GuardedNative::SocketTcpListen),
                ("接受", 2, GuardedNative::SocketAccept),
                ("发送", 3, GuardedNative::SocketSend),
                ("接收", 3, GuardedNative::SocketReceive),
                ("发送字节", 3, GuardedNative::SocketSendBytes),
                ("接收字节", 3, GuardedNative::SocketReceiveBytes),
                ("精确读取", 3, GuardedNative::SocketReadExact),
                ("UDP绑定", 1, GuardedNative::SocketUdpBind),
                ("UDP发送至", 4, GuardedNative::SocketUdpSendTo),
                ("UDP接收自", 3, GuardedNative::SocketUdpReceiveFrom),
                ("UDP发送字节至", 4, GuardedNative::SocketUdpSendBytesTo),
                ("UDP接收字节自", 3, GuardedNative::SocketUdpReceiveBytesFrom),
                ("本地地址", 1, GuardedNative::SocketLocalAddress),
                ("对端地址", 1, GuardedNative::SocketPeerAddress),
                ("关闭", 1, GuardedNative::SocketClose),
                ("关闭写端", 1, GuardedNative::SocketShutdownWrite),
                ("TCP无延迟", 2, GuardedNative::SocketSetNodelay),
            ] {
                define_export_intrinsic(
                    &environment,
                    &mut exports,
                    name,
                    arity,
                    NativeKind::Guarded(function),
                );
            }
        }
        "测试" => {
            define_export_native(&environment, &mut exports, "断言", 2, native_assert);
            define_export_native(&environment, &mut exports, "相等", 2, native_assert_equal);
            define_export_native(&environment, &mut exports, "非空", 2, native_assert_not_nil);
        }
        "路径" => {
            define_export_native(&environment, &mut exports, "合并", 2, native_path_join);
            define_export_native(&environment, &mut exports, "父级", 1, native_path_parent);
            define_export_native(
                &environment,
                &mut exports,
                "文件名",
                1,
                native_path_file_name,
            );
            define_export_native(
                &environment,
                &mut exports,
                "扩展名",
                1,
                native_path_extension,
            );
            define_export_native(
                &environment,
                &mut exports,
                "是否绝对",
                1,
                native_path_is_absolute,
            );
            define_export_native(
                &environment,
                &mut exports,
                "规范化",
                1,
                native_path_normalize,
            );
        }
        "环境" => {
            define_export_intrinsic(
                &environment,
                &mut exports,
                "读取",
                1,
                NativeKind::Guarded(GuardedNative::EnvRead),
            );
            define_export_intrinsic(
                &environment,
                &mut exports,
                "存在",
                1,
                NativeKind::Guarded(GuardedNative::EnvExists),
            );
            define_export_native(
                &environment,
                &mut exports,
                "当前目录",
                0,
                native_current_dir,
            );
            define_export_native(&environment, &mut exports, "系统", 0, native_os);
            define_export_native(&environment, &mut exports, "架构", 0, native_arch);
            define_export_intrinsic(
                &environment,
                &mut exports,
                "参数",
                0,
                NativeKind::Guarded(GuardedNative::Arguments),
            );
        }
        "进程" => {
            define_export_intrinsic(
                &environment,
                &mut exports,
                "执行",
                4,
                NativeKind::Guarded(GuardedNative::ProcessRun),
            );
        }
        "资源" => {
            for (name, function) in [
                ("读取字节", GuardedNative::ResourceReadBytes),
                ("读取文字", GuardedNative::ResourceReadText),
                ("目录", GuardedNative::ResourceList),
            ] {
                define_export_intrinsic(
                    &environment,
                    &mut exports,
                    name,
                    1,
                    NativeKind::Guarded(function),
                );
            }
        }
        "哈希" => {
            define_export_native(&environment, &mut exports, "SHA256", 1, native_sha256);
            define_export_native(
                &environment,
                &mut exports,
                "HMACSHA256",
                2,
                native_hmac_sha256,
            );
            define_export_native(
                &environment,
                &mut exports,
                "恒时相等",
                2,
                native_constant_time_equal,
            );
        }
        "编码" => {
            define_export_native(&environment, &mut exports, "十六进制", 1, native_hex_encode);
            define_export_native(
                &environment,
                &mut exports,
                "解十六进制",
                1,
                native_hex_decode,
            );
            define_export_native(
                &environment,
                &mut exports,
                "百分号",
                1,
                native_percent_encode,
            );
            define_export_native(
                &environment,
                &mut exports,
                "解百分号",
                1,
                native_percent_decode,
            );
        }
        "统计" => {
            define_export_native(&environment, &mut exports, "总和", 1, native_stats_sum);
            define_export_native(&environment, &mut exports, "平均", 1, native_stats_mean);
            define_export_native(&environment, &mut exports, "中位数", 1, native_stats_median);
            define_export_native(&environment, &mut exports, "方差", 1, native_stats_variance);
            define_export_native(&environment, &mut exports, "标准差", 1, native_stats_stddev);
        }
        "CSV" | "csv" => {
            define_export_native(&environment, &mut exports, "解析", 1, native_csv_parse);
            define_export_native(
                &environment,
                &mut exports,
                "序列化",
                1,
                native_csv_stringify,
            );
        }
        "随机" => {
            define_export_native(&environment, &mut exports, "小数", 1, native_random_unit);
            define_export_native(&environment, &mut exports, "整数", 3, native_random_integer);
            define_export_native(&environment, &mut exports, "布尔", 1, native_random_bool);
            define_export_native(
                &environment,
                &mut exports,
                "安全字节",
                1,
                native_secure_random_bytes,
            );
        }
        "标识" => {
            define_export_native(
                &environment,
                &mut exports,
                "稳定UUID",
                1,
                native_stable_uuid,
            );
            define_export_native(&environment, &mut exports, "是否UUID", 1, native_is_uuid);
            define_export_native(
                &environment,
                &mut exports,
                "稳定短码",
                2,
                native_stable_short_id,
            );
        }
        "模板" => {
            define_export_native(
                &environment,
                &mut exports,
                "插值",
                3,
                native_template_interpolate,
            );
            define_export_native(
                &environment,
                &mut exports,
                "转义HTML",
                1,
                native_html_escape,
            );
            define_export_native(
                &environment,
                &mut exports,
                "反转义HTML",
                1,
                native_html_unescape,
            );
        }
        "校验" => {
            define_export_native(&environment, &mut exports, "电子邮件", 1, native_is_email);
            define_export_native(&environment, &mut exports, "IPv4", 1, native_is_ipv4);
            define_export_native(
                &environment,
                &mut exports,
                "十六进制色",
                1,
                native_is_hex_color,
            );
            define_export_native(
                &environment,
                &mut exports,
                "标识符",
                1,
                native_is_identifier,
            );
        }
        "Base64" => {
            define_export_native(&environment, &mut exports, "编码", 1, native_base64_encode);
            define_export_native(&environment, &mut exports, "解码", 1, native_base64_decode);
            define_export_native(
                &environment,
                &mut exports,
                "网址编码",
                1,
                native_base64_url_encode,
            );
            define_export_native(
                &environment,
                &mut exports,
                "解网址编码",
                1,
                native_base64_url_decode,
            );
        }
        "正则" => {
            define_export_native(&environment, &mut exports, "匹配", 2, native_regex_is_match);
            define_export_native(&environment, &mut exports, "首项", 2, native_regex_first);
            define_export_native(
                &environment,
                &mut exports,
                "替换全部",
                3,
                native_regex_replace_all,
            );
            define_export_native(&environment, &mut exports, "分割", 2, native_regex_split);
        }
        "URL" => {
            define_export_native(
                &environment,
                &mut exports,
                "是否合法",
                1,
                native_url_is_valid,
            );
            define_export_native(&environment, &mut exports, "协议", 1, native_url_scheme);
            define_export_native(&environment, &mut exports, "主机", 1, native_url_host);
            define_export_native(&environment, &mut exports, "端口", 1, native_url_port);
            define_export_native(&environment, &mut exports, "路径", 1, native_url_path);
            define_export_native(
                &environment,
                &mut exports,
                "查询值",
                2,
                native_url_query_value,
            );
            define_export_native(&environment, &mut exports, "合并", 2, native_url_join);
        }
        "日期" => {
            define_export_native(
                &environment,
                &mut exports,
                "是否合法",
                1,
                native_date_is_valid,
            );
            define_export_native(
                &environment,
                &mut exports,
                "是否闰年",
                1,
                native_date_is_leap_year,
            );
            define_export_native(&environment, &mut exports, "加天", 2, native_date_add_days);
            define_export_native(
                &environment,
                &mut exports,
                "相差天数",
                2,
                native_date_days_between,
            );
            define_export_native(&environment, &mut exports, "HTTP日期", 1, native_http_date);
            define_export_native(
                &environment,
                &mut exports,
                "解析HTTP日期",
                1,
                native_parse_http_date,
            );
        }
        _ => return Err(RuntimeError::new(format!("未有标准模块“{name}”"))),
    }
    Ok(Rc::new(YanxuModule {
        name: format!("标准:{name}"),
        module_id: ModuleId::standard(name),
        environment,
        exports,
    }))
}

fn define_export_value(env: &EnvRef, exports: &mut HashSet<String>, name: String, value: Value) {
    env.borrow_mut()
        .define_unchecked(name.clone(), value, false);
    exports.insert(name);
}

fn define_export_native(
    env: &EnvRef,
    exports: &mut HashSet<String>,
    name: &'static str,
    arity: usize,
    body: NativeBody,
) {
    define_native(env, name, arity, body);
    exports.insert(name.into());
}

fn define_export_intrinsic(
    env: &EnvRef,
    exports: &mut HashSet<String>,
    name: &'static str,
    arity: usize,
    kind: NativeKind,
) {
    define_intrinsic(env, name, arity, kind);
    exports.insert(name.into());
}

fn define_native(env: &EnvRef, name: &'static str, arity: usize, body: NativeBody) {
    env.borrow_mut().define_unchecked(
        name.into(),
        Value::Native(Rc::new(NativeFunction {
            name,
            arity,
            kind: NativeKind::Plain(body),
        })),
        false,
    );
}

fn define_intrinsic(env: &EnvRef, name: &'static str, arity: usize, kind: NativeKind) {
    env.borrow_mut().define_unchecked(
        name.into(),
        Value::Native(Rc::new(NativeFunction { name, arity, kind })),
        false,
    );
}

fn native_clock(_: &[Value]) -> Result<Value, RuntimeError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::new("无法取得时刻"))?
        .as_secs_f64();
    Ok(Value::Number(seconds))
}

fn native_abs(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match arguments[0] {
        Value::Number(value) => Ok(Value::Number(value.abs())),
        ref value => Err(RuntimeError::new(format!(
            "“绝对值”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_sqrt(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match arguments[0] {
        Value::Number(value) if value >= 0.0 => Ok(Value::Number(value.sqrt())),
        Value::Number(_) => Err(RuntimeError::new("负数不可求实平方根")),
        ref value => Err(RuntimeError::new(format!(
            "“平方根”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_pow(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match (&arguments[0], &arguments[1]) {
        (Value::Number(base), Value::Number(exponent)) => Ok(Value::Number(base.powf(*exponent))),
        (left, right) => Err(type_pair_error("求幂", left, right)),
    }
}

fn native_floor(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        number_argument(arguments, 0, "下取整")?.floor(),
    ))
}

fn native_ceil(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        number_argument(arguments, 0, "上取整")?.ceil(),
    ))
}

fn native_round(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        number_argument(arguments, 0, "四舍五入")?.round(),
    ))
}

fn native_sin(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(number_argument(arguments, 0, "正弦")?.sin()))
}

fn native_cos(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(number_argument(arguments, 0, "余弦")?.cos()))
}

fn native_min(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        number_argument(arguments, 0, "最小")?.min(number_argument(arguments, 1, "最小")?),
    ))
}

fn native_max(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        number_argument(arguments, 0, "最大")?.max(number_argument(arguments, 1, "最大")?),
    ))
}

fn native_path_join(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::path_join(
        string_argument(arguments, 0, "合并")?,
        string_argument(arguments, 1, "合并")?,
    )))
}

fn native_path_parent(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(optional_string(crate::stdlib::path_parent(
        string_argument(arguments, 0, "父级")?,
    )))
}

fn native_path_file_name(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(optional_string(crate::stdlib::path_file_name(
        string_argument(arguments, 0, "文件名")?,
    )))
}

fn native_path_extension(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(optional_string(crate::stdlib::path_extension(
        string_argument(arguments, 0, "扩展名")?,
    )))
}

fn native_path_is_absolute(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::path_is_absolute(
        string_argument(arguments, 0, "是否绝对")?,
    )))
}

fn native_path_normalize(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::path_normalize(
        string_argument(arguments, 0, "规范化")?,
    )))
}

fn native_env_read(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let name = string_argument(arguments, 0, "环境.读取")?;
    match std::env::var(name) {
        Ok(value) => Ok(Value::String(value)),
        Err(std::env::VarError::NotPresent) => Ok(Value::Nil),
        Err(std::env::VarError::NotUnicode(_)) => Err(RuntimeError::new(format!(
            "环境变量“{name}”不是 UTF-8 文字"
        ))),
    }
}

fn native_env_exists(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(
        std::env::var_os(string_argument(arguments, 0, "环境.存在")?).is_some(),
    ))
}

fn native_current_dir(_: &[Value]) -> Result<Value, RuntimeError> {
    std::env::current_dir()
        .map(|path| Value::String(path.to_string_lossy().into_owned()))
        .map_err(|error| RuntimeError::new(format!("不能取得当前目录：{error}")))
}

fn native_os(_: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(std::env::consts::OS.into()))
}

fn native_arch(_: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(std::env::consts::ARCH.into()))
}

fn native_process_run(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let program = string_argument(arguments, 0, "进程.执行")?;
    let process_arguments = string_sequence_argument(arguments, 1, "进程.执行")?;
    let directory = match &arguments[2] {
        Value::Nil => None,
        Value::String(directory) => Some(directory.as_str()),
        value => {
            return Err(RuntimeError::new(format!(
                "“进程.执行”第三参数须为文或空，不可为{}",
                value.type_name()
            )));
        }
    };
    let timeout = nonnegative_safe_u64_argument(arguments, 3, "进程.执行")?;
    let output = crate::stdlib::process_run(program, &process_arguments, directory, timeout)
        .map_err(RuntimeError::new)?;
    Ok(string_key_map(vec![
        ("状态", Value::Number(f64::from(output.status))),
        ("成功", Value::Bool(output.success)),
        ("标准输出", Value::String(output.stdout)),
        ("标准错误", Value::String(output.stderr)),
    ]))
}

fn native_sha256(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::sha256(string_argument(
        arguments, 0, "SHA256",
    )?)))
}

fn native_hmac_sha256(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let key = bytes_argument(arguments, 0, "哈希.HMACSHA256")?;
    let body = bytes_argument(arguments, 1, "哈希.HMACSHA256")?;
    crate::stdlib::hmac_sha256(&key, &body)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|message| RuntimeError::bytes("BYTES_CRYPTO", message))
}

fn native_constant_time_equal(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let left = bytes_argument(arguments, 0, "哈希.恒时相等")?;
    let right = bytes_argument(arguments, 1, "哈希.恒时相等")?;
    Ok(Value::Bool(crate::stdlib::constant_time_equal(
        &left, &right,
    )))
}

fn native_hex_encode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::hex_encode(string_argument(
        arguments,
        0,
        "十六进制",
    )?)))
}

fn native_hex_decode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::hex_decode(string_argument(arguments, 0, "解十六进制")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_percent_encode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::percent_encode(
        string_argument(arguments, 0, "百分号")?,
    )))
}

fn native_percent_decode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::percent_decode(string_argument(arguments, 0, "解百分号")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_stats_sum(arguments: &[Value]) -> Result<Value, RuntimeError> {
    native_statistic(arguments, "总和", crate::stdlib::stats_sum)
}

fn native_stats_mean(arguments: &[Value]) -> Result<Value, RuntimeError> {
    native_statistic(arguments, "平均", crate::stdlib::stats_mean)
}

fn native_stats_median(arguments: &[Value]) -> Result<Value, RuntimeError> {
    native_statistic(arguments, "中位数", crate::stdlib::stats_median)
}

fn native_stats_variance(arguments: &[Value]) -> Result<Value, RuntimeError> {
    native_statistic(arguments, "方差", crate::stdlib::stats_variance)
}

fn native_stats_stddev(arguments: &[Value]) -> Result<Value, RuntimeError> {
    native_statistic(arguments, "标准差", crate::stdlib::stats_stddev)
}

fn native_statistic(
    arguments: &[Value],
    function: &str,
    statistic: fn(&[f64]) -> Result<f64, String>,
) -> Result<Value, RuntimeError> {
    let numbers = number_sequence_argument(arguments, 0, function)?;
    statistic(&numbers)
        .map(Value::Number)
        .map_err(RuntimeError::new)
}

fn native_csv_parse(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let rows = crate::stdlib::csv_parse(string_argument(arguments, 0, "CSV.解析")?)
        .map_err(RuntimeError::new)?;
    Ok(Value::List(Rc::new(RefCell::new(
        rows.into_iter()
            .map(|row| {
                Value::List(Rc::new(RefCell::new(
                    row.into_iter().map(Value::String).collect(),
                )))
            })
            .collect(),
    ))))
}

fn native_csv_stringify(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let rows = string_table_argument(arguments, 0, "CSV.序列化")?;
    Ok(Value::String(crate::stdlib::csv_stringify(&rows)))
}

fn native_random_unit(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::seeded_random_unit(number_argument(arguments, 0, "随机.小数")?)
        .map(Value::Number)
        .map_err(RuntimeError::new)
}

fn native_random_integer(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::seeded_random_integer(
        number_argument(arguments, 0, "随机.整数")?,
        number_argument(arguments, 1, "随机.整数")?,
        number_argument(arguments, 2, "随机.整数")?,
    )
    .map(Value::Number)
    .map_err(RuntimeError::new)
}

fn native_random_bool(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::seeded_random_bool(number_argument(arguments, 0, "随机.布尔")?)
        .map(Value::Bool)
        .map_err(RuntimeError::new)
}

fn native_secure_random_bytes(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let length = nonnegative_usize_argument(
        arguments,
        0,
        "随机.安全字节",
        crate::stdlib::SECURE_RANDOM_MAX_BYTES,
    )?;
    crate::stdlib::secure_random_bytes(length)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|message| RuntimeError::bytes("BYTES_RANDOM", message))
}

fn native_stable_uuid(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::stable_uuid(string_argument(
        arguments,
        0,
        "标识.稳定UUID",
    )?)))
}

fn native_is_uuid(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::is_uuid(string_argument(
        arguments,
        0,
        "标识.是否UUID",
    )?)))
}

fn native_stable_short_id(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::stable_short_id(
        string_argument(arguments, 0, "标识.稳定短码")?,
        number_argument(arguments, 1, "标识.稳定短码")?,
    )
    .map(Value::String)
    .map_err(RuntimeError::new)
}

fn native_template_interpolate(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::template_interpolate(
        string_argument(arguments, 0, "模板.插值")?,
        string_argument(arguments, 1, "模板.插值")?,
        string_argument(arguments, 2, "模板.插值")?,
    )
    .map(Value::String)
    .map_err(RuntimeError::new)
}

fn native_html_escape(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::html_escape(string_argument(
        arguments,
        0,
        "模板.转义HTML",
    )?)))
}

fn native_html_unescape(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::html_unescape(
        string_argument(arguments, 0, "模板.反转义HTML")?,
    )))
}

fn native_is_email(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::is_email(string_argument(
        arguments,
        0,
        "校验.电子邮件",
    )?)))
}

fn native_is_ipv4(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::is_ipv4(string_argument(
        arguments,
        0,
        "校验.IPv4",
    )?)))
}

fn native_is_hex_color(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::is_hex_color(string_argument(
        arguments,
        0,
        "校验.十六进制色",
    )?)))
}

fn native_is_identifier(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::is_identifier(string_argument(
        arguments,
        0,
        "校验.标识符",
    )?)))
}

fn native_base64_encode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::base64_encode(
        string_argument(arguments, 0, "Base64.编码")?,
    )))
}

fn native_base64_decode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::base64_decode(string_argument(arguments, 0, "Base64.解码")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_base64_url_encode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(crate::stdlib::base64_url_encode(
        string_argument(arguments, 0, "Base64.网址编码")?,
    )))
}

fn native_base64_url_decode(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::base64_url_decode(string_argument(arguments, 0, "Base64.解网址编码")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_regex_is_match(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::regex_is_match(
        string_argument(arguments, 0, "正则.匹配")?,
        string_argument(arguments, 1, "正则.匹配")?,
    )
    .map(Value::Bool)
    .map_err(RuntimeError::new)
}

fn native_regex_first(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::regex_first(
        string_argument(arguments, 0, "正则.首项")?,
        string_argument(arguments, 1, "正则.首项")?,
    )
    .map(optional_string)
    .map_err(RuntimeError::new)
}

fn native_regex_replace_all(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::regex_replace_all(
        string_argument(arguments, 0, "正则.替换全部")?,
        string_argument(arguments, 1, "正则.替换全部")?,
        string_argument(arguments, 2, "正则.替换全部")?,
    )
    .map(Value::String)
    .map_err(RuntimeError::new)
}

fn native_regex_split(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::regex_split(
        string_argument(arguments, 0, "正则.分割")?,
        string_argument(arguments, 1, "正则.分割")?,
    )
    .map(|parts| {
        Value::List(Rc::new(RefCell::new(
            parts.into_iter().map(Value::String).collect(),
        )))
    })
    .map_err(RuntimeError::new)
}

fn native_url_is_valid(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::url_is_valid(string_argument(
        arguments,
        0,
        "URL.是否合法",
    )?)))
}

fn native_url_scheme(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_scheme(string_argument(arguments, 0, "URL.协议")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_url_host(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_host(string_argument(arguments, 0, "URL.主机")?)
        .map(optional_string)
        .map_err(RuntimeError::new)
}

fn native_url_port(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_port(string_argument(arguments, 0, "URL.端口")?)
        .map(|port| port.map_or(Value::Nil, Value::Number))
        .map_err(RuntimeError::new)
}

fn native_url_path(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_path(string_argument(arguments, 0, "URL.路径")?)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_url_query_value(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_query_value(
        string_argument(arguments, 0, "URL.查询值")?,
        string_argument(arguments, 1, "URL.查询值")?,
    )
    .map(optional_string)
    .map_err(RuntimeError::new)
}

fn native_url_join(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::url_join(
        string_argument(arguments, 0, "URL.合并")?,
        string_argument(arguments, 1, "URL.合并")?,
    )
    .map(Value::String)
    .map_err(RuntimeError::new)
}

fn native_date_is_valid(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(crate::stdlib::date_is_valid(string_argument(
        arguments,
        0,
        "日期.是否合法",
    )?)))
}

fn native_date_is_leap_year(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::date_is_leap_year(number_argument(arguments, 0, "日期.是否闰年")?)
        .map(Value::Bool)
        .map_err(RuntimeError::new)
}

fn native_date_add_days(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::date_add_days(
        string_argument(arguments, 0, "日期.加天")?,
        number_argument(arguments, 1, "日期.加天")?,
    )
    .map(Value::String)
    .map_err(RuntimeError::new)
}

fn native_date_days_between(arguments: &[Value]) -> Result<Value, RuntimeError> {
    crate::stdlib::date_days_between(
        string_argument(arguments, 0, "日期.相差天数")?,
        string_argument(arguments, 1, "日期.相差天数")?,
    )
    .map(Value::Number)
    .map_err(RuntimeError::new)
}

fn native_http_date(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let millis = nonnegative_safe_u64_argument(arguments, 0, "日期.HTTP日期")?;
    crate::stdlib::format_http_date(millis)
        .map(Value::String)
        .map_err(RuntimeError::new)
}

fn native_parse_http_date(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(
        crate::stdlib::parse_http_date(string_argument(arguments, 0, "日期.解析HTTP日期")?)
            .map_or(Value::Nil, |millis| Value::Number(millis as f64)),
    )
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Nil, Value::String)
}

fn native_bytes_from_text(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let text = string_argument(arguments, 0, "字节.从文字")?;
    if text.len() > crate::stdlib::BYTES_MAX_VALUE_BYTES {
        return Err(RuntimeError::bytes(
            "BYTES_LIMIT",
            format!(
                "字节串不得超过 {} 字节",
                crate::stdlib::BYTES_MAX_VALUE_BYTES
            ),
        ));
    }
    Ok(Value::Bytes(Rc::new(text.as_bytes().to_vec())))
}

fn native_bytes_to_text(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let bytes = bytes_argument(arguments, 0, "字节.转文字")?;
    String::from_utf8(bytes.as_ref().clone())
        .map(Value::String)
        .map_err(|_| RuntimeError::bytes("BYTES_UTF8", "字节串不是有效的 UTF-8 文字"))
}

fn native_bytes_length(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Number(
        bytes_argument(arguments, 0, "字节.长度")?.len() as f64,
    ))
}

fn native_bytes_slice(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let bytes = bytes_argument(arguments, 0, "字节.切片")?;
    let start = nonnegative_usize_argument(arguments, 1, "字节.切片", bytes.len())?;
    let end = nonnegative_usize_argument(arguments, 2, "字节.切片", bytes.len())?;
    crate::stdlib::bytes_slice(&bytes, start, end)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|message| RuntimeError::bytes("BYTES_RANGE", message))
}

fn native_bytes_concat(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let left = bytes_argument(arguments, 0, "字节.拼接")?;
    let right = bytes_argument(arguments, 1, "字节.拼接")?;
    crate::stdlib::bytes_concat(&left, &right)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|message| RuntimeError::bytes("BYTES_LIMIT", message))
}

fn native_bytes_find(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let source = bytes_argument(arguments, 0, "字节.查找")?;
    let needle = bytes_argument(arguments, 1, "字节.查找")?;
    Ok(crate::stdlib::bytes_find(&source, &needle)
        .map_or(Value::Nil, |index| Value::Number(index as f64)))
}

fn native_bytes_from_numbers(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let numbers = number_sequence_argument(arguments, 0, "字节.从数列")?;
    crate::stdlib::bytes_from_numbers(&numbers)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|message| RuntimeError::bytes("BYTES_VALUE", message))
}

fn native_bytes_to_numbers(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let bytes = bytes_argument(arguments, 0, "字节.转数列")?;
    Ok(Value::List(Rc::new(RefCell::new(
        bytes
            .iter()
            .map(|byte| Value::Number(f64::from(*byte)))
            .collect(),
    ))))
}

fn native_trim(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(
        string_argument(arguments, 0, "修剪")?.trim().into(),
    ))
}

fn native_split(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let text = string_argument(arguments, 0, "分割")?;
    let separator = string_argument(arguments, 1, "分割")?;
    let parts = if separator.is_empty() {
        text.chars()
            .map(|character| Value::String(character.to_string()))
            .collect()
    } else {
        text.split(separator)
            .map(|part| Value::String(part.into()))
            .collect()
    };
    Ok(Value::List(Rc::new(RefCell::new(parts))))
}

fn native_replace(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(
        string_argument(arguments, 0, "替换")?.replace(
            string_argument(arguments, 1, "替换")?,
            string_argument(arguments, 2, "替换")?,
        ),
    ))
}

fn native_starts_with(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(
        string_argument(arguments, 0, "始于")?.starts_with(string_argument(arguments, 1, "始于")?),
    ))
}

fn native_ends_with(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(
        string_argument(arguments, 0, "终于")?.ends_with(string_argument(arguments, 1, "终于")?),
    ))
}

fn native_uppercase(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(
        string_argument(arguments, 0, "大写")?.to_uppercase(),
    ))
}

fn native_lowercase(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(
        string_argument(arguments, 0, "小写")?.to_lowercase(),
    ))
}

fn native_characters(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::List(Rc::new(RefCell::new(
        string_argument(arguments, 0, "字符列")?
            .chars()
            .map(|character| Value::String(character.to_string()))
            .collect(),
    ))))
}

fn native_join(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let separator = string_argument(arguments, 1, "联结")?;
    let items: Vec<Value> = match &arguments[0] {
        Value::List(items) => items.borrow().clone(),
        Value::Tuple(items) => items.as_ref().clone(),
        value => {
            return Err(RuntimeError::new(format!(
                "“联结”须收列或元，不可收{}",
                value.type_name()
            )));
        }
    };
    let parts = items
        .iter()
        .enumerate()
        .map(|(index, item)| match item {
            Value::String(text) => Ok(text.clone()),
            value => Err(RuntimeError::new(format!(
                "“联结”第 {} 项须为文，不可为{}",
                index + 1,
                value.type_name()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::String(parts.join(separator)))
}

fn native_millis(_: &[Value]) -> Result<Value, RuntimeError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::new("无法取得时刻"))?
        .as_millis();
    Ok(Value::Number(millis as f64))
}

fn native_sleep(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let seconds = number_argument(arguments, 0, "等待")?;
    if !(0.0..=60.0).contains(&seconds) {
        return Err(RuntimeError::new("“等待”秒数须在 0 至 60 之间"));
    }
    std::thread::sleep(Duration::from_secs_f64(seconds));
    Ok(Value::Nil)
}

fn native_read_file(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "读取")?;
    fs::read_to_string(path)
        .map(Value::String)
        .map_err(|error| RuntimeError::new(format!("不能读取“{path}”：{error}")))
}

fn native_read_bytes(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "文件.读取字节")?;
    crate::stdlib::read_file_bytes(Path::new(path))
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(|source| match source {
            crate::stdlib::FileBytesError::Io(message) => {
                RuntimeError::new(format!("“{path}”：{message}"))
            }
            crate::stdlib::FileBytesError::Limit(message) => {
                RuntimeError::bytes("BYTES_LIMIT", format!("“{path}”：{message}"))
            }
        })
}

fn native_write_file(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "写入")?;
    let text = string_argument(arguments, 1, "写入")?;
    fs::write(path, text)
        .map(|()| Value::Number(text.len() as f64))
        .map_err(|error| RuntimeError::new(format!("不能写入“{path}”：{error}")))
}

fn native_write_bytes(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "文件.写入字节")?;
    let bytes = bytes_argument(arguments, 1, "文件.写入字节")?;
    fs::write(path, bytes.as_ref())
        .map(|()| Value::Number(bytes.len() as f64))
        .map_err(|error| RuntimeError::new(format!("不能写入“{path}”：{error}")))
}

fn native_append_file(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "追加")?;
    let text = string_argument(arguments, 1, "追加")?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| RuntimeError::new(format!("不能打开“{path}”：{error}")))?;
    file.write_all(text.as_bytes())
        .map_err(|error| RuntimeError::new(format!("不能追加“{path}”：{error}")))?;
    Ok(Value::Number(text.len() as f64))
}

fn native_append_bytes(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "文件.追加字节")?;
    let bytes = bytes_argument(arguments, 1, "文件.追加字节")?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| RuntimeError::new(format!("不能打开“{path}”：{error}")))?;
    file.write_all(&bytes)
        .map_err(|error| RuntimeError::new(format!("不能追加“{path}”：{error}")))?;
    Ok(Value::Number(bytes.len() as f64))
}

fn native_file_status(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "文件.状态")?;
    let status = crate::stdlib::file_status(Path::new(path)).map_err(RuntimeError::new)?;
    Ok(string_key_map(vec![
        ("种类", Value::String(status.kind.into())),
        ("字节数", Value::Number(status.bytes as f64)),
        ("只读", Value::Bool(status.readonly)),
        (
            "修改毫秒",
            status
                .modified_millis
                .map_or(Value::Nil, |millis| Value::Number(millis as f64)),
        ),
    ]))
}

fn native_path_exists(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::Bool(
        Path::new(string_argument(arguments, 0, "存在")?).exists(),
    ))
}

fn native_read_directory(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let path = string_argument(arguments, 0, "目录")?;
    let mut entries = fs::read_dir(path)
        .map_err(|error| RuntimeError::new(format!("不能读取目录“{path}”：{error}")))?
        .map(|entry| {
            entry
                .map(|entry| Value::String(entry.file_name().to_string_lossy().into_owned()))
                .map_err(|error| RuntimeError::new(format!("不能读取目录项：{error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(compare_values_for_sort);
    Ok(Value::List(Rc::new(RefCell::new(entries))))
}

fn native_json_parse(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let text = string_argument(arguments, 0, "JSON.解析")?;
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| RuntimeError::new(format!("JSON 解析失败：{error}")))?;
    json_to_value(json)
}

fn native_json_stringify(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let json = value_to_json(&arguments[0])?;
    serde_json::to_string(&json)
        .map(Value::String)
        .map_err(|error| RuntimeError::new(format!("JSON 序列化失败：{error}")))
}

fn native_http_get(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    host_limits: crate::budget::HostResourceLimits,
) -> Result<Value, RuntimeError> {
    http_request(
        "GET",
        string_argument(arguments, 0, "网络.获取")?,
        None,
        permissions,
        host_limits,
    )
    .map(Value::String)
}

fn native_http_post(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    host_limits: crate::budget::HostResourceLimits,
) -> Result<Value, RuntimeError> {
    http_request(
        "POST",
        string_argument(arguments, 0, "网络.发文")?,
        Some(string_argument(arguments, 1, "网络.发文")?),
        permissions,
        host_limits,
    )
    .map(Value::String)
}

fn native_http_request(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    host_limits: crate::budget::HostResourceLimits,
) -> Result<Value, RuntimeError> {
    let timeout = positive_u64_argument(arguments, 3, "网络.请求", "超时毫秒")?;
    let max_bytes = positive_u64_argument(arguments, 4, "网络.请求", "最大字节")?;
    let response = crate::stdlib::http_request_with_options_and_limits_guarded(
        string_argument(arguments, 0, "网络.请求")?,
        string_argument(arguments, 1, "网络.请求")?,
        Some(string_argument(arguments, 2, "网络.请求")?),
        permissions,
        crate::stdlib::HttpRequestBudget::new(timeout, max_bytes, host_limits),
    )
    .map_err(RuntimeError::network)?;
    let headers = Value::Map(Rc::new(RefCell::new(YanxuMap {
        entries: response
            .headers
            .into_iter()
            .map(|(name, value)| (Value::String(name), Value::String(value)))
            .collect(),
    })));
    Ok(Value::Map(Rc::new(RefCell::new(YanxuMap {
        entries: vec![
            ("状态".into(), Value::Number(f64::from(response.status))),
            ("地址".into(), Value::String(response.url)),
            ("首部".into(), headers),
            ("正文".into(), Value::String(response.body)),
        ]
        .into_iter()
        .map(|(key, value)| (Value::String(key), value))
        .collect(),
    }))))
}

fn native_http_bytes_request(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    host_limits: crate::budget::HostResourceLimits,
) -> Result<Value, RuntimeError> {
    let headers = string_map_argument(arguments, 2, "网络.请求字节")?;
    let body = match &arguments[3] {
        Value::Nil => None,
        Value::Bytes(bytes) => Some(bytes.clone()),
        value => {
            return Err(RuntimeError::bytes(
                "BYTES_TYPE",
                format!(
                    "“网络.请求字节”第 4 参数须为字节串或空，不可为{}",
                    value.type_name()
                ),
            ));
        }
    };
    let timeout = positive_u64_argument(arguments, 4, "网络.请求字节", "超时毫秒")?;
    let max_bytes = positive_u64_argument(arguments, 5, "网络.请求字节", "最大字节")?;
    let response = crate::stdlib::http_request_bytes_with_options_and_limits_guarded(
        string_argument(arguments, 0, "网络.请求字节")?,
        string_argument(arguments, 1, "网络.请求字节")?,
        &headers,
        body.as_deref().map(Vec::as_slice),
        permissions,
        crate::stdlib::HttpRequestBudget::new(timeout, max_bytes, host_limits),
    )
    .map_err(RuntimeError::network)?;
    let headers = Value::Map(Rc::new(RefCell::new(YanxuMap {
        entries: response
            .headers
            .into_iter()
            .map(|(name, value)| (Value::String(name), Value::String(value)))
            .collect(),
    })));
    Ok(string_key_map(vec![
        ("状态", Value::Number(f64::from(response.status))),
        ("地址", Value::String(response.url)),
        ("首部", headers),
        ("正文", Value::Bytes(Rc::new(response.body))),
    ]))
}

fn native_socket_tcp_connect(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    quota: &crate::stdlib::SocketQuota,
) -> Result<Value, RuntimeError> {
    let address = string_argument(arguments, 0, "套接字.TCP连接")?;
    let timeout = socket_timeout_argument(arguments, 1, "套接字.TCP连接")?;
    crate::stdlib::socket_tcp_connect_guarded(address, timeout, permissions, quota)
        .map(|socket| Value::Socket(Rc::new(RefCell::new(socket))))
        .map_err(RuntimeError::socket)
}

fn native_socket_tcp_listen(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    quota: &crate::stdlib::SocketQuota,
) -> Result<Value, RuntimeError> {
    let address = string_argument(arguments, 0, "套接字.TCP监听")?;
    crate::stdlib::socket_tcp_listen_guarded(address, permissions, quota)
        .map(|socket| Value::Socket(Rc::new(RefCell::new(socket))))
        .map_err(RuntimeError::socket)
}

fn native_socket_accept(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let timeout = socket_timeout_argument(arguments, 1, "套接字.接受")?;
    let socket = socket_argument(arguments, 0, "套接字.接受")?;
    let (accepted, peer) = crate::stdlib::socket_accept(&mut socket.borrow_mut(), timeout)
        .map_err(RuntimeError::socket)?;
    Ok(string_key_map(vec![
        ("套接字", Value::Socket(Rc::new(RefCell::new(accepted)))),
        ("对端", Value::String(peer)),
    ]))
}

fn native_socket_send(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let text = string_argument(arguments, 1, "套接字.发送")?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.发送")?;
    let socket = socket_argument(arguments, 0, "套接字.发送")?;
    crate::stdlib::socket_send(&mut socket.borrow_mut(), text, timeout)
        .map(|written| Value::Number(written as f64))
        .map_err(RuntimeError::socket)
}

fn native_socket_receive(arguments: &[Value], host_max_bytes: u64) -> Result<Value, RuntimeError> {
    let max_bytes = socket_max_bytes_argument(arguments, 1, "套接字.接收", host_max_bytes)?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.接收")?;
    let socket = socket_argument(arguments, 0, "套接字.接收")?;
    crate::stdlib::socket_receive(&mut socket.borrow_mut(), max_bytes, timeout)
        .map(Value::String)
        .map_err(RuntimeError::socket)
}

fn native_socket_send_bytes(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let bytes = bytes_argument(arguments, 1, "套接字.发送字节")?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.发送字节")?;
    let socket = socket_argument(arguments, 0, "套接字.发送字节")?;
    crate::stdlib::socket_send_bytes(&mut socket.borrow_mut(), &bytes, timeout)
        .map(|written| Value::Number(written as f64))
        .map_err(RuntimeError::socket)
}

fn native_socket_receive_bytes(
    arguments: &[Value],
    host_max_bytes: u64,
) -> Result<Value, RuntimeError> {
    let max_bytes = socket_max_bytes_argument(arguments, 1, "套接字.接收字节", host_max_bytes)?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.接收字节")?;
    let socket = socket_argument(arguments, 0, "套接字.接收字节")?;
    let received =
        crate::stdlib::socket_receive_bytes(&mut socket.borrow_mut(), max_bytes, timeout)
            .map_err(RuntimeError::socket)?;
    Ok(string_key_map(vec![
        ("数据", Value::Bytes(Rc::new(received.bytes))),
        ("已结束", Value::Bool(received.eof)),
    ]))
}

fn native_socket_read_exact(
    arguments: &[Value],
    host_max_bytes: u64,
) -> Result<Value, RuntimeError> {
    let byte_count = socket_max_bytes_argument(arguments, 1, "套接字.精确读取", host_max_bytes)?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.精确读取")?;
    let socket = socket_argument(arguments, 0, "套接字.精确读取")?;
    crate::stdlib::socket_read_exact_bytes(&mut socket.borrow_mut(), byte_count, timeout)
        .map(|bytes| Value::Bytes(Rc::new(bytes)))
        .map_err(RuntimeError::socket)
}

fn native_socket_udp_bind(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
    quota: &crate::stdlib::SocketQuota,
) -> Result<Value, RuntimeError> {
    let address = string_argument(arguments, 0, "套接字.UDP绑定")?;
    crate::stdlib::socket_udp_bind_guarded(address, permissions, quota)
        .map(|socket| Value::Socket(Rc::new(RefCell::new(socket))))
        .map_err(RuntimeError::socket)
}

fn native_socket_udp_send_to(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
) -> Result<Value, RuntimeError> {
    let text = string_argument(arguments, 1, "套接字.UDP发送至")?;
    let address = string_argument(arguments, 2, "套接字.UDP发送至")?;
    let timeout = socket_timeout_argument(arguments, 3, "套接字.UDP发送至")?;
    let socket = socket_argument(arguments, 0, "套接字.UDP发送至")?;
    crate::stdlib::socket_udp_send_to_guarded(
        &mut socket.borrow_mut(),
        text,
        address,
        timeout,
        permissions,
    )
    .map(|written| Value::Number(written as f64))
    .map_err(RuntimeError::socket)
}

fn native_socket_udp_receive_from(
    arguments: &[Value],
    host_max_bytes: u64,
) -> Result<Value, RuntimeError> {
    let max_bytes = socket_max_bytes_argument(arguments, 1, "套接字.UDP接收自", host_max_bytes)?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.UDP接收自")?;
    let socket = socket_argument(arguments, 0, "套接字.UDP接收自")?;
    let (text, peer) =
        crate::stdlib::socket_udp_receive_from(&mut socket.borrow_mut(), max_bytes, timeout)
            .map_err(RuntimeError::socket)?;
    Ok(string_key_map(vec![
        ("正文", Value::String(text)),
        ("对端", Value::String(peer)),
    ]))
}

fn native_socket_udp_send_bytes_to(
    arguments: &[Value],
    permissions: &crate::permissions::PermissionSet,
) -> Result<Value, RuntimeError> {
    let bytes = bytes_argument(arguments, 1, "套接字.UDP发送字节至")?;
    let address = string_argument(arguments, 2, "套接字.UDP发送字节至")?;
    let timeout = socket_timeout_argument(arguments, 3, "套接字.UDP发送字节至")?;
    let socket = socket_argument(arguments, 0, "套接字.UDP发送字节至")?;
    crate::stdlib::socket_udp_send_bytes_to_guarded(
        &mut socket.borrow_mut(),
        &bytes,
        address,
        timeout,
        permissions,
    )
    .map(|written| Value::Number(written as f64))
    .map_err(RuntimeError::socket)
}

fn native_socket_udp_receive_bytes_from(
    arguments: &[Value],
    host_max_bytes: u64,
) -> Result<Value, RuntimeError> {
    let max_bytes =
        socket_max_bytes_argument(arguments, 1, "套接字.UDP接收字节自", host_max_bytes)?;
    let timeout = socket_timeout_argument(arguments, 2, "套接字.UDP接收字节自")?;
    let socket = socket_argument(arguments, 0, "套接字.UDP接收字节自")?;
    let (bytes, peer) =
        crate::stdlib::socket_udp_receive_bytes_from(&mut socket.borrow_mut(), max_bytes, timeout)
            .map_err(RuntimeError::socket)?;
    Ok(string_key_map(vec![
        ("数据", Value::Bytes(Rc::new(bytes))),
        ("对端", Value::String(peer)),
    ]))
}

fn native_socket_local_address(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let socket = socket_argument(arguments, 0, "套接字.本地地址")?;
    crate::stdlib::socket_local_address(&socket.borrow())
        .map(Value::String)
        .map_err(RuntimeError::socket)
}

fn native_socket_peer_address(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let socket = socket_argument(arguments, 0, "套接字.对端地址")?;
    crate::stdlib::socket_peer_address(&socket.borrow())
        .map(|address| address.map_or(Value::Nil, Value::String))
        .map_err(RuntimeError::socket)
}

fn native_socket_close(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let socket = socket_argument(arguments, 0, "套接字.关闭")?;
    crate::stdlib::socket_close(&mut socket.borrow_mut())
        .map(|()| Value::Nil)
        .map_err(RuntimeError::socket)
}

fn native_socket_shutdown_write(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let socket = socket_argument(arguments, 0, "套接字.关闭写端")?;
    crate::stdlib::socket_shutdown_write(&mut socket.borrow_mut())
        .map(|()| Value::Nil)
        .map_err(RuntimeError::socket)
}

fn native_socket_set_nodelay(arguments: &[Value]) -> Result<Value, RuntimeError> {
    let enabled = bool_argument(arguments, 1, "套接字.TCP无延迟")?;
    let socket = socket_argument(arguments, 0, "套接字.TCP无延迟")?;
    crate::stdlib::socket_set_nodelay(&mut socket.borrow_mut(), enabled)
        .map(|()| Value::Nil)
        .map_err(RuntimeError::socket)
}

fn socket_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Rc<RefCell<crate::stdlib::SocketHandle>>, RuntimeError> {
    match &arguments[index] {
        Value::Socket(socket) => Ok(socket.clone()),
        value => Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为套接字，不可为{}",
            index + 1,
            value.type_name()
        ))),
    }
}

fn string_key_map(entries: Vec<(&'static str, Value)>) -> Value {
    Value::Map(Rc::new(RefCell::new(YanxuMap {
        entries: entries
            .into_iter()
            .map(|(key, value)| (Value::String(key.into()), value))
            .collect(),
    })))
}

fn native_assert(arguments: &[Value]) -> Result<Value, RuntimeError> {
    if arguments[0].truthy() {
        Ok(Value::Nil)
    } else {
        Err(RuntimeError::new(format!("断言失败：{}", arguments[1])))
    }
}

fn native_assert_equal(arguments: &[Value]) -> Result<Value, RuntimeError> {
    if values_equal(&arguments[0], &arguments[1]) {
        Ok(Value::Nil)
    } else {
        Err(RuntimeError::new(format!(
            "相等断言失败：左为 {}，右为 {}",
            arguments[0], arguments[1]
        )))
    }
}

fn native_assert_not_nil(arguments: &[Value]) -> Result<Value, RuntimeError> {
    if matches!(arguments[0], Value::Nil) {
        Err(RuntimeError::new(format!("非空断言失败：{}", arguments[1])))
    } else {
        Ok(Value::Nil)
    }
}

fn native_length(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::String(text) => Ok(Value::Number(text.chars().count() as f64)),
        Value::Bytes(bytes) => Ok(Value::Number(bytes.len() as f64)),
        Value::List(items) => Ok(Value::Number(items.borrow().len() as f64)),
        Value::Tuple(items) => Ok(Value::Number(items.len() as f64)),
        Value::Map(map) => Ok(Value::Number(map.borrow().entries.len() as f64)),
        value => Err(RuntimeError::new(format!(
            "“长度”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_type(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(arguments[0].type_name()))
}

fn native_pop(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::List(items) => items
            .borrow_mut()
            .pop()
            .ok_or_else(|| RuntimeError::new("不可从空列弹出")),
        value => Err(RuntimeError::new(format!(
            "“弹出”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_has_key(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::Map(map) => Ok(Value::Bool(
            map.borrow()
                .entries
                .iter()
                .any(|(key, _)| values_equal(key, &arguments[1])),
        )),
        value => Err(RuntimeError::new(format!(
            "“有键”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_remove(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::List(items) => {
            let index = list_index(&arguments[1])?;
            let mut items = items.borrow_mut();
            if index >= items.len() {
                return Err(RuntimeError::new(format!("列下标 {index} 超出范围")));
            }
            Ok(items.remove(index))
        }
        value => Err(RuntimeError::new(format!(
            "“删除”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_keys(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::Map(map) => Ok(Value::List(Rc::new(RefCell::new(
            map.borrow()
                .entries
                .iter()
                .map(|(key, _)| key.clone())
                .collect(),
        )))),
        value => Err(RuntimeError::new(format!(
            "“键列”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_values(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::Map(map) => Ok(Value::List(Rc::new(RefCell::new(
            map.borrow()
                .entries
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
        )))),
        value => Err(RuntimeError::new(format!(
            "“值列”不适用于{}",
            value.type_name()
        ))),
    }
}

fn number_argument(arguments: &[Value], index: usize, function: &str) -> Result<f64, RuntimeError> {
    match &arguments[index] {
        Value::Number(number) if number.is_finite() => Ok(*number),
        value => Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为有限数，不可为{}",
            index + 1,
            value.type_name()
        ))),
    }
}

fn positive_u64_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
    name: &str,
) -> Result<u64, RuntimeError> {
    let number = number_argument(arguments, index, function)?;
    if number <= 0.0 || number.fract() != 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(RuntimeError::new(format!(
            "“{function}”之{name}须为安全正整数"
        )));
    }
    Ok(number as u64)
}

fn nonnegative_safe_u64_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<u64, RuntimeError> {
    let number = number_argument(arguments, index, function)?;
    if number < 0.0 || number.fract() != 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为安全非负整数",
            index + 1
        )));
    }
    Ok(number as u64)
}

fn nonnegative_usize_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let number = number_argument(arguments, index, function)?;
    if number < 0.0 || number.fract() != 0.0 || number > maximum as f64 {
        return Err(RuntimeError::bytes(
            "BYTES_RANGE",
            format!("“{function}”第 {} 参数须为 0..={maximum} 的整数", index + 1),
        ));
    }
    Ok(number as usize)
}

fn socket_timeout_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<u64, RuntimeError> {
    let number = number_argument(arguments, index, function)?;
    if number <= 0.0
        || number.fract() != 0.0
        || number > crate::stdlib::SOCKET_MAX_TIMEOUT_MILLIS as f64
    {
        return Err(RuntimeError::socket(crate::stdlib::SocketError::new(
            "SOCKET_TIMEOUT",
            format!(
                "套接字超时须在 1..={} 毫秒之间",
                crate::stdlib::SOCKET_MAX_TIMEOUT_MILLIS
            ),
        )));
    }
    Ok(number as u64)
}

fn socket_max_bytes_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
    host_max_bytes: u64,
) -> Result<u64, RuntimeError> {
    let number = number_argument(arguments, index, function)?;
    if number <= 0.0 || number.fract() != 0.0 || number > host_max_bytes as f64 {
        return Err(RuntimeError::socket(crate::stdlib::SocketError::new(
            "SOCKET_LIMIT",
            format!("套接字单次接收上限须在 1..={} 字节之间", host_max_bytes),
        )));
    }
    Ok(number as u64)
}

fn string_argument<'a>(
    arguments: &'a [Value],
    index: usize,
    function: &str,
) -> Result<&'a str, RuntimeError> {
    match &arguments[index] {
        Value::String(text) => Ok(text),
        value => Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为文，不可为{}",
            index + 1,
            value.type_name()
        ))),
    }
}

fn bool_argument(arguments: &[Value], index: usize, function: &str) -> Result<bool, RuntimeError> {
    match arguments.get(index) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(value) => Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为理，不可为{}",
            index + 1,
            value.type_name()
        ))),
        None => Err(RuntimeError::new(format!(
            "“{function}”缺少第 {} 参数",
            index + 1
        ))),
    }
}

fn bytes_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Rc<Vec<u8>>, RuntimeError> {
    match arguments.get(index) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(value) => Err(RuntimeError::bytes(
            "BYTES_TYPE",
            format!(
                "“{function}”第 {} 参数须为字节串，不可为{}",
                index + 1,
                value.type_name()
            ),
        )),
        None => Err(RuntimeError::bytes(
            "BYTES_TYPE",
            format!("“{function}”缺少第 {} 参数", index + 1),
        )),
    }
}

fn string_map_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Vec<(String, String)>, RuntimeError> {
    let Value::Map(map) = &arguments[index] else {
        return Err(RuntimeError::new(format!(
            "“{function}”第 {} 参数须为文至文之典，不可为{}",
            index + 1,
            arguments[index].type_name()
        )));
    };
    map.borrow()
        .entries
        .iter()
        .enumerate()
        .map(|(entry_index, (key, value))| match (key, value) {
            (Value::String(key), Value::String(value)) => Ok((key.clone(), value.clone())),
            _ => Err(RuntimeError::new(format!(
                "“{function}”首部第 {} 项之键和值皆须为文",
                entry_index + 1
            ))),
        })
        .collect()
}

fn number_sequence_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Vec<f64>, RuntimeError> {
    let values: Vec<Value> = match &arguments[index] {
        Value::List(values) => values.borrow().clone(),
        Value::Tuple(values) => values.as_ref().clone(),
        value => {
            return Err(RuntimeError::new(format!(
                "“{function}”第 {} 参数须为数列，不可为{}",
                index + 1,
                value.type_name()
            )));
        }
    };
    values
        .iter()
        .enumerate()
        .map(|(item_index, value)| match value {
            Value::Number(number) if number.is_finite() => Ok(*number),
            other => Err(RuntimeError::new(format!(
                "“{function}”数据第 {} 项须为有限数，不可为{}",
                item_index + 1,
                other.type_name()
            ))),
        })
        .collect()
}

fn string_sequence_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Vec<String>, RuntimeError> {
    let values: Vec<Value> = match &arguments[index] {
        Value::List(values) => values.borrow().clone(),
        Value::Tuple(values) => values.as_ref().clone(),
        value => {
            return Err(RuntimeError::new(format!(
                "“{function}”第 {} 参数须为文列，不可为{}",
                index + 1,
                value.type_name()
            )));
        }
    };
    values
        .iter()
        .enumerate()
        .map(|(item_index, value)| match value {
            Value::String(text) => Ok(text.clone()),
            other => Err(RuntimeError::new(format!(
                "“{function}”第 {} 参数第 {} 项须为文，不可为{}",
                index + 1,
                item_index + 1,
                other.type_name()
            ))),
        })
        .collect()
}

fn string_table_argument(
    arguments: &[Value],
    index: usize,
    function: &str,
) -> Result<Vec<Vec<String>>, RuntimeError> {
    let rows: Vec<Value> = match &arguments[index] {
        Value::List(values) => values.borrow().clone(),
        Value::Tuple(values) => values.as_ref().clone(),
        value => {
            return Err(RuntimeError::new(format!(
                "“{function}”第 {} 参数须为二维文列，不可为{}",
                index + 1,
                value.type_name()
            )));
        }
    };
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            let fields: Vec<Value> = match row {
                Value::List(values) => values.borrow().clone(),
                Value::Tuple(values) => values.as_ref().clone(),
                value => {
                    return Err(RuntimeError::new(format!(
                        "“{function}”第 {} 行须为文列，不可为{}",
                        row_index + 1,
                        value.type_name()
                    )));
                }
            };
            fields
                .iter()
                .enumerate()
                .map(|(field_index, field)| match field {
                    Value::String(text) => Ok(text.clone()),
                    value => Err(RuntimeError::new(format!(
                        "“{function}”第 {} 行第 {} 项须为文，不可为{}",
                        row_index + 1,
                        field_index + 1,
                        value.type_name()
                    ))),
                })
                .collect()
        })
        .collect()
}

fn json_to_value(json: serde_json::Value) -> Result<Value, RuntimeError> {
    Ok(match json {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => Value::Number(
            value
                .as_f64()
                .ok_or_else(|| RuntimeError::new("JSON 数超出言序数值范围"))?,
        ),
        serde_json::Value::String(value) => Value::String(value),
        serde_json::Value::Array(items) => Value::List(Rc::new(RefCell::new(
            items
                .into_iter()
                .map(json_to_value)
                .collect::<Result<Vec<_>, _>>()?,
        ))),
        serde_json::Value::Object(entries) => Value::Map(Rc::new(RefCell::new(YanxuMap {
            entries: entries
                .into_iter()
                .map(|(key, value)| Ok((Value::String(key), json_to_value(value)?)))
                .collect::<Result<Vec<_>, RuntimeError>>()?,
        }))),
    })
}

fn value_to_json(value: &Value) -> Result<serde_json::Value, RuntimeError> {
    Ok(match value {
        Value::Nil => serde_json::Value::Null,
        Value::Bool(value) => serde_json::Value::Bool(*value),
        Value::Number(value) if value.is_finite() => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| RuntimeError::new("数值不可表示为 JSON"))?,
        Value::String(value) => serde_json::Value::String(value.clone()),
        Value::List(items) => serde_json::Value::Array(
            items
                .borrow()
                .iter()
                .map(value_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Tuple(items) => serde_json::Value::Array(
            items
                .iter()
                .map(value_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Map(map) => {
            let mut object = serde_json::Map::new();
            for (key, value) in &map.borrow().entries {
                let Value::String(key) = key else {
                    return Err(RuntimeError::new("JSON 对象之典键必须为文"));
                };
                object.insert(key.clone(), value_to_json(value)?);
            }
            serde_json::Value::Object(object)
        }
        value => {
            return Err(RuntimeError::new(format!(
                "{}不可序列化为 JSON",
                value.type_name()
            )));
        }
    })
}

fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    permissions: &crate::permissions::PermissionSet,
    host_limits: crate::budget::HostResourceLimits,
) -> Result<String, RuntimeError> {
    crate::stdlib::http_request_with_options_and_limits_guarded(
        method,
        url,
        body,
        permissions,
        crate::stdlib::HttpRequestBudget::new(
            crate::stdlib::HTTP_DEFAULT_TIMEOUT_MILLIS,
            crate::stdlib::HTTP_DEFAULT_MAX_BYTES,
            host_limits,
        ),
    )
    .map(|response| response.body)
    .map_err(RuntimeError::network)
}

fn numeric_pair(
    left: Value,
    right: Value,
    action: &str,
    operation: impl FnOnce(f64, f64) -> f64,
) -> Result<Value, RuntimeError> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => Ok(Value::Number(operation(a, b))),
        (a, b) => Err(type_pair_error(action, &a, &b)),
    }
}

fn compare_pair(
    left: Value,
    right: Value,
    action: &str,
    operation: impl FnOnce(f64, f64) -> bool,
) -> Result<Value, RuntimeError> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => Ok(Value::Bool(operation(a, b))),
        (a, b) => Err(type_pair_error(action, &a, &b)),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Nil, Value::Nil) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bytes(a), Value::Bytes(b)) => a == b,
        (Value::Function(a), Value::Function(b)) => Rc::ptr_eq(a, b),
        (Value::Native(a), Value::Native(b)) => Rc::ptr_eq(a, b),
        (Value::Class(a), Value::Class(b)) => Rc::ptr_eq(a, b),
        (Value::Protocol(a), Value::Protocol(b)) => Rc::ptr_eq(a, b),
        (Value::Instance(a), Value::Instance(b)) => Rc::ptr_eq(a, b),
        (Value::Module(a), Value::Module(b)) => Rc::ptr_eq(a, b),
        (Value::List(a), Value::List(b)) => Rc::ptr_eq(a, b),
        (Value::Tuple(a), Value::Tuple(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| values_equal(a, b))
        }
        (Value::Map(a), Value::Map(b)) => Rc::ptr_eq(a, b),
        (Value::Iterator(a), Value::Iterator(b)) => Rc::ptr_eq(a, b),
        (Value::Error(a), Value::Error(b)) => Rc::ptr_eq(a, b),
        (Value::Task(a), Value::Task(b)) => Rc::ptr_eq(a, b),
        (Value::Socket(a), Value::Socket(b)) => Rc::ptr_eq(a, b),
        _ => false,
    }
}

fn ensure_callable(value: &Value, subject: &str) -> Result<(), RuntimeError> {
    if matches!(
        value,
        Value::Function(_) | Value::Native(_) | Value::Class(_)
    ) {
        Ok(())
    } else {
        Err(RuntimeError::new(format!(
            "{subject}须可调用，不可为{}",
            value.type_name()
        )))
    }
}

fn finite_number(value: &Value, subject: &str) -> Result<f64, RuntimeError> {
    match value {
        Value::Number(number) if number.is_finite() => Ok(*number),
        Value::Number(_) => Err(RuntimeError::new(format!("{subject}须为有限数"))),
        value => Err(RuntimeError::new(format!(
            "{subject}须为数，不可为{}",
            value.type_name()
        ))),
    }
}

fn iterator_result(value: Option<Value>) -> Value {
    let (available, value) = value.map_or((false, Value::Nil), |value| (true, value));
    Value::Tuple(Rc::new(vec![Value::Bool(available), value]))
}

fn parse_iterator_result(value: Value) -> Result<Option<Value>, RuntimeError> {
    let Value::Tuple(items) = value else {
        return Err(RuntimeError::new("“遍次”须归还（是否尚有，值）二元组"));
    };
    if items.len() != 2 {
        return Err(RuntimeError::new("“遍次”须归还（是否尚有，值）二元组"));
    }
    match &items[0] {
        Value::Bool(true) => Ok(Some(items[1].clone())),
        Value::Bool(false) => Ok(None),
        value => Err(RuntimeError::new(format!(
            "“遍次”结果首项须为理，不可为{}",
            value.type_name()
        ))),
    }
}

fn compare_values_for_sort(left: &Value, right: &Value) -> Ordering {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.total_cmp(right),
        (Value::String(left), Value::String(right)) => left.cmp(right),
        (left, right) => left
            .type_name()
            .cmp(&right.type_name())
            .then_with(|| left.to_string().cmp(&right.to_string())),
    }
}

fn clone_field_value(value: &Value) -> Value {
    match value {
        Value::List(items) => Value::List(Rc::new(RefCell::new(
            items.borrow().iter().map(clone_field_value).collect(),
        ))),
        Value::Tuple(items) => Value::Tuple(Rc::new(items.iter().map(clone_field_value).collect())),
        Value::Map(map) => Value::Map(Rc::new(RefCell::new(YanxuMap {
            entries: map
                .borrow()
                .entries
                .iter()
                .map(|(key, value)| (clone_field_value(key), clone_field_value(value)))
                .collect(),
        }))),
        value => value.clone(),
    }
}

fn type_pair_error(action: &str, left: &Value, right: &Value) -> RuntimeError {
    RuntimeError::new(format!(
        "不可令{}与{}{}",
        left.type_name(),
        right.type_name(),
        action
    ))
}

fn arity_error(name: &str, expected: usize, actual: usize) -> RuntimeError {
    RuntimeError::new(format!("“{name}”应收 {expected} 个参数，实得 {actual} 个"))
}

fn list_index(value: &Value) -> Result<usize, RuntimeError> {
    match value {
        Value::Number(number) if number.is_finite() && *number >= 0.0 && number.fract() == 0.0 => {
            Ok(*number as usize)
        }
        _ => Err(RuntimeError::new("下标须为非负整数")),
    }
}

fn slice_bounds(
    start: Option<&Value>,
    end: Option<&Value>,
    length: usize,
) -> Result<(usize, usize), RuntimeError> {
    let start = start.map(list_index).transpose()?.unwrap_or(0);
    let end = end.map(list_index).transpose()?.unwrap_or(length);
    if start > end {
        return Err(RuntimeError::new(format!(
            "切片起点 {start} 不可大于终点 {end}"
        )));
    }
    if end > length {
        return Err(RuntimeError::new(format!(
            "切片终点 {end} 超出长度 {length}"
        )));
    }
    Ok((start, end))
}

fn map_insert(map: &mut YanxuMap, key: Value, value: Value) -> Result<(), RuntimeError> {
    if !matches!(
        key,
        Value::Number(_) | Value::String(_) | Value::Bool(_) | Value::Nil
    ) {
        return Err(RuntimeError::new(format!(
            "{}不可作为典之键",
            key.type_name()
        )));
    }
    if let Some((_, old_value)) = map
        .entries
        .iter_mut()
        .find(|(old_key, _)| values_equal(old_key, &key))
    {
        *old_value = value;
    } else {
        map.entries.push((key, value));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_with;
    use std::io::Read;

    #[test]
    fn dropping_interpreter_releases_the_global_environment() {
        let globals = {
            let mut interpreter = Interpreter::silent();
            let globals = Rc::downgrade(&interpreter.globals);
            run_with(
                &mut interpreter,
                "法 恒（）：数 则 归 1；终 定 值：法 为 恒；",
            )
            .unwrap();
            globals
        };
        assert!(globals.upgrade().is_none());
    }

    #[test]
    fn persistent_interpreter_collects_replaced_closure_environments() {
        let mut interpreter = Interpreter::silent();
        run_with(
            &mut interpreter,
            r#"
                法 外层（甲：数）：法 则
                    法 内层（乙：数）：数 则 归 甲 加 乙；终
                    归 内层；
                终
                法 清理（）：空 则
                    法 自环（）：法 则 归 自环；终
                    归 空；
                终
                令 加值：法 为 外层（10）；
                清理（）；
                言 加值（5）；
            "#,
        )
        .unwrap();
        let global_id = Rc::as_ptr(&interpreter.globals);
        let escaped = interpreter
            .heap_environments
            .iter()
            .find(|environment| environment.as_ptr() != global_id && environment.strong_count() > 0)
            .cloned()
            .expect("逃逸闭包环境应保持存活");
        assert_eq!(
            interpreter
                .heap_environments
                .iter()
                .filter(|environment| environment.strong_count() > 0)
                .count(),
            2
        );

        run_with(&mut interpreter, "置 加值 为 外层（20）；言 加值（1）；").unwrap();
        assert!(escaped.upgrade().is_none());
        assert_eq!(interpreter.output(), &["15", "21"]);
    }

    #[test]
    fn persistent_interpreter_collects_bound_method_cycles() {
        let mut interpreter = Interpreter::silent();
        run_with(
            &mut interpreter,
            r#"
                类 盒 则
                    法 取（）：数 则 归 1；终
                终
                令 盒子 为 盒（）；
                令 绑定 为 盒子.取；
                置 盒子.回调 为 绑定；
            "#,
        )
        .unwrap();
        let global_id = Rc::as_ptr(&interpreter.globals);
        let bound_environment = interpreter
            .heap_environments
            .iter()
            .find(|environment| environment.as_ptr() != global_id && environment.strong_count() > 0)
            .cloned()
            .expect("绑定方法环境应登记并保持存活");

        run_with(&mut interpreter, "置 盒子 为 空；置 绑定 为 空；").unwrap();
        assert!(bound_environment.upgrade().is_none());
    }

    #[test]
    fn runs_loop_and_function() {
        let source = r#"
            法 倍增（数值：数）：数 则
                归 数值 乘 2；
            终
            令 次：数 为 0；
            当 次 小于 3 则
                言 倍增（次）；
                置 次 为 次 加 1；
            终
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["0", "2", "4"]);
    }

    #[test]
    fn has_lexical_closures() {
        let source = r#"
            法 外层（甲：数）：法 则
                法 内层（乙：数）：数 则 归 甲 加 乙；终
                归 内层；
            终
            令 加十：法 为 外层（10）；
            言 加十（5）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["15"]);
    }

    #[test]
    fn enforces_variable_types() {
        let mut interpreter = Interpreter::silent();
        let error =
            run_with(&mut interpreter, "令 年岁：数 为 18；置 年岁 为「十八」；").unwrap_err();
        assert!(error.to_string().contains("注为数，不可纳入文"));
    }

    #[test]
    fn enforces_structured_container_and_nullable_types_at_runtime() {
        let mut interpreter = Interpreter::silent();
        run_with(
            &mut interpreter,
            "定 数列：列<数> 为【1，2】；定 可空：数? 为 空；",
        )
        .unwrap();
        let error = run_with(&mut interpreter, "定 坏列：列<数> 为【1，「二」】；").unwrap_err();
        assert!(error.to_string().contains("注为列<数>，不可纳入列"));
    }

    #[test]
    fn constructs_instances_and_binds_methods() {
        let source = r#"
            类 人 则
                法 初始化（姓名：文）则 置 此.姓名 为 姓名；终
                法 问候（）：文 则 归 「吾名」 加 此.姓名；终
            终
            令 子：人 为 人（「言序」）；
            言 子.问候（）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["吾名言序"]);
    }

    #[test]
    fn supports_protocol_fields_visibility_readonly_and_static_members() {
        let source = r#"
            协 可命名 则 域 姓名：文；法 显示（）：文；终
            类 用户 纳 可命名 则
                公 只 域 姓名：文；
                私 域 密语：文 为「山河」；
                公 静 域 数量：数 为 0；
                法 初始化（姓名：文）则
                    置 此.姓名 为 姓名；
                    置 用户.数量 为 用户.数量 加 1；
                终
                法 显示（）：文 则 归 此.姓名；终
                私 法 取密（）：文 则 归 此.密语；终
                公 静 法 新建（姓名：文）：用户 则 归 用户（姓名）；终
            终
            定 某人：可命名 为 用户.新建（「言序」）；
            言 某人.显示（）；
            言 用户.数量；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["言序", "1"]);

        let private = run_with(&mut interpreter, "言 某人.密语；").unwrap_err();
        assert!(private.to_string().contains("私域"));
        let readonly = run_with(&mut interpreter, "置 某人.姓名 为「再改」；").unwrap_err();
        assert!(readonly.to_string().contains("只读域"));
    }

    #[test]
    fn standard_text_math_json_time_and_test_modules_work_together() {
        let source = r#"
            引「标准:文字」为 文字；
            引「标准:数学」为 数学；
            引「标准:JSON」为 JSON；
            引「标准:时间」为 时间；
            引「标准:测试」为 测试；
            言 文字.联结（文字.分割（「甲,乙,丙」，「,」），「-」）；
            言 数学.最大（数学.下取整（3.9），2）；
            定 数据：典 为 JSON.解析（「{\"名\":\"言序\",\"版\":7}」）；
            言 数据【「名」】；
            言 JSON.序列化（【真，空，3】）；
            测试.相等（文字.修剪（「  善  」），「善」）；
            言 时间.今（） 大于 0；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &["甲-乙-丙", "3", "言序", "[true,null,3.0]", "真"]
        );
    }

    #[test]
    fn expanded_path_environment_hash_encoding_statistics_and_csv_modules_work() {
        let source = r#"
            引「标准:路径」为 路径；
            引「标准:环境」为 环境；
            引「标准:哈希」为 哈希；
            引「标准:编码」为 编码；
            引「标准:统计」为 统计；
            引「标准:CSV」为 CSV；
            定 十六：文 为 编码.十六进制（「言序」）；
            言 十六；
            言 编码.解十六进制（十六）；
            言 编码.解百分号（编码.百分号（「言序 /?」））；
            言 哈希.SHA256（「言序」）；
            言 统计.总和（【1，2，3，4】）；
            言 统计.中位数（【4，1，3，2】）；
            定 表：列<列<文>> 为 CSV.解析（「姓名,诗句\n子衿,\"青青子衿,悠悠我心\"」）；
            言 表【1】【1】；
            言 CSV.序列化（表）；
            言 路径.文件名（「甲/乙.yx」）；
            言 环境.系统（）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &[
                crate::stdlib::hex_encode("言序"),
                "言序".into(),
                "言序 /?".into(),
                crate::stdlib::sha256("言序"),
                "10".into(),
                "2.5".into(),
                "青青子衿,悠悠我心".into(),
                "姓名,诗句\n子衿,\"青青子衿,悠悠我心\"".into(),
                "乙.yx".into(),
                std::env::consts::OS.into(),
            ]
        );

        let error = run_with(&mut interpreter, "言 编码.解十六进制（「坏」）；").unwrap_err();
        assert!(error.to_string().contains("十六进制"));
        let error = run_with(&mut interpreter, "言 统计.平均（【】）；").unwrap_err();
        assert!(error.to_string().contains("不可为空"));
    }

    #[test]
    fn post_one_zero_pure_standard_modules_work_together() {
        let source = r#"
            引「标准:随机」为 随机；
            引「标准:标识」为 标识；
            引「标准:模板」为 模板；
            引「标准:校验」为 校验；
            言 随机.小数（42）；
            言 随机.整数（42，10，20）；
            言 随机.布尔（42）；
            定 标号：文 为 标识.稳定UUID（「言序」）；
            言 标号；言 标识.是否UUID（标号）；
            言 标识.稳定短码（「言序」，8）；
            定 转义：文 为 模板.转义HTML（「<言序>」）；
            言 转义；言 模板.反转义HTML（转义）；
            言 模板.插值（「问{{name}}安」，「name」，「子衿」）；
            言 校验.电子邮件（「hello@yanxu.dev」）；
            言 校验.IPv4（「127.0.0.1」）；
            言 校验.十六进制色（「#7fef6d」）；
            言 校验.标识符（「言序_1」）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output()[1], "13");
        assert_eq!(
            interpreter.output()[3],
            "7fef6d82-32f7-8809-a49c-11a4e2944571"
        );
        assert_eq!(
            &interpreter.output()[4..],
            [
                "真",
                "7fef6d82",
                "&lt;言序&gt;",
                "<言序>",
                "问子衿安",
                "真",
                "真",
                "真",
                "真"
            ]
        );

        let error = run_with(&mut interpreter, "言 随机.整数（1，2，2）；").unwrap_err();
        assert!(error.to_string().contains("下界小于上界"));
    }

    #[test]
    fn one_one_standard_modules_work_together() {
        let source = r#"
            引「标准:Base64」为 Base64；
            引「标准:正则」为 正则；
            引「标准:URL」为 URL；
            引「标准:日期」为 日期；
            定 编码值：文 为 Base64.编码（「言序」）；
            言 编码值；言 Base64.解码（编码值）；
            言 Base64.解网址编码（Base64.网址编码（「言序/语言」））；
            言 正则.匹配（「^言.+$」，「言序」）；
            言 正则.首项（「[0-9]+」，「甲12乙」）；
            言 正则.替换全部（「[0-9]+」，「甲12乙34」，「数」）；
            言 正则.分割（「[,，]」，「甲,乙，丙」）；
            定 地址：文 为「https://yanxu.dev:8443/docs/start?lang=zh」；
            言 URL.协议（地址）；言 URL.主机（地址）；言 URL.端口（地址）；
            言 URL.路径（地址）；言 URL.查询值（地址，「lang」）；
            言 URL.合并（「https://yanxu.dev/docs/」，「../download」）；
            言 日期.是否合法（「2024-02-29」）；
            言 日期.是否闰年（2000）；
            言 日期.加天（「2024-02-28」，2）；
            言 日期.相差天数（「2024-02-28」，「2024-03-01」）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &[
                "6KiA5bqP",
                "言序",
                "言序/语言",
                "真",
                "12",
                "甲数乙数",
                "【甲，乙，丙】",
                "https",
                "yanxu.dev",
                "8443",
                "/docs/start",
                "zh",
                "https://yanxu.dev/download",
                "真",
                "真",
                "2024-03-01",
                "2",
            ]
        );
    }

    #[test]
    fn async_tasks_await_cancel_cache_and_join_structurally() {
        let source = r#"
            异 法 倍增（值：数）：数 则 归 值 乘 2；终
            定 甲：任务<数> 为 倍增（3）；
            言 任务状态（甲）；
            言 候 甲；
            言 任务状态（甲）；
            言 候 甲；
            定 乙：任务<数> 为 倍增（4）；
            定 丙：任务<数> 为 倍增（5）；
            言 并候（【乙，丙】）；
            定 丁：任务<数> 为 倍增（6）；
            言 取消（丁）；
            言 任务状态（丁）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &["待行", "6", "完成", "6", "【8，10】", "真", "取消"]
        );

        let error = run_with(&mut interpreter, "言 候 丁；").unwrap_err();
        assert!(error.to_string().contains("已取消"));
    }

    #[test]
    fn structured_join_cancels_remaining_tasks_after_failure() {
        let source = r#"
            异 法 失败（）：数 则 抛「先败」；终
            异 法 成功（）：数 则 归 7；终
            定 坏：任务<数> 为 失败（）；
            定 后：任务<数> 为 成功（）；
            试 则 并候（【坏，后】）；救 错 则 言 错.消息；终
            言 任务状态（后）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["先败", "取消"]);
    }

    #[test]
    fn standard_file_and_http_modules_have_real_io_and_errors() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-stdlib-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("文.txt");
        let source = format!(
            "引「标准:文件」为 文件；文件.写入（「{}」，「甲」）；文件.追加（「{}」，「乙」）；言 文件.读取（「{}」）；言 文件.存在（「{}」）；",
            file.display(),
            file.display(),
            file.display(),
            file.display()
        );
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, &source).unwrap();
        assert_eq!(interpreter.output(), &["甲乙", "真"]);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nyanxu!",
                )
                .unwrap();
        });
        let source = format!("引「标准:网络」为 网络；言 网络.获取（「http://{address}/健康」）；");
        let mut network = Interpreter::silent();
        run_with(&mut network, &source).unwrap();
        server.join().unwrap();
        assert_eq!(network.output(), &["yanxu!"]);

        let error = run_with(&mut network, "网络.获取（「ftp://example.com」）；").unwrap_err();
        assert!(error.to_string().contains("NET_URL"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn socket_module_runs_tcp_in_the_tree_interpreter_and_exposes_structured_errors() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 16];
            let length = stream.read(&mut request).unwrap();
            assert_eq!(&request[..length], "问安".as_bytes());
            stream.write_all("安好".as_bytes()).unwrap();
        });
        let source = format!(
            r#"
                引「标准:套接字」为 套接字；
                定 流 为 套接字.TCP连接（「{address}」，1000）；
                言 类型（流）；
                言 流 是 套接字；
                言 套接字.发送（流，「问安」，1000）；
                言 套接字.接收（流，16，1000）；
                言 套接字.对端地址（流）等于「{address}」；
                套接字.关闭（流）；
                试 则 套接字.发送（流，「晚安」，1000）；
                救 错 则 言 错.代码；言 错.类别；终
            "#
        );
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, &source).unwrap();
        server.join().unwrap();
        assert_eq!(
            interpreter.output(),
            &["套接字", "真", "6", "安好", "真", "SOCKET_STATE", "套接字"]
        );

        let mut sandbox =
            Interpreter::silent_with_permissions(crate::permissions::PermissionSet::sandboxed());
        let error = run_with(
            &mut sandbox,
            &format!("引「标准:套接字」为 套接字；套接字.TCP连接（「{address}」，10）；"),
        )
        .unwrap_err();
        let crate::YanxuError::Runtime(error) = error else {
            panic!("应为运行错误");
        };
        assert_eq!(error.code, "SOCKET_PERMISSION");
        assert_eq!(error.category(), "套接字");
    }

    #[test]
    fn supports_lists_maps_indexes_and_iteration() {
        let source = r#"
            定 人名：列 为 【「甲」，「乙」，「丙」】；
            置 人名【1】 为 「仲」；
            令 次序：典 为 {「甲」：1，「仲」：2，「丙」：3}；
            令 合计：数 为 0；
            逐 姓名：文 于 人名 则
                置 合计 为 合计 加 次序【姓名】；
            终
            言 人名；
            言 合计；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["【甲，仲，丙】", "6"]);
    }

    #[test]
    fn iterator_pipeline_is_lazy_and_shares_one_protocol() {
        let source = r#"
            令 调用数：数 为 0；
            法 加倍（值：数）：数 则
                置 调用数 为 调用数 加 1；
                归 值 乘 2；
            终
            定 管道：遍器 为 映射（范围（0，4），加倍）；
            言 调用数；
            言 续（管道）；
            言 调用数；
            令 合计：数 为 0；
            逐 值：数 于 管道 则
                置 合计 为 合计 加 值；
            终
            言 合计；
            言 调用数；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["0", "（真，0）", "1", "12", "4"]);
    }

    #[test]
    fn user_objects_implement_iterator_protocol() {
        let source = r#"
            类 计数器 则
                法 初始化（上限：数）则
                    置 此.当前 为 0；
                    置 此.上限 为 上限；
                终
                法 遍始（）：计数器 则 归 此；终
                法 遍次（）：元 则
                    若 此.当前 小于 此.上限 则
                        定 所得：数 为 此.当前；
                        置 此.当前 为 此.当前 加 1；
                        归（真，所得）；
                    否则
                        归（假，空）；
                    终
                终
            终
            令 合计：数 为 0；
            逐 值：数 于 计数器（4）则
                置 合计 为 合计 加 值；
            终
            言 合计；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["6"]);
    }

    #[test]
    fn data_primitives_cover_transform_search_and_ordering() {
        let source = r#"
            法 为四（值：数）：理 则 归 值 等于 4；终
            法 大于二（值：数）：理 则 归 值 大于 2；终
            法 求和（合计：数，值：数）：数 则 归 合计 加 值；终
            言 反转（排序（【3，1，2】））；
            言 包含（「天地玄黄」，「玄」）；
            言 寻找（范围（0，5），大于二）；
            言 折叠（筛选（范围（0，5），为四），0，求和）；
            言 反转（步进范围（5，0，-2））；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &["【3，2，1】", "真", "（真，3）", "4", "【1，3，5】"]
        );
    }

    #[test]
    fn iterator_protocol_reports_invalid_steps_and_results() {
        let mut interpreter = Interpreter::silent();
        let error = run_with(&mut interpreter, "步进范围（0，10，0）；").unwrap_err();
        assert!(error.to_string().contains("步长不可为零"));

        let source = r#"
            类 坏遍器 则
                法 遍次（）：数 则 归 1；终
            终
            逐 值 于 坏遍器（）则 言 值；终
        "#;
        let error = run_with(&mut interpreter, source).unwrap_err();
        assert!(error.to_string().contains("须归还（是否尚有，值）二元组"));
    }

    #[test]
    fn catches_structured_errors_with_frames() {
        let source = r#"
            法 内层（）：数 则 归 1 除 0；终
            法 外层（）：数 则 归 内层（）；终
            试 则
                外层（）；
            救 所误 则
                言 所误.消息；
                言 长度（所误.踪迹）；
            终
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["不可除以零", "2"]);
    }

    struct RecordingHook(Rc<RefCell<Vec<DebugSnapshot>>>);

    impl DebugHook for RecordingHook {
        fn before_statement(&mut self, snapshot: &DebugSnapshot) -> Result<(), String> {
            self.0.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }

    #[test]
    fn debugger_observes_frames_and_visible_variables_before_statements() {
        let snapshots = Rc::new(RefCell::new(Vec::new()));
        let mut interpreter = Interpreter::silent();
        interpreter.set_debug_hook(Box::new(RecordingHook(snapshots.clone())));
        crate::run_with(
            &mut interpreter,
            "法 加一（值：数）：数 则 令 结果：数 为 值 加 1；归 结果；终 言 加一（2）；",
        )
        .unwrap();
        let snapshots = snapshots.borrow();
        let inside_function = snapshots
            .iter()
            .find(|snapshot| {
                snapshot
                    .frames
                    .first()
                    .is_some_and(|frame| frame.name.contains("加一"))
            })
            .unwrap();
        assert!(inside_function.frames.len() >= 2);
        assert!(
            inside_function.frames[0]
                .variables
                .iter()
                .any(|variable| variable.name == "值" && variable.value == "2")
        );
    }

    #[test]
    fn constants_reject_rebinding_but_allow_collection_mutation() {
        let mut interpreter = Interpreter::silent();
        run_with(
            &mut interpreter,
            "定 数列：列 为【1】；置 数列【0】为 2；言 数列【0】；",
        )
        .unwrap();
        assert_eq!(interpreter.output(), &["2"]);
        let error = run_with(&mut interpreter, "置 数列 为【3】；").unwrap_err();
        assert!(error.to_string().contains("乃定值，不可改写"));
    }

    #[test]
    fn supports_immutable_tuples_and_slices() {
        let source = r#"
            定 坐标：元 为（10，20，30）；
            定 名录：列 为【「甲」，「乙」，「丙」，「丁」】；
            言 坐标【1】；
            言 坐标【1：】；
            言 名录【：2】；
            言 「天地玄黄」【1：3】；
            言 坐标 等于（10，20，30）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(
            interpreter.output(),
            &["20", "（20，30）", "【甲，乙】", "地玄", "真"]
        );

        let error = run_with(&mut interpreter, "置 坐标【0】为 1；").unwrap_err();
        assert!(error.to_string().contains("元不可用下标改写"));
    }

    #[test]
    fn runtime_errors_render_source_and_call_locations() {
        let statements = crate::parse_named(
            "法 求值（）：数 则\n    归 1 除 0；\n终\n求值（）；\n",
            "诊断例.yx",
        )
        .unwrap();
        let mut interpreter = Interpreter::silent();
        let error = interpreter.execute(&statements).unwrap_err().to_string();
        assert!(error.contains("诊断例.yx:2:7"));
        assert!(error.contains("归 1 除 0；"));
        assert!(error.contains("法“求值”（诊断例.yx:1:1）"));
    }
}

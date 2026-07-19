//! 言序栈式虚拟机。
//!
//! VM 只消费字节码和原型，不调用树解释器。词法环境、闭包、对象与模块
//! 都有独立的运行时表示。

mod native;

use crate::ast::Visibility;
use crate::bytecode::{
    Chunk, ClassPrototype, Constant, FieldPrototype, FunctionPrototype, Instruction,
};
use crate::source::Span;
use crate::type_model::{ModuleId, RuntimeType, TypeId, TypeLink};
use crate::{host_events, host_handles, native_abi_v2};
pub use native::VmNative;
use native::{NativeKind, StandardNative};
use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicPtr, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

type EnvRef = Rc<RefCell<Environment>>;

#[derive(Clone)]
pub enum VmValue {
    Number(f64),
    String(String),
    Bytes(Rc<Vec<u8>>),
    Bool(bool),
    Nil,
    List(Rc<RefCell<Vec<VmValue>>>),
    Tuple(Rc<Vec<VmValue>>),
    Map(Rc<RefCell<VmMap>>),
    Closure(Rc<VmClosure>),
    BoundMethod(Rc<VmClosure>, Rc<RefCell<VmInstance>>),
    Native(Rc<VmNative>),
    Class(Rc<VmClass>),
    Instance(Rc<RefCell<VmInstance>>),
    Module(Rc<VmModule>),
    Protocol(Rc<VmProtocol>),
    Iterator(Rc<RefCell<VmIterator>>),
    Error(Rc<VmErrorValue>),
    Task(Rc<RefCell<VmTask>>),
    Socket(Rc<RefCell<crate::stdlib::SocketHandle>>),
    NativeModuleV2(Rc<native_abi_v2::NativeExtensionV2>),
    NativeResource(u64),
}

impl fmt::Debug for VmValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self}")
    }
}

impl PartialEq for VmValue {
    fn eq(&self, other: &Self) -> bool {
        values_equal(self, other)
    }
}

impl VmValue {
    fn truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Bool(false))
    }

    pub fn type_name(&self) -> String {
        match self {
            Self::Number(_) => "数".into(),
            Self::String(_) => "文".into(),
            Self::Bytes(_) => "字节串".into(),
            Self::Bool(_) => "理".into(),
            Self::Nil => "空".into(),
            Self::List(_) => "列".into(),
            Self::Tuple(_) => "元".into(),
            Self::Map(_) => "典".into(),
            Self::Closure(_) | Self::BoundMethod(_, _) | Self::Native(_) => "法".into(),
            Self::Class(_) => "类".into(),
            Self::Instance(instance) => instance.borrow().class.type_id.name.clone(),
            Self::Module(_) => "模块".into(),
            Self::Protocol(_) => "协".into(),
            Self::Iterator(_) => "遍器".into(),
            Self::Error(_) => "误".into(),
            Self::Task(_) => "任务".into(),
            Self::Socket(_) => "套接字".into(),
            Self::NativeModuleV2(_) => "原生模块".into(),
            Self::NativeResource(_) => "原生资源".into(),
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}

impl fmt::Display for VmValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) if number.fract() == 0.0 => write!(formatter, "{number:.0}"),
            Self::Number(number) => write!(formatter, "{number}"),
            Self::String(text) => write!(formatter, "{text}"),
            Self::Bytes(bytes) => write!(formatter, "<字节串 {} 字节>", bytes.len()),
            Self::Bool(true) => formatter.write_str("真"),
            Self::Bool(false) => formatter.write_str("假"),
            Self::Nil => formatter.write_str("空"),
            Self::List(items) => render_items(formatter, &items.borrow(), '【', '】'),
            Self::Tuple(items) => render_items(formatter, items, '（', '）'),
            Self::Map(map) => {
                let rendered = map
                    .borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| format!("{key}：{value}"))
                    .collect::<Vec<_>>()
                    .join("，");
                write!(formatter, "{{{rendered}}}")
            }
            Self::Closure(function) => write!(formatter, "<法 {}>", function.prototype.name),
            Self::BoundMethod(function, _) => write!(formatter, "<法 {}>", function.prototype.name),
            Self::Native(function) => write!(formatter, "<天授之法 {}>", function.name),
            Self::Class(class) => write!(formatter, "<类 {}>", class.type_id.name),
            Self::Instance(instance) => {
                write!(
                    formatter,
                    "<{}之实例>",
                    instance.borrow().class.type_id.name
                )
            }
            Self::Module(module) => write!(formatter, "<模块 {}>", module.name),
            Self::Protocol(protocol) => write!(formatter, "<协 {}>", protocol.type_id.name),
            Self::Iterator(_) => formatter.write_str("<遍器>"),
            Self::Error(error) => write!(formatter, "<误 {}>", error.message),
            Self::Task(task) => write!(formatter, "<任务 {}>", task.borrow().status()),
            Self::Socket(socket) => {
                write!(formatter, "<套接字 {}>", socket.borrow().kind_name())
            }
            Self::NativeModuleV2(module) => write!(formatter, "<原生模块 {}>", module.name()),
            Self::NativeResource(handle) => write!(formatter, "<原生资源 {handle}>"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmError {
    pub code: &'static str,
    pub message: String,
    pub span: Span,
    pub frames: Vec<String>,
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            self.span
                .render("VM 运行有误", &format!("[{}] {}", self.code, self.message))
        )?;
        for frame in &self.frames {
            write!(formatter, "\n  经 {frame}")?;
        }
        Ok(())
    }
}

impl std::error::Error for VmError {}

impl VmError {
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
}

#[derive(Clone)]
struct Binding {
    value: VmValue,
    mutable: bool,
    type_ref: Option<RuntimeType>,
    type_environment: Option<Weak<RefCell<Environment>>>,
}

#[derive(Default)]
struct Environment {
    values: HashMap<String, Binding>,
    parent: Option<EnvRef>,
}

impl Environment {
    fn get(&self, name: &str) -> Option<VmValue> {
        self.values
            .get(name)
            .map(|binding| binding.value.clone())
            .or_else(|| self.parent.as_ref()?.borrow().get(name))
    }
}

pub struct VmClosure {
    prototype: Rc<FunctionPrototype>,
    closure: EnvRef,
    directory: PathBuf,
}

pub struct VmMap {
    entries: Vec<(VmValue, VmValue)>,
}

struct RuntimeField {
    prototype: FieldPrototype,
    initial: Option<VmValue>,
    owner: TypeId,
    type_environment: EnvRef,
}

struct RuntimeMethod {
    closure: Rc<VmClosure>,
    owner: TypeId,
}

pub struct VmClass {
    type_id: TypeId,
    superclass: Option<Rc<VmClass>>,
    protocols: HashSet<TypeId>,
    fields: HashMap<String, RuntimeField>,
    methods: HashMap<String, RuntimeMethod>,
    static_values: RefCell<HashMap<String, VmValue>>,
}

impl VmClass {
    fn field(&self, name: &str) -> Option<&RuntimeField> {
        self.fields
            .get(name)
            .or_else(|| self.superclass.as_ref()?.field(name))
    }

    fn method(&self, name: &str) -> Option<&RuntimeMethod> {
        self.methods
            .get(name)
            .or_else(|| self.superclass.as_ref()?.method(name))
    }

    fn has_instance_fields(&self) -> bool {
        self.fields.values().any(|field| !field.prototype.is_static)
            || self
                .superclass
                .as_ref()
                .is_some_and(|class| class.has_instance_fields())
    }

    fn initial_fields(&self) -> HashMap<String, VmValue> {
        let mut values = self
            .superclass
            .as_ref()
            .map_or_else(HashMap::new, |class| class.initial_fields());
        for (name, field) in &self.fields {
            if !field.prototype.is_static
                && let Some(initial) = &field.initial
            {
                values.insert(name.clone(), deep_clone(initial));
            }
        }
        values
    }

    fn static_storage(&self, name: &str) -> Option<&RefCell<HashMap<String, VmValue>>> {
        if self
            .fields
            .get(name)
            .is_some_and(|field| field.prototype.is_static)
        {
            Some(&self.static_values)
        } else {
            self.superclass.as_ref()?.static_storage(name)
        }
    }

    fn is_a(&self, type_id: &TypeId) -> bool {
        &self.type_id == type_id
            || self.protocols.contains(type_id)
            || self
                .superclass
                .as_ref()
                .is_some_and(|class| class.is_a(type_id))
    }

    fn superclass_of(&self, owner: &TypeId) -> Option<Rc<VmClass>> {
        if &self.type_id == owner {
            self.superclass.clone()
        } else {
            self.superclass
                .as_ref()
                .and_then(|class| class.superclass_of(owner))
        }
    }
}

pub struct VmInstance {
    class: Rc<VmClass>,
    fields: HashMap<String, VmValue>,
}

pub struct VmProtocol {
    type_id: TypeId,
}

pub struct VmModule {
    name: String,
    module_id: ModuleId,
    environment: EnvRef,
    exports: HashSet<String>,
}

pub struct VmErrorValue {
    code: &'static str,
    category: String,
    message: String,
    frames: Vec<String>,
    span: Span,
}

pub enum VmIterator {
    Values {
        values: Vec<VmValue>,
        index: usize,
    },
    Range {
        current: f64,
        end: f64,
        step: f64,
    },
    Object(Rc<RefCell<VmInstance>>),
    Mapped {
        source: Rc<RefCell<VmIterator>>,
        mapper: VmValue,
    },
    Filtered {
        source: Rc<RefCell<VmIterator>>,
        predicate: VmValue,
    },
}

pub struct VmTask {
    state: VmTaskState,
}

enum VmTaskState {
    Pending {
        closure: Rc<VmClosure>,
        instance: Option<Rc<RefCell<VmInstance>>>,
        arguments: Vec<VmValue>,
        directory: PathBuf,
    },
    Running,
    Completed(VmValue),
    Failed(VmError),
    Cancelled,
}

impl VmTask {
    fn status(&self) -> &'static str {
        match self.state {
            VmTaskState::Pending { .. } => "待行",
            VmTaskState::Running => "运行",
            VmTaskState::Completed(_) => "完成",
            VmTaskState::Failed(_) => "失败",
            VmTaskState::Cancelled => "取消",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    pub allocated_environments: usize,
    pub collected_environments: usize,
    pub live_environments: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub property_hits: usize,
    pub property_misses: usize,
    pub module_hits: usize,
    pub module_misses: usize,
}

#[derive(Clone)]
struct FrameInfo {
    name: String,
    span: Span,
    owner_class: Option<TypeId>,
    environment: EnvRef,
}

struct Handler {
    target: usize,
    stack_len: usize,
    environment: EnvRef,
}

struct CachedChunk {
    length: u64,
    modified: Option<SystemTime>,
    chunk: Rc<Chunk>,
}

struct VmHostShared {
    event_loop: host_events::BoundedHostEventLoop,
    callback_validity: host_handles::CallbackValidity,
    owner: AtomicPtr<VmHostState>,
    owner_thread: std::thread::ThreadId,
    permissions: std::sync::RwLock<crate::permissions::PermissionSet>,
}

struct VmHostState {
    shared: Box<VmHostShared>,
    host: native_abi_v2::YanxuNativeHostV2,
    callbacks: RefCell<host_handles::CallbackRegistry<VmValue>>,
    resources: RefCell<host_handles::ResourceRegistry>,
    vm: Cell<*mut Vm>,
    pumping: Cell<bool>,
    active_extension: RefCell<Option<String>>,
    current_directory: RefCell<PathBuf>,
    last_pump_error: RefCell<Option<VmError>>,
}

impl VmHostState {
    fn new(permissions: crate::permissions::PermissionSet) -> Box<Self> {
        let callbacks = host_handles::CallbackRegistry::new();
        let callback_validity = callbacks.validity();
        let event_loop = host_events::BoundedHostEventLoop::default();
        let event_loop_id = event_loop.id();
        let shared = Box::new(VmHostShared {
            event_loop,
            callback_validity,
            owner: AtomicPtr::new(std::ptr::null_mut()),
            owner_thread: std::thread::current().id(),
            permissions: std::sync::RwLock::new(permissions),
        });
        let mut state = Box::new(Self {
            shared,
            host: native_abi_v2::YanxuNativeHostV2 {
                abi_version: native_abi_v2::NATIVE_ABI_VERSION_V2,
                struct_size: std::mem::size_of::<native_abi_v2::YanxuNativeHostV2>(),
                context: std::ptr::null_mut(),
                callback_retain: Some(native_host_callback_retain),
                callback_release: Some(native_host_callback_release),
                callback_post: Some(native_host_callback_post),
                wake: Some(native_host_wake),
                pump: Some(native_host_pump),
                has_permission: Some(native_host_has_permission),
                resource_get: Some(native_host_resource_get),
                event_loop_id,
                owner_thread_token: event_loop_id,
            },
            callbacks: RefCell::new(callbacks),
            resources: RefCell::new(host_handles::ResourceRegistry::new(event_loop_id)),
            vm: Cell::new(std::ptr::null_mut()),
            pumping: Cell::new(false),
            active_extension: RefCell::new(None),
            current_directory: RefCell::new(
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            ),
            last_pump_error: RefCell::new(None),
        });
        let state_pointer = (&mut *state) as *mut VmHostState;
        state
            .shared
            .owner
            .store(state_pointer, AtomicOrdering::Release);
        state.host.context = (&*state.shared as *const VmHostShared).cast_mut().cast();
        state
    }

    fn set_permissions(&self, permissions: crate::permissions::PermissionSet) {
        *self
            .shared
            .permissions
            .write()
            .expect("native host permissions poisoned") = permissions;
    }
}

impl Drop for VmHostState {
    fn drop(&mut self) {
        self.vm.set(std::ptr::null_mut());
        self.shared
            .owner
            .store(std::ptr::null_mut(), AtomicOrdering::Release);
        let _ = self.callbacks.get_mut().close();
        let _ = self.resources.get_mut().close_all();
        host_events::HostEventLoop::quit(&self.shared.event_loop);
    }
}

static NATIVE_HOST_ERROR_CODE: &[u8] = b"GUI_HOST_ERROR";
static NATIVE_HOST_ERROR_MESSAGE: &[u8] = b"host callback operation failed";

fn write_native_host_error(error: *mut native_abi_v2::YanxuNativeErrorV2) {
    if let Some(error) = unsafe { error.as_mut() } {
        *error = native_abi_v2::YanxuNativeErrorV2 {
            code: NATIVE_HOST_ERROR_CODE.as_ptr(),
            code_length: NATIVE_HOST_ERROR_CODE.len(),
            message: NATIVE_HOST_ERROR_MESSAGE.as_ptr(),
            message_length: NATIVE_HOST_ERROR_MESSAGE.len(),
        };
    }
}

unsafe fn native_host_shared<'a>(context: *mut std::ffi::c_void) -> Option<&'a VmHostShared> {
    unsafe { context.cast::<VmHostShared>().as_ref() }
}

unsafe fn native_host_state<'a>(context: *mut std::ffi::c_void) -> Option<&'a VmHostState> {
    let shared = unsafe { native_host_shared(context) }?;
    if std::thread::current().id() != shared.owner_thread {
        return None;
    }
    let state = shared.owner.load(AtomicOrdering::Acquire);
    unsafe { state.as_ref() }
}

unsafe extern "C" fn native_host_callback_retain(
    context: *mut std::ffi::c_void,
    callback: u64,
) -> i32 {
    let Some(state) = (unsafe { native_host_state(context) }) else {
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    match state.callbacks.borrow_mut().retain(callback) {
        Ok(()) => native_abi_v2::NATIVE_V2_OK,
        Err(_) => native_abi_v2::NATIVE_V2_ERROR,
    }
}

unsafe extern "C" fn native_host_callback_release(
    context: *mut std::ffi::c_void,
    callback: u64,
) -> i32 {
    let Some(state) = (unsafe { native_host_state(context) }) else {
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    match state.callbacks.borrow_mut().release(callback) {
        Ok(()) => native_abi_v2::NATIVE_V2_OK,
        Err(_) => native_abi_v2::NATIVE_V2_ERROR,
    }
}

unsafe extern "C" fn native_host_callback_post(
    context: *mut std::ffi::c_void,
    callback: u64,
    arguments: *const native_abi_v2::YanxuValueV2,
    argument_count: usize,
    error: *mut native_abi_v2::YanxuNativeErrorV2,
) -> i32 {
    let Some(shared) = (unsafe { native_host_shared(context) }) else {
        write_native_host_error(error);
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    if !shared.callback_validity.is_live(callback) {
        write_native_host_error(error);
        return native_abi_v2::NATIVE_V2_ERROR;
    }
    let arguments = match unsafe { native_abi_v2::copy_posted_arguments(arguments, argument_count) }
    {
        Ok(arguments) => arguments,
        Err(_) => {
            write_native_host_error(error);
            return native_abi_v2::NATIVE_V2_ERROR;
        }
    };
    match shared
        .callback_validity
        .post(&shared.event_loop, callback, arguments)
    {
        Ok(()) => native_abi_v2::NATIVE_V2_OK,
        Err(_) => {
            write_native_host_error(error);
            native_abi_v2::NATIVE_V2_ERROR
        }
    }
}

unsafe extern "C" fn native_host_wake(context: *mut std::ffi::c_void) {
    if let Some(shared) = unsafe { native_host_shared(context) } {
        host_events::HostEventLoop::wake(&shared.event_loop);
    }
}

unsafe extern "C" fn native_host_pump(
    context: *mut std::ffi::c_void,
    maximum_events: usize,
    error: *mut native_abi_v2::YanxuNativeErrorV2,
) -> i32 {
    let Some(state) = (unsafe { native_host_state(context) }) else {
        write_native_host_error(error);
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    // Native callbacks may synchronously request another pump while the owner
    // thread is already draining the queue. The request is already covered by
    // the outer pump, so treat a nested request as a successful no-op.
    if state.pumping.get() {
        return native_abi_v2::NATIVE_V2_OK;
    }
    state.pumping.set(true);
    let vm = state.vm.get();
    if vm.is_null() {
        state.pumping.set(false);
        write_native_host_error(error);
        return native_abi_v2::NATIVE_V2_ERROR;
    }
    let maximum_events = maximum_events.clamp(1, host_events::DEFAULT_HOST_EVENT_CAPACITY);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `vm` is installed only for the duration of an owner-thread native call.
        unsafe { (&mut *vm).pump_host_events(maximum_events) }
    }));
    state.pumping.set(false);
    match result {
        Ok(Ok(_)) => native_abi_v2::NATIVE_V2_OK,
        Ok(Err(runtime_error)) => {
            *state.last_pump_error.borrow_mut() = Some(runtime_error);
            write_native_host_error(error);
            native_abi_v2::NATIVE_V2_ERROR
        }
        Err(_) => {
            *state.last_pump_error.borrow_mut() = Some(VmError {
                code: "NATIVE_PANIC",
                message: "宿主事件泵 panic 已在 FFI 边界隔离".into(),
                span: Span::synthetic(),
                frames: Vec::new(),
            });
            write_native_host_error(error);
            native_abi_v2::NATIVE_V2_ERROR
        }
    }
}

unsafe extern "C" fn native_host_has_permission(
    context: *mut std::ffi::c_void,
    capability: *const u8,
    capability_length: usize,
) -> i32 {
    let Some(shared) = (unsafe { native_host_shared(context) }) else {
        return 0;
    };
    if capability.is_null() || capability_length == 0 || capability_length > 1_024 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(capability, capability_length) };
    let Ok(capability) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let permissions = shared
        .permissions
        .read()
        .expect("native host permissions poisoned");
    let granted = match capability {
        "图形界面" | "gui" => permissions.graphical_interface_allowed(),
        "剪贴板" | "clipboard" => permissions.clipboard_allowed(),
        "文件对话框" | "file_dialog" => permissions.file_dialog_allowed(),
        "系统通知" | "system_notifications" => permissions.system_notifications_allowed(),
        "托盘" | "tray" => permissions.tray_allowed(),
        "打开外部地址" | "open_external_url" => permissions.open_external_url_allowed(),
        "全局快捷键" | "global_shortcuts" => permissions.global_shortcuts_allowed(),
        "原生扩展" | "native_extensions" => permissions.native_extensions_allowed(),
        _ => false,
    };
    i32::from(granted)
}

unsafe extern "C" fn native_host_resource_get(
    context: *mut std::ffi::c_void,
    resource: u64,
    raw_resource: *mut *mut std::ffi::c_void,
) -> i32 {
    let Some(state) = (unsafe { native_host_state(context) }) else {
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    let Some(raw_resource) = (unsafe { raw_resource.as_mut() }) else {
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    let Some(extension) = state.active_extension.borrow().clone() else {
        return native_abi_v2::NATIVE_V2_ERROR;
    };
    match state.resources.borrow().raw_pointer(resource, &extension) {
        Ok(pointer) => {
            *raw_resource = pointer;
            native_abi_v2::NATIVE_V2_OK
        }
        Err(_) => native_abi_v2::NATIVE_V2_ERROR,
    }
}

pub struct Vm {
    stack: Vec<VmValue>,
    globals: EnvRef,
    output: Vec<String>,
    echo: bool,
    frames: Vec<FrameInfo>,
    heap_environments: Vec<Weak<RefCell<Environment>>>,
    gc_stats: GcStats,
    property_cache: HashSet<(usize, String, bool)>,
    cache_stats: CacheStats,
    module_cache: HashMap<PathBuf, Rc<VmModule>>,
    bytecode_cache: HashMap<PathBuf, CachedChunk>,
    loading_modules: Vec<PathBuf>,
    application_modules: HashMap<String, Rc<crate::application::ApplicationModule>>,
    application_module_cache: HashMap<String, Rc<VmModule>>,
    loading_application_modules: Vec<String>,
    application_resources: Option<Rc<std::collections::BTreeMap<String, Vec<u8>>>>,
    application_native_modules:
        Option<Rc<std::collections::BTreeMap<String, crate::application::DecodedNativeModule>>>,
    package_root: Option<PathBuf>,
    package_module_roots: crate::package::TrustedPackageRoots,
    permissions: crate::permissions::PermissionSet,
    socket_quota: crate::stdlib::SocketQuota,
    arguments: Vec<String>,
    resources: crate::budget::ResourceMeter,
    native_extensions_v2: HashMap<String, Rc<native_abi_v2::NativeExtensionV2>>,
    host_state: Box<VmHostState>,
}

enum Step {
    Continue,
    Return(VmValue),
}

impl Vm {
    pub fn new() -> Self {
        Self::with_echo(true)
    }

    pub fn silent() -> Self {
        Self::with_echo(false)
    }

    pub fn with_permissions(permissions: crate::permissions::PermissionSet) -> Self {
        let mut vm = Self::with_echo(true);
        vm.set_permissions(permissions);
        vm
    }

    pub fn silent_with_permissions(permissions: crate::permissions::PermissionSet) -> Self {
        let mut vm = Self::with_echo(false);
        vm.set_permissions(permissions);
        vm
    }

    pub fn set_permissions(&mut self, permissions: crate::permissions::PermissionSet) {
        self.host_state.set_permissions(permissions.clone());
        self.permissions = permissions;
    }

    fn with_echo(echo: bool) -> Self {
        let globals = Rc::new(RefCell::new(Environment::default()));
        let permissions = crate::permissions::PermissionSet::unrestricted();
        let host_state = VmHostState::new(permissions.clone());
        let vm = Self {
            stack: Vec::new(),
            globals: globals.clone(),
            output: Vec::new(),
            echo,
            frames: Vec::new(),
            heap_environments: vec![Rc::downgrade(&globals)],
            gc_stats: GcStats {
                allocated_environments: 1,
                collected_environments: 0,
                live_environments: 1,
            },
            property_cache: HashSet::new(),
            cache_stats: CacheStats::default(),
            module_cache: HashMap::new(),
            bytecode_cache: HashMap::new(),
            loading_modules: Vec::new(),
            application_modules: HashMap::new(),
            application_module_cache: HashMap::new(),
            loading_application_modules: Vec::new(),
            application_resources: None,
            application_native_modules: None,
            package_root: None,
            package_module_roots: crate::package::TrustedPackageRoots::default(),
            permissions,
            socket_quota: crate::stdlib::SocketQuota::default(),
            arguments: Vec::new(),
            resources: crate::budget::ResourceMeter::new(crate::budget::ExecutionBudget::default()),
            native_extensions_v2: HashMap::new(),
            host_state,
        };
        for (name, arity, kind) in [
            ("时刻", 0, NativeKind::Clock),
            ("长度", 1, NativeKind::Length),
            ("类型", 1, NativeKind::Type),
            ("追加", 2, NativeKind::Append),
            ("弹出", 1, NativeKind::Pop),
            ("有键", 2, NativeKind::HasKey),
            ("插入", 3, NativeKind::Insert),
            ("删除", 2, NativeKind::Remove),
            ("键列", 1, NativeKind::Keys),
            ("值列", 1, NativeKind::Values),
            ("遍", 1, NativeKind::Iterator),
            ("续", 1, NativeKind::Next),
            ("范围", 2, NativeKind::Range),
            ("步进范围", 3, NativeKind::SteppedRange),
            ("映射", 2, NativeKind::Map),
            ("筛选", 2, NativeKind::Filter),
            ("折叠", 3, NativeKind::Fold),
            ("排序", 1, NativeKind::Sort),
            ("反转", 1, NativeKind::Reverse),
            ("包含", 2, NativeKind::Contains),
            ("寻找", 2, NativeKind::Find),
            ("取消", 1, NativeKind::CancelTask),
            ("任务状态", 1, NativeKind::TaskStatus),
            ("并候", 1, NativeKind::JoinTasks),
        ] {
            vm.define_native(&globals, name, arity, kind);
        }
        vm
    }

    pub fn output(&self) -> &[String] {
        &self.output
    }

    pub fn set_budget(&mut self, budget: crate::budget::ExecutionBudget) {
        self.resources.set_budget(budget);
    }

    pub(crate) fn set_host_resource_limits(&mut self, limits: crate::budget::HostResourceLimits) {
        self.resources.set_host_limits(limits);
    }

    pub fn set_arguments(&mut self, arguments: Vec<String>) {
        self.arguments = arguments;
    }

    pub fn budget(&self) -> crate::budget::ExecutionBudget {
        self.resources.budget()
    }

    pub fn take_output(&mut self) -> Vec<String> {
        std::mem::take(&mut self.output)
    }

    pub fn call_stack(&self) -> Vec<String> {
        self.frames
            .iter()
            .map(|frame| format!("{}（{}）", frame.name, frame.span))
            .collect()
    }

    pub fn gc_stats(&self) -> GcStats {
        self.gc_stats
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache_stats
    }

    pub fn execute(&mut self, chunk: &Chunk) -> Result<VmValue, VmError> {
        let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        self.execute_in_directory(chunk, &directory)
    }

    pub fn execute_in_directory(
        &mut self,
        chunk: &Chunk,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        if chunk.format_version == crate::bytecode::BYTECODE_FORMAT_VERSION {
            crate::bytecode::validate_format(chunk)
                .map_err(|archive_error| error(&Span::synthetic(), archive_error.to_string()))?;
        }
        self.resources.reset();
        let absolute_directory = if directory.is_absolute() {
            directory.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(directory)
        };
        let directory = fs::canonicalize(&absolute_directory).unwrap_or(absolute_directory);
        let package_root = crate::package::discover(&directory)
            .map_err(|runtime_error| package_error(&Span::synthetic(), runtime_error))?
            .map(|manifest| {
                fs::canonicalize(&manifest.root).map_err(|runtime_error| {
                    error(
                        &Span::synthetic(),
                        format!(
                            "不能定位包根目录“{}”：{runtime_error}",
                            manifest.root.display()
                        ),
                    )
                })
            })
            .transpose()?;
        let mut package_module_roots = crate::package::TrustedPackageRoots::default();
        if let Some(root) = &package_root {
            package_module_roots
                .insert(root)
                .map_err(|runtime_error| package_path_error(&Span::synthetic(), runtime_error))?;
        }
        let previous_package_root = std::mem::replace(&mut self.package_root, package_root);
        let previous_package_module_roots =
            std::mem::replace(&mut self.package_module_roots, package_module_roots);
        let result = self.run_chunk(
            Rc::new(chunk.clone()),
            self.globals.clone(),
            "<顶层>".into(),
            Span::synthetic(),
            directory,
            None,
        );
        self.package_root = previous_package_root;
        self.package_module_roots = previous_package_module_roots;
        result
    }

    pub fn execute_application(
        &mut self,
        archive: &crate::application::ApplicationArchive,
    ) -> Result<VmValue, VmError> {
        crate::application::validate_archive(archive)
            .map_err(|runtime_error| error(&Span::synthetic(), runtime_error.to_string()))?;
        let entry = archive
            .modules
            .get(&archive.entry_module)
            .ok_or_else(|| error(&Span::synthetic(), "YXB 应用缺少入口模块"))?;
        let resources = crate::application::decode_resources(archive)
            .map_err(|runtime_error| error(&Span::synthetic(), runtime_error.to_string()))?;
        let native_modules = crate::application::decode_native_modules(archive)
            .map_err(|runtime_error| error(&Span::synthetic(), runtime_error.to_string()))?;
        let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let application_permissions = archive.permissions.to_permissions(&directory);
        let effective_permissions = self.permissions.intersect(&application_permissions);
        let previous_permissions = std::mem::replace(&mut self.permissions, effective_permissions);
        self.host_state.set_permissions(self.permissions.clone());
        let previous_modules = std::mem::replace(
            &mut self.application_modules,
            archive
                .modules
                .iter()
                .map(|(id, module)| (id.clone(), Rc::new(module.clone())))
                .collect(),
        );
        let previous_cache = std::mem::take(&mut self.application_module_cache);
        let previous_loading = std::mem::take(&mut self.loading_application_modules);
        let previous_resources = self.application_resources.replace(resources);
        let previous_native_modules = self.application_native_modules.replace(native_modules);
        let previous_native_extensions = std::mem::take(&mut self.native_extensions_v2);
        self.resources.reset();
        let result = self.run_chunk(
            Rc::new(entry.chunk.clone()),
            self.globals.clone(),
            format!("应用“{}”", archive.package.name),
            Span::synthetic(),
            directory,
            None,
        );
        self.permissions = previous_permissions;
        self.host_state.set_permissions(self.permissions.clone());
        self.application_modules = previous_modules;
        self.application_module_cache = previous_cache;
        self.loading_application_modules = previous_loading;
        self.application_resources = previous_resources;
        self.application_native_modules = previous_native_modules;
        self.native_extensions_v2 = previous_native_extensions;
        result
    }

    fn run_chunk(
        &mut self,
        chunk: Rc<Chunk>,
        environment: EnvRef,
        name: String,
        frame_span: Span,
        directory: PathBuf,
        owner_class: Option<TypeId>,
    ) -> Result<VmValue, VmError> {
        if chunk.format_version != crate::bytecode::BYTECODE_FORMAT_VERSION {
            return Err(error(
                &frame_span,
                format!(
                    "不支持字节码格式版本 {}，本运行时仅支持版本 {}",
                    chunk.format_version,
                    crate::bytecode::BYTECODE_FORMAT_VERSION
                ),
            ));
        }
        let stack_base = self.stack.len();
        self.frames.push(FrameInfo {
            name: name.clone(),
            span: frame_span.clone(),
            owner_class,
            environment: environment.clone(),
        });
        let mut current_env = environment;
        let mut ip = 0;
        let mut last = VmValue::Nil;
        let mut handlers = Vec::new();
        let mut pending_error = None;

        while let Some(instruction) = chunk.code.get(ip).cloned() {
            let span = chunk.spans[ip].clone();
            self.resources
                .charge_step()
                .map_err(|message| error(&span, message))?;
            let offset = ip;
            ip += 1;
            let result = self.step(
                &chunk,
                instruction,
                &span,
                offset,
                &mut ip,
                &mut current_env,
                &mut last,
                &mut handlers,
                &mut pending_error,
                &directory,
            );
            match result {
                Ok(Step::Continue) => {}
                Ok(Step::Return(value)) => {
                    self.stack.truncate(stack_base);
                    self.frames.pop();
                    return Ok(value);
                }
                Err(mut runtime_error) => {
                    if let Some(handler) = handlers.pop() {
                        self.stack.truncate(handler.stack_len);
                        current_env = handler.environment;
                        ip = handler.target;
                        pending_error = Some(VmValue::Error(Rc::new(VmErrorValue {
                            code: runtime_error.code,
                            category: runtime_error.category().into(),
                            message: runtime_error.message,
                            frames: runtime_error.frames,
                            span: runtime_error.span,
                        })));
                    } else {
                        runtime_error.frames.push(format!("{name}（{frame_span}）"));
                        self.stack.truncate(stack_base);
                        self.frames.pop();
                        return Err(runtime_error);
                    }
                }
            }
        }
        self.stack.truncate(stack_base);
        self.frames.pop();
        Ok(last)
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        chunk: &Chunk,
        instruction: Instruction,
        span: &Span,
        offset: usize,
        ip: &mut usize,
        environment: &mut EnvRef,
        last: &mut VmValue,
        handlers: &mut Vec<Handler>,
        pending_error: &mut Option<VmValue>,
        directory: &Path,
    ) -> Result<Step, VmError> {
        match instruction {
            Instruction::Constant(index) => self.stack.push(constant(chunk, index, span)?),
            Instruction::Load(name) => {
                let value = environment
                    .borrow()
                    .get(&name)
                    .ok_or_else(|| error(span, format!("未曾定义“{name}”")))?;
                self.stack.push(value);
            }
            Instruction::Define {
                name,
                mutable,
                type_ref,
            } => {
                let value = self.pop(span)?;
                self.ensure_type(
                    &format!("变量“{name}”"),
                    type_ref.as_ref(),
                    &value,
                    environment.clone(),
                    span,
                )?;
                environment.borrow_mut().values.insert(
                    name,
                    Binding {
                        value: value.clone(),
                        mutable,
                        type_ref,
                        type_environment: Some(Rc::downgrade(environment)),
                    },
                );
                *last = value;
            }
            Instruction::Store(name) => {
                let value = self.pop(span)?;
                self.assign_variable(environment.clone(), &name, value.clone(), span)?;
                *last = value;
            }
            Instruction::EnterScope => *environment = self.child_env(environment.clone()),
            Instruction::ExitScope => {
                let parent = environment
                    .borrow()
                    .parent
                    .clone()
                    .ok_or_else(|| error(span, "不可退出根作用域"))?;
                *environment = parent;
            }
            Instruction::Pop => *last = self.pop(span)?,
            Instruction::Print => {
                let value = self.pop(span)?;
                let line = value.to_string();
                if self.echo {
                    println!("{line}");
                }
                self.output.push(line);
                *last = value;
            }
            Instruction::Negate => {
                let value = self.pop(span)?;
                let VmValue::Number(number) = value else {
                    return Err(error(span, format!("不可求负于{}", value.type_name())));
                };
                self.stack.push(VmValue::Number(-number));
            }
            Instruction::Not => {
                let value = self.pop(span)?;
                self.stack.push(VmValue::Bool(!value.truthy()));
            }
            Instruction::Add => self.binary(span, add)?,
            Instruction::Subtract => self.numeric(span, "相减", |a, b| a - b)?,
            Instruction::Multiply => self.numeric(span, "相乘", |a, b| a * b)?,
            Instruction::Divide => self.numeric(span, "相除", |a, b| a / b)?,
            Instruction::Equal => self.compare_values(span, false)?,
            Instruction::NotEqual => self.compare_values(span, true)?,
            Instruction::Greater => self.compare_numbers(span, |a, b| a > b)?,
            Instruction::GreaterEqual => self.compare_numbers(span, |a, b| a >= b)?,
            Instruction::Less => self.compare_numbers(span, |a, b| a < b)?,
            Instruction::LessEqual => self.compare_numbers(span, |a, b| a <= b)?,
            Instruction::BuildList(count) => {
                self.resources
                    .check_collection(count)
                    .map_err(|message| error(span, message))?;
                let values = self.take(count, span)?;
                self.stack
                    .push(VmValue::List(Rc::new(RefCell::new(values))));
            }
            Instruction::BuildTuple(count) => {
                self.resources
                    .check_collection(count)
                    .map_err(|message| error(span, message))?;
                let values = self.take(count, span)?;
                self.stack.push(VmValue::Tuple(Rc::new(values)));
            }
            Instruction::BuildMap(count) => {
                self.resources
                    .check_collection(count)
                    .map_err(|message| error(span, message))?;
                let values = self.take(count * 2, span)?;
                let mut map = VmMap {
                    entries: Vec::new(),
                };
                for pair in values.chunks_exact(2) {
                    map_insert(&mut map, pair[0].clone(), pair[1].clone(), span)?;
                }
                self.stack.push(VmValue::Map(Rc::new(RefCell::new(map))));
            }
            Instruction::Index => {
                let index = self.pop(span)?;
                let object = self.pop(span)?;
                self.stack.push(index_value(object, index, span)?);
            }
            Instruction::Slice => {
                let end = self.pop(span)?;
                let start = self.pop(span)?;
                let object = self.pop(span)?;
                let value = slice_value(object, start, end, span)?;
                self.ensure_value_budget(&value, span)?;
                self.stack.push(value);
            }
            Instruction::SetIndex => {
                let value = self.pop(span)?;
                let index = self.pop(span)?;
                let object = self.pop(span)?;
                self.set_index(object, index, value.clone(), span)?;
                *last = value;
            }
            Instruction::GetProperty(name) => {
                let object = self.pop(span)?;
                let value = self.get_property(object, &name, span, offset)?;
                self.stack.push(value);
            }
            Instruction::GetSuper(name) => {
                let value = self.get_super(environment, &name, span)?;
                self.stack.push(value);
            }
            Instruction::SetProperty(name) => {
                let value = self.pop(span)?;
                let object = self.pop(span)?;
                self.set_property(object, &name, value.clone(), span, offset)?;
                *last = value;
            }
            Instruction::IsType(type_name) => {
                let value = self.pop(span)?;
                let matches =
                    self.value_matches_type(&value, &type_name, environment.clone(), span)?;
                self.stack.push(VmValue::Bool(matches));
            }
            Instruction::JumpIfFalse(target) => {
                if !self.peek(span)?.truthy() {
                    *ip = target;
                }
            }
            Instruction::JumpIfTrue(target) => {
                if self.peek(span)?.truthy() {
                    *ip = target;
                }
            }
            Instruction::Jump(target) => *ip = target,
            Instruction::MakeClosure(index) => {
                let prototype = chunk
                    .functions
                    .get(index)
                    .cloned()
                    .ok_or_else(|| error(span, "法原型下标越界"))?;
                self.stack.push(VmValue::Closure(Rc::new(VmClosure {
                    prototype: Rc::new(prototype),
                    closure: environment.clone(),
                    directory: directory.to_path_buf(),
                })));
            }
            Instruction::Call(count) => {
                let arguments = self.take(count, span)?;
                let callee = self.pop(span)?;
                let value = self.call_value(callee, arguments, span, directory)?;
                self.stack.push(value);
            }
            Instruction::Await => {
                let value = self.pop(span)?;
                let VmValue::Task(task) = value else {
                    return Err(error(
                        span,
                        format!("“候”须收任务，不可收{}", value.type_name()),
                    ));
                };
                let value = self.await_task(&task, span)?;
                self.stack.push(value);
            }
            Instruction::Return => return Ok(Step::Return(self.pop(span)?)),
            Instruction::GetIterator => {
                let value = self.pop(span)?;
                let iterator = self.make_iterator(value, span, directory)?;
                self.stack.push(VmValue::Iterator(iterator));
            }
            Instruction::IteratorNext(target) => {
                let iterator = match self.peek(span)? {
                    VmValue::Iterator(iterator) => iterator.clone(),
                    value => {
                        return Err(error(span, format!("{}不可作为遍器", value.type_name())));
                    }
                };
                if let Some(value) = self.next_iterator(&iterator, span, directory)? {
                    self.stack.push(value);
                } else {
                    self.pop(span)?;
                    *ip = target;
                }
            }
            Instruction::DefineClass(index) => {
                self.define_class(chunk, index, environment, span, directory)?;
            }
            Instruction::DefineProtocol(index) => {
                let protocol = chunk
                    .protocols
                    .get(index)
                    .ok_or_else(|| error(span, "协原型下标越界"))?;
                environment.borrow_mut().values.insert(
                    protocol.type_id.name.clone(),
                    Binding {
                        value: VmValue::Protocol(Rc::new(VmProtocol {
                            type_id: protocol.type_id.clone(),
                        })),
                        mutable: false,
                        type_ref: Some(RuntimeType::named("协")),
                        type_environment: Some(Rc::downgrade(environment)),
                    },
                );
            }
            Instruction::Import { path, alias } => {
                let module = self.load_module(&path, directory, span)?;
                environment.borrow_mut().values.insert(
                    alias,
                    Binding {
                        value: VmValue::Module(module),
                        mutable: false,
                        type_ref: Some(RuntimeType::named("模块")),
                        type_environment: Some(Rc::downgrade(environment)),
                    },
                );
            }
            Instruction::TryBegin(target) => handlers.push(Handler {
                target,
                stack_len: self.stack.len(),
                environment: environment.clone(),
            }),
            Instruction::TryEnd => {
                handlers.pop();
            }
            Instruction::BindError(name) => {
                let value = pending_error
                    .take()
                    .ok_or_else(|| error(span, "没有待绑定之误"))?;
                environment.borrow_mut().values.insert(
                    name,
                    Binding {
                        value,
                        mutable: false,
                        type_ref: Some(RuntimeType::named("误")),
                        type_environment: Some(Rc::downgrade(environment)),
                    },
                );
            }
            Instruction::Throw => return Err(thrown(self.pop(span)?, span)),
            Instruction::Halt => return Ok(Step::Return(last.clone())),
        }
        Ok(Step::Continue)
    }

    fn assign_variable(
        &self,
        environment: EnvRef,
        name: &str,
        value: VmValue,
        span: &Span,
    ) -> Result<(), VmError> {
        let mut current = environment;
        loop {
            if current.borrow().values.contains_key(name) {
                let (mutable, type_ref, type_environment) = {
                    let environment = current.borrow();
                    let binding = environment
                        .values
                        .get(name)
                        .expect("binding existence checked above");
                    (
                        binding.mutable,
                        binding.type_ref.clone(),
                        binding.type_environment.as_ref().and_then(Weak::upgrade),
                    )
                };
                if !mutable {
                    return Err(error(span, format!("“{name}”乃定值，不可改写")));
                }
                self.ensure_type(
                    &format!("变量“{name}”"),
                    type_ref.as_ref(),
                    &value,
                    type_environment.unwrap_or_else(|| current.clone()),
                    span,
                )?;
                current
                    .borrow_mut()
                    .values
                    .get_mut(name)
                    .expect("binding existence checked above")
                    .value = value;
                return Ok(());
            }
            let parent = current.borrow().parent.clone();
            let Some(parent) = parent else {
                return Err(error(span, format!("不可改写未定义之名“{name}”")));
            };
            current = parent;
        }
    }

    fn resolve_type_link(
        &self,
        environment: EnvRef,
        link: &TypeLink,
        span: &Span,
    ) -> Result<VmValue, VmError> {
        let Some(first) = link.source.segments.first() else {
            return Err(error(span, "字节码类型路径不可为空"));
        };
        let mut value = environment
            .borrow()
            .get(first)
            .ok_or_else(|| error(span, format!("类型路径“{link}”的首段“{first}”未定义")))?;
        for segment in link.source.segments.iter().skip(1) {
            let VmValue::Module(module) = value else {
                return Err(error(span, format!("类型路径“{link}”的中间成员不是模块")));
            };
            if !module.module_id.is_valid() {
                return Err(error(
                    span,
                    format!("模块“{}”携带无效规范身份", module.name),
                ));
            }
            if !module.exports.contains(segment) {
                return Err(error(
                    span,
                    format!("模块“{}”未导出“{segment}”（类型路径“{link}”）", module.name),
                ));
            }
            value = module
                .environment
                .borrow()
                .values
                .get(segment)
                .map(|binding| binding.value.clone())
                .ok_or_else(|| {
                    error(
                        span,
                        format!("模块“{}”未导出“{segment}”（类型路径“{link}”）", module.name),
                    )
                })?;
        }
        if let Some(target) = &link.target {
            let linked = match &value {
                VmValue::Class(class) => &class.type_id,
                VmValue::Protocol(protocol) => &protocol.type_id,
                other => {
                    return Err(error(
                        span,
                        format!(
                            "字节码类型引用“{link}”链接到{}而非类或协",
                            other.type_name()
                        ),
                    ));
                }
            };
            if linked != target {
                return Err(error(
                    span,
                    format!("字节码类型引用“{link}”的规范身份不一致：期望 {target}，实得 {linked}"),
                ));
            }
        }
        Ok(value)
    }

    fn ensure_type(
        &self,
        subject: &str,
        expected: Option<&RuntimeType>,
        value: &VmValue,
        environment: EnvRef,
        span: &Span,
    ) -> Result<(), VmError> {
        let Some(expected) = expected else {
            return Ok(());
        };
        if self.value_matches_type(value, expected, environment, span)? {
            return Ok(());
        }
        Err(error(
            span,
            format!("{subject}注为{expected}，不可纳入{}", value.type_name()),
        ))
    }

    fn value_matches_type(
        &self,
        value: &VmValue,
        expected: &RuntimeType,
        environment: EnvRef,
        span: &Span,
    ) -> Result<bool, VmError> {
        match expected {
            RuntimeType::Union { variants } => {
                for variant in variants {
                    if self.value_matches_type(value, variant, environment.clone(), span)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            RuntimeType::Nullable { inner } => Ok(matches!(value, VmValue::Nil)
                || self.value_matches_type(value, inner, environment, span)?),
            RuntimeType::Function { .. } => Ok(matches!(
                value,
                VmValue::Closure(_)
                    | VmValue::BoundMethod(_, _)
                    | VmValue::Native(_)
                    | VmValue::Class(_)
            )),
            RuntimeType::Generic { base, arguments } => {
                let Some(base_name) = base.source.single_name() else {
                    return self.matches_object_link(value, base, environment, span);
                };
                match (base_name, value) {
                    ("列", VmValue::List(items)) if arguments.len() == 1 => {
                        for item in items.borrow().iter() {
                            if !self.value_matches_type(
                                item,
                                &arguments[0],
                                environment.clone(),
                                span,
                            )? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("典", VmValue::Map(map)) if arguments.len() == 2 => {
                        for (key, item) in &map.borrow().entries {
                            if !self.value_matches_type(
                                key,
                                &arguments[0],
                                environment.clone(),
                                span,
                            )? || !self.value_matches_type(
                                item,
                                &arguments[1],
                                environment.clone(),
                                span,
                            )? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("元", VmValue::Tuple(items)) if arguments.len() == items.len() => {
                        for (item, item_type) in items.iter().zip(arguments) {
                            if !self.value_matches_type(
                                item,
                                item_type,
                                environment.clone(),
                                span,
                            )? {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    }
                    ("遍器", VmValue::Iterator(_)) if arguments.len() == 1 => Ok(true),
                    ("任务", VmValue::Task(_)) if arguments.len() == 1 => Ok(true),
                    ("套接字", VmValue::Socket(_)) if arguments.is_empty() => Ok(true),
                    _ if base.target.is_some() => {
                        self.matches_object_link(value, base, environment, span)
                    }
                    _ => Ok(false),
                }
            }
            RuntimeType::Named { link } => {
                if let Some(expected) = link.source.single_name()
                    && link.target.is_none()
                {
                    let builtin = match expected {
                        "任意" => Some(true),
                        "数" => Some(matches!(value, VmValue::Number(_))),
                        "文" => Some(matches!(value, VmValue::String(_))),
                        "字节串" => Some(matches!(value, VmValue::Bytes(_))),
                        "理" => Some(matches!(value, VmValue::Bool(_))),
                        "空" => Some(matches!(value, VmValue::Nil)),
                        "法" => Some(matches!(
                            value,
                            VmValue::Closure(_)
                                | VmValue::BoundMethod(_, _)
                                | VmValue::Native(_)
                                | VmValue::Class(_)
                        )),
                        "类" => Some(matches!(value, VmValue::Class(_))),
                        "协" => Some(matches!(value, VmValue::Protocol(_))),
                        "模块" => Some(matches!(value, VmValue::Module(_))),
                        "对象" => Some(matches!(value, VmValue::Instance(_))),
                        "列" => Some(matches!(value, VmValue::List(_))),
                        "元" => Some(matches!(value, VmValue::Tuple(_))),
                        "典" => Some(matches!(value, VmValue::Map(_))),
                        "遍器" => Some(matches!(value, VmValue::Iterator(_))),
                        "误" => Some(matches!(value, VmValue::Error(_))),
                        "任务" => Some(matches!(value, VmValue::Task(_))),
                        "套接字" => Some(matches!(value, VmValue::Socket(_))),
                        "原生模块" => Some(matches!(value, VmValue::NativeModuleV2(_))),
                        "原生资源" => Some(matches!(value, VmValue::NativeResource(_))),
                        _ => None,
                    };
                    if let Some(matches) = builtin {
                        return Ok(matches);
                    }
                }
                self.matches_object_link(value, link, environment, span)
            }
        }
    }

    fn matches_object_link(
        &self,
        value: &VmValue,
        link: &TypeLink,
        environment: EnvRef,
        span: &Span,
    ) -> Result<bool, VmError> {
        match self.resolve_type_link(environment, link, span)? {
            VmValue::Class(class) => Ok(matches!(value, VmValue::Instance(instance)
                if instance.borrow().class.is_a(&class.type_id))),
            VmValue::Protocol(protocol) => Ok(matches!(value, VmValue::Instance(instance)
                if instance.borrow().class.is_a(&protocol.type_id))),
            other => Err(error(
                span,
                format!("类型路径“{link}”指向{}而非类或协", other.type_name()),
            )),
        }
    }

    fn define_class(
        &mut self,
        chunk: &Chunk,
        index: usize,
        environment: &EnvRef,
        span: &Span,
        directory: &Path,
    ) -> Result<(), VmError> {
        let prototype: ClassPrototype = chunk
            .classes
            .get(index)
            .cloned()
            .ok_or_else(|| error(span, "类原型下标越界"))?;
        let initial_count = prototype
            .fields
            .iter()
            .filter(|field| field.initial_slot.is_some())
            .count();
        let initials = self.take(initial_count, span)?;
        let superclass = prototype
            .superclass
            .as_ref()
            .map(
                |link| match self.resolve_type_link(environment.clone(), link, span)? {
                    VmValue::Class(class) => Ok(class),
                    value => Err(error(
                        span,
                        format!("“{link}”为{}，不可作父类", value.type_name()),
                    )),
                },
            )
            .transpose()?;
        let mut protocols = HashSet::new();
        for link in &prototype.protocols {
            match self.resolve_type_link(environment.clone(), link, span)? {
                VmValue::Protocol(protocol) => {
                    protocols.insert(protocol.type_id.clone());
                }
                value => {
                    return Err(error(
                        span,
                        format!("“{link}”为{}，不可作协议", value.type_name()),
                    ));
                }
            }
        }

        let methods = prototype
            .methods
            .into_iter()
            .map(|method| {
                let closure = Rc::new(VmClosure {
                    prototype: Rc::new(method.clone()),
                    closure: environment.clone(),
                    directory: directory.to_path_buf(),
                });
                (
                    method.name.clone(),
                    RuntimeMethod {
                        closure,
                        owner: prototype.type_id.clone(),
                    },
                )
            })
            .collect();
        let mut static_values = HashMap::new();
        let fields = prototype
            .fields
            .into_iter()
            .map(|field| {
                let initial = field.initial_slot.map(|slot| initials[slot].clone());
                if let Some(value) = &initial {
                    self.ensure_type(
                        &format!("域“{}”", field.name),
                        Some(&field.type_ref),
                        value,
                        environment.clone(),
                        span,
                    )?;
                }
                if field.is_static
                    && let Some(value) = &initial
                {
                    static_values.insert(field.name.clone(), value.clone());
                }
                Ok((
                    field.name.clone(),
                    RuntimeField {
                        prototype: field,
                        initial,
                        owner: prototype.type_id.clone(),
                        type_environment: environment.clone(),
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>, VmError>>()?;
        let class = Rc::new(VmClass {
            type_id: prototype.type_id.clone(),
            superclass,
            protocols,
            fields,
            methods,
            static_values: RefCell::new(static_values),
        });
        environment.borrow_mut().values.insert(
            prototype.type_id.name,
            Binding {
                value: VmValue::Class(class),
                mutable: false,
                type_ref: Some(RuntimeType::named("类")),
                type_environment: Some(Rc::downgrade(environment)),
            },
        );
        Ok(())
    }

    fn call_value(
        &mut self,
        callee: VmValue,
        arguments: Vec<VmValue>,
        span: &Span,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        let value = self.call_value_inner(callee, arguments, span, directory)?;
        self.ensure_value_budget(&value, span)?;
        Ok(value)
    }

    fn call_value_inner(
        &mut self,
        callee: VmValue,
        arguments: Vec<VmValue>,
        span: &Span,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        match callee {
            VmValue::Closure(closure) if closure.prototype.is_async => {
                self.make_task(closure, None, arguments, span, directory)
            }
            VmValue::Closure(closure) => {
                self.call_closure(closure, None, arguments, span, directory)
            }
            VmValue::BoundMethod(closure, instance) if closure.prototype.is_async => {
                self.make_task(closure, Some(instance), arguments, span, directory)
            }
            VmValue::BoundMethod(closure, instance) => {
                self.call_closure(closure, Some(instance), arguments, span, directory)
            }
            VmValue::Native(native) => {
                if arguments.len() != native.arity {
                    return Err(error(
                        span,
                        format!(
                            "“{}”应收 {} 个参数，实得 {} 个",
                            native.name,
                            native.arity,
                            arguments.len()
                        ),
                    ));
                }
                self.call_native(native.kind, &arguments, span, directory)
            }
            VmValue::Class(class) => {
                let instance = Rc::new(RefCell::new(VmInstance {
                    fields: class.initial_fields(),
                    class: class.clone(),
                }));
                if let Some(initializer) = class.method("初始化") {
                    if initializer.closure.prototype.is_static {
                        return Err(error(span, "初始化不可为静法"));
                    }
                    if initializer.closure.prototype.is_async {
                        return Err(error(span, "初始化不可为异法"));
                    }
                    self.call_closure(
                        initializer.closure.clone(),
                        Some(instance.clone()),
                        arguments,
                        span,
                        directory,
                    )?;
                } else if !arguments.is_empty() {
                    return Err(error(
                        span,
                        format!("“{}”应收 0 个参数", class.type_id.name),
                    ));
                }
                Ok(VmValue::Instance(instance))
            }
            value => Err(error(span, format!("{}不可调用", value.type_name()))),
        }
    }

    fn make_task(
        &self,
        closure: Rc<VmClosure>,
        instance: Option<Rc<RefCell<VmInstance>>>,
        arguments: Vec<VmValue>,
        span: &Span,
        _directory: &Path,
    ) -> Result<VmValue, VmError> {
        if arguments.len() != closure.prototype.parameters.len() {
            return Err(error(
                span,
                format!(
                    "“{}”应收 {} 个参数，实得 {} 个",
                    closure.prototype.name,
                    closure.prototype.parameters.len(),
                    arguments.len()
                ),
            ));
        }
        let directory = closure.directory.clone();
        Ok(VmValue::Task(Rc::new(RefCell::new(VmTask {
            state: VmTaskState::Pending {
                closure,
                instance,
                arguments,
                directory,
            },
        }))))
    }

    fn call_closure(
        &mut self,
        closure: Rc<VmClosure>,
        instance: Option<Rc<RefCell<VmInstance>>>,
        arguments: Vec<VmValue>,
        span: &Span,
        _directory: &Path,
    ) -> Result<VmValue, VmError> {
        self.resources
            .enter_call()
            .map_err(|message| error(span, message))?;
        let result = self.call_closure_inner(closure, instance, arguments, span, _directory);
        self.resources.leave_call();
        result
    }

    fn call_closure_inner(
        &mut self,
        closure: Rc<VmClosure>,
        instance: Option<Rc<RefCell<VmInstance>>>,
        arguments: Vec<VmValue>,
        span: &Span,
        _directory: &Path,
    ) -> Result<VmValue, VmError> {
        if arguments.len() != closure.prototype.parameters.len() {
            return Err(error(
                span,
                format!(
                    "“{}”应收 {} 个参数，实得 {} 个",
                    closure.prototype.name,
                    closure.prototype.parameters.len(),
                    arguments.len()
                ),
            ));
        }
        let environment = self.child_env(closure.closure.clone());
        if let Some(instance) = instance {
            environment.borrow_mut().values.insert(
                "此".into(),
                Binding {
                    value: VmValue::Instance(instance),
                    mutable: false,
                    type_ref: None,
                    type_environment: None,
                },
            );
        }
        for (parameter, value) in closure.prototype.parameters.iter().zip(arguments) {
            self.ensure_type(
                &format!("变量“{}”", parameter.name),
                parameter.type_ref.as_ref(),
                &value,
                closure.closure.clone(),
                span,
            )?;
            environment.borrow_mut().values.insert(
                parameter.name.clone(),
                Binding {
                    value,
                    mutable: true,
                    type_ref: parameter.type_ref.clone(),
                    type_environment: Some(Rc::downgrade(&closure.closure)),
                },
            );
        }
        let result = self.run_chunk(
            Rc::new(closure.prototype.chunk.clone()),
            environment,
            format!("法“{}”", closure.prototype.name),
            closure.prototype.span.clone(),
            closure.directory.clone(),
            closure.prototype.owner_class.clone(),
        )?;
        self.ensure_type(
            &format!("法“{}”之归值", closure.prototype.name),
            closure.prototype.return_type.as_ref(),
            &result,
            closure.closure.clone(),
            span,
        )?;
        Ok(result)
    }

    fn get_property(
        &mut self,
        object: VmValue,
        name: &str,
        span: &Span,
        _offset: usize,
    ) -> Result<VmValue, VmError> {
        match object {
            VmValue::Instance(instance) => {
                let class = instance.borrow().class.clone();
                self.touch_property_cache(&class, name, false);
                if let Some(field) = class.field(name) {
                    self.check_access(field.prototype.visibility, &field.owner, name, span)?;
                }
                if let Some(value) = instance.borrow().fields.get(name).cloned() {
                    return Ok(value);
                }
                let method = class
                    .method(name)
                    .ok_or_else(|| error(span, format!("实例无成员“{name}”")))?;
                if method.closure.prototype.is_static {
                    return Err(error(span, format!("“{name}”乃静法")));
                }
                self.check_access(
                    method.closure.prototype.visibility,
                    &method.owner,
                    name,
                    span,
                )?;
                Ok(VmValue::BoundMethod(method.closure.clone(), instance))
            }
            VmValue::Class(class) => {
                self.touch_property_cache(&class, name, true);
                if let Some(field) = class.field(name).filter(|field| field.prototype.is_static) {
                    self.check_access(field.prototype.visibility, &field.owner, name, span)?;
                    return class
                        .static_storage(name)
                        .and_then(|storage| storage.borrow().get(name).cloned())
                        .ok_or_else(|| error(span, format!("静域“{name}”尚未赋值")));
                }
                let method = class
                    .method(name)
                    .filter(|method| method.closure.prototype.is_static)
                    .ok_or_else(|| {
                        error(span, format!("类“{}”无静成员“{name}”", class.type_id.name))
                    })?;
                self.check_access(
                    method.closure.prototype.visibility,
                    &method.owner,
                    name,
                    span,
                )?;
                Ok(VmValue::Closure(method.closure.clone()))
            }
            VmValue::Module(module) => {
                if !module.exports.contains(name) {
                    return Err(error(span, format!("模块“{}”未导出“{name}”", module.name)));
                }
                let value = module
                    .environment
                    .borrow()
                    .values
                    .get(name)
                    .map(|binding| binding.value.clone());
                value.ok_or_else(|| error(span, format!("模块“{}”未导出“{name}”", module.name)))
            }
            VmValue::Error(value) => match name {
                "代码" => Ok(VmValue::String(value.code.into())),
                "类别" => Ok(VmValue::String(value.category.clone())),
                "消息" => Ok(VmValue::String(value.message.clone())),
                "踪迹" => Ok(VmValue::List(Rc::new(RefCell::new(
                    value.frames.iter().cloned().map(VmValue::String).collect(),
                )))),
                "位置" => Ok(VmValue::String(value.span.to_string())),
                _ => Err(error(span, format!("误值无成员“{name}”"))),
            },
            value => Err(error(
                span,
                format!("{}无可访问之成员“{name}”", value.type_name()),
            )),
        }
    }

    fn get_super(&self, environment: &EnvRef, name: &str, span: &Span) -> Result<VmValue, VmError> {
        let owner = self
            .frames
            .last()
            .and_then(|frame| frame.owner_class.as_ref())
            .ok_or_else(|| error(span, "“父”只可用于类之法内"))?;
        let instance = environment
            .borrow()
            .get("此")
            .ok_or_else(|| error(span, "“父”只可用于实例法"))?;
        let VmValue::Instance(instance) = instance else {
            return Err(error(span, "“父”只可用于实例法"));
        };
        let parent = instance
            .borrow()
            .class
            .superclass_of(owner)
            .ok_or_else(|| error(span, format!("类“{owner}”没有父类")))?;
        let method = parent
            .method(name)
            .ok_or_else(|| error(span, format!("父类“{}”无方法“{name}”", parent.type_id.name)))?;
        if method.closure.prototype.is_static {
            return Err(error(
                span,
                format!("父类方法“{name}”乃静法，不可绑定此实例"),
            ));
        }
        if method.closure.prototype.visibility == Visibility::Private && &method.owner != owner {
            return Err(error(span, format!("父类私法“{name}”不可由子类调用")));
        }
        Ok(VmValue::BoundMethod(method.closure.clone(), instance))
    }

    fn set_index(
        &mut self,
        object: VmValue,
        index: VmValue,
        value: VmValue,
        span: &Span,
    ) -> Result<(), VmError> {
        match object {
            VmValue::List(items) => {
                let index = list_index(&index, span)?;
                let mut items = items.borrow_mut();
                let slot = items
                    .get_mut(index)
                    .ok_or_else(|| error(span, format!("列下标 {index} 超出范围")))?;
                *slot = value;
                Ok(())
            }
            VmValue::Map(map) => {
                let adds_key = !map
                    .borrow()
                    .entries
                    .iter()
                    .any(|(key, _)| values_equal(key, &index));
                if adds_key {
                    self.resources
                        .check_collection(map.borrow().entries.len().saturating_add(1))
                        .map_err(|message| error(span, message))?;
                }
                map_insert(&mut map.borrow_mut(), index, value, span)
            }
            value => Err(error(span, format!("{}不可用下标改写", value.type_name()))),
        }
    }

    fn ensure_value_budget(&self, value: &VmValue, span: &Span) -> Result<(), VmError> {
        self.ensure_value_budget_inner(value, span, &mut HashSet::new())
    }

    fn ensure_value_budget_inner(
        &self,
        value: &VmValue,
        span: &Span,
        visited: &mut HashSet<usize>,
    ) -> Result<(), VmError> {
        match value {
            VmValue::List(items) => {
                if !visited.insert(Rc::as_ptr(items) as usize) {
                    return Ok(());
                }
                let items = items.borrow();
                self.resources
                    .check_collection(items.len())
                    .map_err(|message| error(span, message))?;
                for item in items.iter() {
                    self.ensure_value_budget_inner(item, span, visited)?;
                }
            }
            VmValue::Tuple(items) => {
                if !visited.insert(Rc::as_ptr(items) as usize) {
                    return Ok(());
                }
                self.resources
                    .check_collection(items.len())
                    .map_err(|message| error(span, message))?;
                for item in items.iter() {
                    self.ensure_value_budget_inner(item, span, visited)?;
                }
            }
            VmValue::Map(map) => {
                if !visited.insert(Rc::as_ptr(map) as usize) {
                    return Ok(());
                }
                let map = map.borrow();
                self.resources
                    .check_collection(map.entries.len())
                    .map_err(|message| error(span, message))?;
                for (key, item) in &map.entries {
                    self.ensure_value_budget_inner(key, span, visited)?;
                    self.ensure_value_budget_inner(item, span, visited)?;
                }
            }
            VmValue::Bytes(bytes)
                if bytes.len() as u64 > self.resources.host_limits().max_byte_value_bytes() =>
            {
                return Err(bytes_error(
                    span,
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

    fn set_property(
        &mut self,
        object: VmValue,
        name: &str,
        value: VmValue,
        span: &Span,
        _offset: usize,
    ) -> Result<(), VmError> {
        match object {
            VmValue::Instance(instance) => {
                let class = instance.borrow().class.clone();
                self.touch_property_cache(&class, name, false);
                if let Some(field) = class.field(name) {
                    if field.prototype.is_static {
                        return Err(error(span, format!("“{name}”乃静域")));
                    }
                    self.check_access(field.prototype.visibility, &field.owner, name, span)?;
                    if field.prototype.readonly && instance.borrow().fields.contains_key(name) {
                        return Err(error(span, format!("只读域“{name}”不可再次改写")));
                    }
                    self.ensure_type(
                        &format!("域“{name}”"),
                        Some(&field.prototype.type_ref),
                        &value,
                        field.type_environment.clone(),
                        span,
                    )?;
                } else if class.has_instance_fields() {
                    return Err(error(
                        span,
                        format!("类“{}”未声明域“{name}”", class.type_id.name),
                    ));
                }
                instance.borrow_mut().fields.insert(name.into(), value);
                Ok(())
            }
            VmValue::Class(class) => {
                self.touch_property_cache(&class, name, true);
                let field = class
                    .field(name)
                    .filter(|field| field.prototype.is_static)
                    .ok_or_else(|| {
                        error(span, format!("类“{}”无静域“{name}”", class.type_id.name))
                    })?;
                self.check_access(field.prototype.visibility, &field.owner, name, span)?;
                let storage = class
                    .static_storage(name)
                    .expect("static field has storage");
                if field.prototype.readonly && storage.borrow().contains_key(name) {
                    return Err(error(span, format!("只读静域“{name}”不可再次改写")));
                }
                self.ensure_type(
                    &format!("静域“{name}”"),
                    Some(&field.prototype.type_ref),
                    &value,
                    field.type_environment.clone(),
                    span,
                )?;
                storage.borrow_mut().insert(name.into(), value);
                Ok(())
            }
            value => Err(error(
                span,
                format!("{}不可拥有字段“{name}”", value.type_name()),
            )),
        }
    }

    fn check_access(
        &self,
        visibility: Visibility,
        owner: &TypeId,
        name: &str,
        span: &Span,
    ) -> Result<(), VmError> {
        if visibility == Visibility::Public
            || self
                .frames
                .last()
                .and_then(|frame| frame.owner_class.as_ref())
                == Some(owner)
        {
            Ok(())
        } else {
            Err(error(span, format!("私成员“{name}”不可从类外访问")))
        }
    }

    fn touch_property_cache(&mut self, class: &Rc<VmClass>, name: &str, is_static: bool) {
        let key = (Rc::as_ptr(class) as usize, name.into(), is_static);
        if self.property_cache.insert(key) {
            self.cache_stats.property_misses += 1;
        } else {
            self.cache_stats.property_hits += 1;
        }
    }

    fn make_iterator(
        &mut self,
        value: VmValue,
        span: &Span,
        directory: &Path,
    ) -> Result<Rc<RefCell<VmIterator>>, VmError> {
        let iterator = match value {
            VmValue::Iterator(iterator) => return Ok(iterator),
            VmValue::List(values) => VmIterator::Values {
                values: values.borrow().clone(),
                index: 0,
            },
            VmValue::Tuple(values) => VmIterator::Values {
                values: values.as_ref().clone(),
                index: 0,
            },
            VmValue::String(text) => VmIterator::Values {
                values: text
                    .chars()
                    .map(|character| VmValue::String(character.to_string()))
                    .collect(),
                index: 0,
            },
            VmValue::Map(map) => VmIterator::Values {
                values: map
                    .borrow()
                    .entries
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect(),
                index: 0,
            },
            VmValue::Instance(instance) => {
                let start = instance
                    .borrow()
                    .class
                    .method("遍始")
                    .map(|method| method.closure.clone());
                if let Some(start) = start {
                    let started = self.call_closure(
                        start,
                        Some(instance.clone()),
                        Vec::new(),
                        span,
                        directory,
                    )?;
                    if !matches!(&started, VmValue::Instance(value) if Rc::ptr_eq(value, &instance))
                    {
                        return self.make_iterator(started, span, directory);
                    }
                }
                if instance.borrow().class.method("遍次").is_none() {
                    return Err(error(span, "对象未实现“遍次”"));
                }
                VmIterator::Object(instance)
            }
            value => return Err(error(span, format!("{}不可遍历", value.type_name()))),
        };
        Ok(Rc::new(RefCell::new(iterator)))
    }

    fn next_iterator(
        &mut self,
        iterator: &Rc<RefCell<VmIterator>>,
        span: &Span,
        directory: &Path,
    ) -> Result<Option<VmValue>, VmError> {
        match &mut *iterator.borrow_mut() {
            VmIterator::Values { values, index } => {
                let value = values.get(*index).cloned();
                *index += usize::from(value.is_some());
                Ok(value)
            }
            VmIterator::Range { current, end, step } => {
                let valid = if *step > 0.0 {
                    *current < *end
                } else {
                    *current > *end
                };
                if !valid {
                    return Ok(None);
                }
                let value = *current;
                *current += *step;
                Ok(Some(VmValue::Number(value)))
            }
            VmIterator::Object(instance) => {
                let method = instance
                    .borrow()
                    .class
                    .method("遍次")
                    .map(|method| method.closure.clone())
                    .ok_or_else(|| error(span, "对象未实现“遍次”"))?;
                let value =
                    self.call_closure(method, Some(instance.clone()), Vec::new(), span, directory)?;
                parse_iterator_result(value, span)
            }
            VmIterator::Mapped { source, mapper } => self
                .next_iterator(source, span, directory)?
                .map(|value| self.call_value(mapper.clone(), vec![value], span, directory))
                .transpose(),
            VmIterator::Filtered { source, predicate } => loop {
                let Some(value) = self.next_iterator(source, span, directory)? else {
                    return Ok(None);
                };
                if self
                    .call_value(predicate.clone(), vec![value.clone()], span, directory)?
                    .truthy()
                {
                    return Ok(Some(value));
                }
            },
        }
    }

    fn call_native(
        &mut self,
        kind: NativeKind,
        arguments: &[VmValue],
        span: &Span,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        match kind {
            NativeKind::Clock => Ok(VmValue::Number(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| error(span, "无法取得时刻"))?
                    .as_secs_f64(),
            )),
            NativeKind::Length => match &arguments[0] {
                VmValue::String(value) => Ok(VmValue::Number(value.chars().count() as f64)),
                VmValue::Bytes(value) => Ok(VmValue::Number(value.len() as f64)),
                VmValue::List(value) => Ok(VmValue::Number(value.borrow().len() as f64)),
                VmValue::Tuple(value) => Ok(VmValue::Number(value.len() as f64)),
                VmValue::Map(value) => Ok(VmValue::Number(value.borrow().entries.len() as f64)),
                value => Err(error(span, format!("“长度”不适用于{}", value.type_name()))),
            },
            NativeKind::Type => Ok(VmValue::String(arguments[0].type_name())),
            NativeKind::Append => match &arguments[0] {
                VmValue::List(value) => {
                    self.resources
                        .check_collection(value.borrow().len().saturating_add(1))
                        .map_err(|message| error(span, message))?;
                    value.borrow_mut().push(arguments[1].clone());
                    Ok(arguments[0].clone())
                }
                value => Err(error(span, format!("“追加”不适用于{}", value.type_name()))),
            },
            NativeKind::Pop => match &arguments[0] {
                VmValue::List(value) => value
                    .borrow_mut()
                    .pop()
                    .ok_or_else(|| error(span, "不可从空列弹出")),
                value => Err(error(span, format!("“弹出”不适用于{}", value.type_name()))),
            },
            NativeKind::HasKey => match &arguments[0] {
                VmValue::Map(value) => Ok(VmValue::Bool(
                    value
                        .borrow()
                        .entries
                        .iter()
                        .any(|(key, _)| values_equal(key, &arguments[1])),
                )),
                value => Err(error(span, format!("“有键”不适用于{}", value.type_name()))),
            },
            NativeKind::Insert => match &arguments[0] {
                VmValue::List(value) => {
                    let index = list_index(&arguments[1], span)?;
                    if index > value.borrow().len() {
                        return Err(error(span, format!("列下标 {index} 超出可插入范围")));
                    }
                    self.resources
                        .check_collection(value.borrow().len().saturating_add(1))
                        .map_err(|message| error(span, message))?;
                    value.borrow_mut().insert(index, arguments[2].clone());
                    Ok(arguments[0].clone())
                }
                value => Err(error(span, format!("“插入”不适用于{}", value.type_name()))),
            },
            NativeKind::Remove => match &arguments[0] {
                VmValue::List(value) => {
                    let index = list_index(&arguments[1], span)?;
                    if index >= value.borrow().len() {
                        return Err(error(span, format!("列下标 {index} 超出范围")));
                    }
                    Ok(value.borrow_mut().remove(index))
                }
                value => Err(error(span, format!("“删除”不适用于{}", value.type_name()))),
            },
            NativeKind::Keys | NativeKind::Values => match &arguments[0] {
                VmValue::Map(value) => {
                    let take_keys = matches!(kind, NativeKind::Keys);
                    let items = value
                        .borrow()
                        .entries
                        .iter()
                        .map(|(key, value)| {
                            if take_keys {
                                key.clone()
                            } else {
                                value.clone()
                            }
                        })
                        .collect();
                    Ok(VmValue::List(Rc::new(RefCell::new(items))))
                }
                value => Err(error(span, format!("典原语不适用于{}", value.type_name()))),
            },
            NativeKind::Iterator => Ok(VmValue::Iterator(self.make_iterator(
                arguments[0].clone(),
                span,
                directory,
            )?)),
            NativeKind::Next => {
                let VmValue::Iterator(iterator) = &arguments[0] else {
                    return Err(error(span, "“续”须收遍器"));
                };
                Ok(iterator_result(
                    self.next_iterator(iterator, span, directory)?,
                ))
            }
            NativeKind::Range | NativeKind::SteppedRange => {
                let start = number(&arguments[0], span)?;
                let end = number(&arguments[1], span)?;
                let step = if matches!(kind, NativeKind::SteppedRange) {
                    number(&arguments[2], span)?
                } else {
                    1.0
                };
                if step == 0.0 {
                    return Err(error(span, "范围步长不可为零"));
                }
                Ok(VmValue::Iterator(Rc::new(RefCell::new(
                    VmIterator::Range {
                        current: start,
                        end,
                        step,
                    },
                ))))
            }
            NativeKind::Map | NativeKind::Filter => {
                ensure_callable(&arguments[1], span)?;
                let source = self.make_iterator(arguments[0].clone(), span, directory)?;
                let iterator = if matches!(kind, NativeKind::Map) {
                    VmIterator::Mapped {
                        source,
                        mapper: arguments[1].clone(),
                    }
                } else {
                    VmIterator::Filtered {
                        source,
                        predicate: arguments[1].clone(),
                    }
                };
                Ok(VmValue::Iterator(Rc::new(RefCell::new(iterator))))
            }
            NativeKind::Fold => {
                ensure_callable(&arguments[2], span)?;
                let iterator = self.make_iterator(arguments[0].clone(), span, directory)?;
                let mut value = arguments[1].clone();
                while let Some(item) = self.next_iterator(&iterator, span, directory)? {
                    value =
                        self.call_value(arguments[2].clone(), vec![value, item], span, directory)?;
                }
                Ok(value)
            }
            NativeKind::Sort | NativeKind::Reverse => {
                let iterator = self.make_iterator(arguments[0].clone(), span, directory)?;
                let mut values = Vec::new();
                while let Some(value) = self.next_iterator(&iterator, span, directory)? {
                    values.push(value);
                }
                if matches!(kind, NativeKind::Sort) {
                    values.sort_by(compare_values_for_sort);
                } else {
                    values.reverse();
                }
                Ok(VmValue::List(Rc::new(RefCell::new(values))))
            }
            NativeKind::Contains => {
                let iterator = self.make_iterator(arguments[0].clone(), span, directory)?;
                while let Some(value) = self.next_iterator(&iterator, span, directory)? {
                    if values_equal(&value, &arguments[1]) {
                        return Ok(VmValue::Bool(true));
                    }
                }
                Ok(VmValue::Bool(false))
            }
            NativeKind::Find => {
                ensure_callable(&arguments[1], span)?;
                let iterator = self.make_iterator(arguments[0].clone(), span, directory)?;
                while let Some(value) = self.next_iterator(&iterator, span, directory)? {
                    if self
                        .call_value(arguments[1].clone(), vec![value.clone()], span, directory)?
                        .truthy()
                    {
                        return Ok(iterator_result(Some(value)));
                    }
                }
                Ok(iterator_result(None))
            }
            NativeKind::Abs => Ok(VmValue::Number(number(&arguments[0], span)?.abs())),
            NativeKind::Sqrt => {
                let value = number(&arguments[0], span)?;
                if value < 0.0 {
                    return Err(error(span, "负数不可求实平方根"));
                }
                Ok(VmValue::Number(value.sqrt()))
            }
            NativeKind::Pow => Ok(VmValue::Number(
                number(&arguments[0], span)?.powf(number(&arguments[1], span)?),
            )),
            NativeKind::CancelTask => {
                let VmValue::Task(task) = &arguments[0] else {
                    return Err(error(
                        span,
                        format!("“取消”须收任务，不可收{}", arguments[0].type_name()),
                    ));
                };
                let mut task = task.borrow_mut();
                let cancelled = matches!(task.state, VmTaskState::Pending { .. });
                if cancelled {
                    task.state = VmTaskState::Cancelled;
                }
                Ok(VmValue::Bool(cancelled))
            }
            NativeKind::TaskStatus => {
                let VmValue::Task(task) = &arguments[0] else {
                    return Err(error(
                        span,
                        format!("“任务状态”须收任务，不可收{}", arguments[0].type_name()),
                    ));
                };
                Ok(VmValue::String(task.borrow().status().into()))
            }
            NativeKind::JoinTasks => self.join_tasks(&arguments[0], span),
            NativeKind::Standard(function) => {
                self.call_standard_native(function, arguments, span, directory)
            }
        }
    }

    fn await_task(&mut self, task: &Rc<RefCell<VmTask>>, span: &Span) -> Result<VmValue, VmError> {
        let state = std::mem::replace(&mut task.borrow_mut().state, VmTaskState::Running);
        match state {
            VmTaskState::Pending {
                closure,
                instance,
                arguments,
                directory,
            } => match self.call_closure(closure, instance, arguments, span, &directory) {
                Ok(value) => {
                    task.borrow_mut().state = VmTaskState::Completed(value.clone());
                    Ok(value)
                }
                Err(runtime_error) => {
                    task.borrow_mut().state = VmTaskState::Failed(runtime_error.clone());
                    Err(runtime_error)
                }
            },
            VmTaskState::Completed(value) => {
                task.borrow_mut().state = VmTaskState::Completed(value.clone());
                Ok(value)
            }
            VmTaskState::Failed(runtime_error) => {
                task.borrow_mut().state = VmTaskState::Failed(runtime_error.clone());
                Err(runtime_error)
            }
            VmTaskState::Cancelled => {
                task.borrow_mut().state = VmTaskState::Cancelled;
                Err(error(span, "任务已取消，不可等候"))
            }
            VmTaskState::Running => {
                task.borrow_mut().state = VmTaskState::Running;
                Err(error(span, "任务正在运行，不可自相等候"))
            }
        }
    }

    fn join_tasks(&mut self, value: &VmValue, span: &Span) -> Result<VmValue, VmError> {
        let values = match value {
            VmValue::List(values) => values.borrow().clone(),
            VmValue::Tuple(values) => values.as_ref().clone(),
            value => {
                return Err(error(
                    span,
                    format!("“并候”须收任务列，不可收{}", value.type_name()),
                ));
            }
        };
        let tasks = values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                VmValue::Task(task) => Ok(task.clone()),
                value => Err(error(
                    span,
                    format!(
                        "“并候”第 {} 项须为任务，不可为{}",
                        index + 1,
                        value.type_name()
                    ),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut results = Vec::with_capacity(tasks.len());
        for (index, task) in tasks.iter().enumerate() {
            match self.await_task(task, span) {
                Ok(value) => results.push(value),
                Err(mut runtime_error) => {
                    for pending in &tasks[index + 1..] {
                        let mut pending = pending.borrow_mut();
                        if matches!(pending.state, VmTaskState::Pending { .. }) {
                            pending.state = VmTaskState::Cancelled;
                        }
                    }
                    runtime_error.frames.push("结构化并候".into());
                    return Err(runtime_error);
                }
            }
        }
        Ok(VmValue::List(Rc::new(RefCell::new(results))))
    }

    fn call_standard_native(
        &mut self,
        function: StandardNative,
        arguments: &[VmValue],
        span: &Span,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        use StandardNative as Std;
        match function {
            Std::Floor => Ok(VmValue::Number(number(&arguments[0], span)?.floor())),
            Std::Ceil => Ok(VmValue::Number(number(&arguments[0], span)?.ceil())),
            Std::Round => Ok(VmValue::Number(number(&arguments[0], span)?.round())),
            Std::Sin => Ok(VmValue::Number(number(&arguments[0], span)?.sin())),
            Std::Cos => Ok(VmValue::Number(number(&arguments[0], span)?.cos())),
            Std::Min => Ok(VmValue::Number(
                number(&arguments[0], span)?.min(number(&arguments[1], span)?),
            )),
            Std::Max => Ok(VmValue::Number(
                number(&arguments[0], span)?.max(number(&arguments[1], span)?),
            )),
            Std::Trim => Ok(VmValue::String(
                vm_string(&arguments[0], "修剪", span)?.trim().into(),
            )),
            Std::Split => {
                let text = vm_string(&arguments[0], "分割", span)?;
                let separator = vm_string(&arguments[1], "分割", span)?;
                let items = if separator.is_empty() {
                    text.chars()
                        .map(|character| VmValue::String(character.to_string()))
                        .collect()
                } else {
                    text.split(separator)
                        .map(|part| VmValue::String(part.into()))
                        .collect()
                };
                Ok(VmValue::List(Rc::new(RefCell::new(items))))
            }
            Std::Replace => Ok(VmValue::String(
                vm_string(&arguments[0], "替换", span)?.replace(
                    vm_string(&arguments[1], "替换", span)?,
                    vm_string(&arguments[2], "替换", span)?,
                ),
            )),
            Std::StartsWith => Ok(VmValue::Bool(
                vm_string(&arguments[0], "始于", span)?.starts_with(vm_string(
                    &arguments[1],
                    "始于",
                    span,
                )?),
            )),
            Std::EndsWith => Ok(VmValue::Bool(
                vm_string(&arguments[0], "终于", span)?.ends_with(vm_string(
                    &arguments[1],
                    "终于",
                    span,
                )?),
            )),
            Std::Uppercase => Ok(VmValue::String(
                vm_string(&arguments[0], "大写", span)?.to_uppercase(),
            )),
            Std::Lowercase => Ok(VmValue::String(
                vm_string(&arguments[0], "小写", span)?.to_lowercase(),
            )),
            Std::Characters => Ok(VmValue::List(Rc::new(RefCell::new(
                vm_string(&arguments[0], "字符列", span)?
                    .chars()
                    .map(|character| VmValue::String(character.to_string()))
                    .collect(),
            )))),
            Std::Join => {
                let separator = vm_string(&arguments[1], "联结", span)?;
                let items = vm_string_sequence(&arguments[0], "联结", span)?;
                Ok(VmValue::String(items.join(separator)))
            }
            Std::BytesFromText => {
                let text = vm_string(&arguments[0], "字节.从文字", span)?;
                if text.len() > crate::stdlib::BYTES_MAX_VALUE_BYTES {
                    return Err(bytes_error(
                        span,
                        "BYTES_LIMIT",
                        format!(
                            "字节串不得超过 {} 字节",
                            crate::stdlib::BYTES_MAX_VALUE_BYTES
                        ),
                    ));
                }
                Ok(VmValue::Bytes(Rc::new(text.as_bytes().to_vec())))
            }
            Std::BytesToText => String::from_utf8(
                vm_bytes(&arguments[0], "字节.转文字", span)?
                    .as_ref()
                    .clone(),
            )
            .map(VmValue::String)
            .map_err(|_| bytes_error(span, "BYTES_UTF8", "字节串不是有效的 UTF-8 文字")),
            Std::BytesLength => Ok(VmValue::Number(
                vm_bytes(&arguments[0], "字节.长度", span)?.len() as f64,
            )),
            Std::BytesSlice => {
                let bytes = vm_bytes(&arguments[0], "字节.切片", span)?;
                let start = vm_nonnegative_usize(&arguments[1], "字节.切片", bytes.len(), span)?;
                let end = vm_nonnegative_usize(&arguments[2], "字节.切片", bytes.len(), span)?;
                crate::stdlib::bytes_slice(&bytes, start, end)
                    .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                    .map_err(|message| bytes_error(span, "BYTES_RANGE", message))
            }
            Std::BytesConcat => {
                let left = vm_bytes(&arguments[0], "字节.拼接", span)?;
                let right = vm_bytes(&arguments[1], "字节.拼接", span)?;
                crate::stdlib::bytes_concat(&left, &right)
                    .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                    .map_err(|message| bytes_error(span, "BYTES_LIMIT", message))
            }
            Std::BytesFind => {
                let source = vm_bytes(&arguments[0], "字节.查找", span)?;
                let needle = vm_bytes(&arguments[1], "字节.查找", span)?;
                Ok(crate::stdlib::bytes_find(&source, &needle)
                    .map_or(VmValue::Nil, |index| VmValue::Number(index as f64)))
            }
            Std::BytesFromNumbers => crate::stdlib::bytes_from_numbers(&vm_number_sequence(
                &arguments[0],
                "字节.从数列",
                span,
            )?)
            .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
            .map_err(|message| bytes_error(span, "BYTES_VALUE", message)),
            Std::BytesToNumbers => {
                let bytes = vm_bytes(&arguments[0], "字节.转数列", span)?;
                Ok(VmValue::List(Rc::new(RefCell::new(
                    bytes
                        .iter()
                        .map(|byte| VmValue::Number(f64::from(*byte)))
                        .collect(),
                ))))
            }
            Std::Millis => Ok(VmValue::Number(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| error(span, "无法取得时刻"))?
                    .as_millis() as f64,
            )),
            Std::Sleep => {
                let seconds = number(&arguments[0], span)?;
                if !(0.0..=60.0).contains(&seconds) {
                    return Err(error(span, "“等待”秒数须在 0 至 60 之间"));
                }
                std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
                Ok(VmValue::Nil)
            }
            Std::ReadFile => {
                let path = vm_string(&arguments[0], "读取", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                fs::read_to_string(path)
                    .map(VmValue::String)
                    .map_err(|runtime_error| {
                        error(span, format!("不能读取“{path}”：{runtime_error}"))
                    })
            }
            Std::ReadBytes => {
                let path = vm_string(&arguments[0], "文件.读取字节", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                crate::stdlib::read_file_bytes(Path::new(path))
                    .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                    .map_err(|source| match source {
                        crate::stdlib::FileBytesError::Io(message) => {
                            error(span, format!("“{path}”：{message}"))
                        }
                        crate::stdlib::FileBytesError::Limit(message) => {
                            bytes_error(span, "BYTES_LIMIT", format!("“{path}”：{message}"))
                        }
                    })
            }
            Std::WriteFile => {
                let path = vm_string(&arguments[0], "写入", span)?;
                let text = vm_string(&arguments[1], "写入", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                fs::write(path, text)
                    .map(|()| VmValue::Number(text.len() as f64))
                    .map_err(|runtime_error| {
                        error(span, format!("不能写入“{path}”：{runtime_error}"))
                    })
            }
            Std::WriteBytes => {
                let path = vm_string(&arguments[0], "文件.写入字节", span)?;
                let bytes = vm_bytes(&arguments[1], "文件.写入字节", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                fs::write(path, bytes.as_ref())
                    .map(|()| VmValue::Number(bytes.len() as f64))
                    .map_err(|runtime_error| {
                        error(span, format!("不能写入“{path}”：{runtime_error}"))
                    })
            }
            Std::AppendFile => {
                use std::io::Write;
                let path = vm_string(&arguments[0], "追加", span)?;
                let text = vm_string(&arguments[1], "追加", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|runtime_error| {
                        error(span, format!("不能打开“{path}”：{runtime_error}"))
                    })?;
                file.write_all(text.as_bytes()).map_err(|runtime_error| {
                    error(span, format!("不能追加“{path}”：{runtime_error}"))
                })?;
                Ok(VmValue::Number(text.len() as f64))
            }
            Std::AppendBytes => {
                use std::io::Write;
                let path = vm_string(&arguments[0], "文件.追加字节", span)?;
                let bytes = vm_bytes(&arguments[1], "文件.追加字节", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|runtime_error| {
                        error(span, format!("不能打开“{path}”：{runtime_error}"))
                    })?;
                file.write_all(&bytes).map_err(|runtime_error| {
                    error(span, format!("不能追加“{path}”：{runtime_error}"))
                })?;
                Ok(VmValue::Number(bytes.len() as f64))
            }
            Std::FileStatus => {
                let path = vm_string(&arguments[0], "文件.状态", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                let status = crate::stdlib::file_status(Path::new(path))
                    .map_err(|message| error(span, message))?;
                Ok(vm_string_key_map(vec![
                    ("种类", VmValue::String(status.kind.into())),
                    ("字节数", VmValue::Number(status.bytes as f64)),
                    ("只读", VmValue::Bool(status.readonly)),
                    (
                        "修改毫秒",
                        status
                            .modified_millis
                            .map_or(VmValue::Nil, |millis| VmValue::Number(millis as f64)),
                    ),
                ]))
            }
            Std::PathExists => {
                let path = vm_string(&arguments[0], "存在", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                Ok(VmValue::Bool(Path::new(path).exists()))
            }
            Std::ReadDirectory => {
                let path = vm_string(&arguments[0], "目录", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                let mut entries = fs::read_dir(path)
                    .map_err(|runtime_error| {
                        error(span, format!("不能读取目录“{path}”：{runtime_error}"))
                    })?
                    .map(|entry| {
                        entry
                            .map(|entry| {
                                VmValue::String(entry.file_name().to_string_lossy().into_owned())
                            })
                            .map_err(|runtime_error| {
                                error(span, format!("不能读取目录项：{runtime_error}"))
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                entries.sort_by(compare_values_for_sort);
                Ok(VmValue::List(Rc::new(RefCell::new(entries))))
            }
            Std::CreateDirectory => {
                let path = vm_string(&arguments[0], "文件.创建目录", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                crate::stdlib::create_directory(Path::new(path))
                    .map(|()| VmValue::Nil)
                    .map_err(|message| error(span, message))
            }
            Std::RemovePath => {
                let path = vm_string(&arguments[0], "文件.删除", span)?;
                let recursive = vm_bool(&arguments[1], "文件.删除", span)?;
                self.permissions
                    .check_file(path)
                    .map_err(|permission| error(span, permission.to_string()))?;
                crate::stdlib::remove_path(Path::new(path), recursive)
                    .map(|()| VmValue::Nil)
                    .map_err(|message| error(span, message))
            }
            Std::JsonParse => {
                let json = serde_json::from_str(vm_string(&arguments[0], "JSON.解析", span)?)
                    .map_err(|runtime_error| {
                        error(span, format!("JSON 解析失败：{runtime_error}"))
                    })?;
                vm_json_to_value(json, span)
            }
            Std::JsonStringify => serde_json::to_string(&vm_value_to_json(&arguments[0], span)?)
                .map(VmValue::String)
                .map_err(|runtime_error| error(span, format!("JSON 序列化失败：{runtime_error}"))),
            Std::HttpGet => crate::stdlib::http_request_with_options_and_limits_guarded(
                "GET",
                vm_string(&arguments[0], "网络.获取", span)?,
                None,
                &self.permissions,
                crate::stdlib::HttpRequestBudget::new(
                    crate::stdlib::HTTP_DEFAULT_TIMEOUT_MILLIS,
                    crate::stdlib::HTTP_DEFAULT_MAX_BYTES,
                    self.resources.host_limits(),
                ),
            )
            .map(|response| VmValue::String(response.body))
            .map_err(|source| network_error(span, source)),
            Std::HttpPost => crate::stdlib::http_request_with_options_and_limits_guarded(
                "POST",
                vm_string(&arguments[0], "网络.发文", span)?,
                Some(vm_string(&arguments[1], "网络.发文", span)?),
                &self.permissions,
                crate::stdlib::HttpRequestBudget::new(
                    crate::stdlib::HTTP_DEFAULT_TIMEOUT_MILLIS,
                    crate::stdlib::HTTP_DEFAULT_MAX_BYTES,
                    self.resources.host_limits(),
                ),
            )
            .map(|response| VmValue::String(response.body))
            .map_err(|source| network_error(span, source)),
            Std::HttpRequest => {
                let method = vm_string(&arguments[0], "网络.请求", span)?;
                let url = vm_string(&arguments[1], "网络.请求", span)?;
                let body = vm_string(&arguments[2], "网络.请求", span)?;
                let timeout = vm_positive_u64(&arguments[3], "网络.请求", "超时毫秒", span)?;
                let max_bytes = vm_positive_u64(&arguments[4], "网络.请求", "最大字节", span)?;
                let response = crate::stdlib::http_request_with_options_and_limits_guarded(
                    method,
                    url,
                    Some(body),
                    &self.permissions,
                    crate::stdlib::HttpRequestBudget::new(
                        timeout,
                        max_bytes,
                        self.resources.host_limits(),
                    ),
                )
                .map_err(|source| network_error(span, source))?;
                let headers = VmValue::Map(Rc::new(RefCell::new(VmMap {
                    entries: response
                        .headers
                        .into_iter()
                        .map(|(name, value)| (VmValue::String(name), VmValue::String(value)))
                        .collect(),
                })));
                Ok(VmValue::Map(Rc::new(RefCell::new(VmMap {
                    entries: vec![
                        (
                            VmValue::String("状态".into()),
                            VmValue::Number(f64::from(response.status)),
                        ),
                        (
                            VmValue::String("地址".into()),
                            VmValue::String(response.url),
                        ),
                        (VmValue::String("首部".into()), headers),
                        (
                            VmValue::String("正文".into()),
                            VmValue::String(response.body),
                        ),
                    ],
                }))))
            }
            Std::HttpBytesRequest => {
                let method = vm_string(&arguments[0], "网络.请求字节", span)?;
                let url = vm_string(&arguments[1], "网络.请求字节", span)?;
                let headers = vm_string_map(&arguments[2], "网络.请求字节", span)?;
                let body = match &arguments[3] {
                    VmValue::Nil => None,
                    VmValue::Bytes(bytes) => Some(bytes.clone()),
                    value => {
                        return Err(bytes_error(
                            span,
                            "BYTES_TYPE",
                            format!(
                                "“网络.请求字节”第 4 参数须为字节串或空，不可为{}",
                                value.type_name()
                            ),
                        ));
                    }
                };
                let timeout = vm_positive_u64(&arguments[4], "网络.请求字节", "超时毫秒", span)?;
                let max_bytes = vm_positive_u64(&arguments[5], "网络.请求字节", "最大字节", span)?;
                let response = crate::stdlib::http_request_bytes_with_options_and_limits_guarded(
                    method,
                    url,
                    &headers,
                    body.as_deref().map(Vec::as_slice),
                    &self.permissions,
                    crate::stdlib::HttpRequestBudget::new(
                        timeout,
                        max_bytes,
                        self.resources.host_limits(),
                    ),
                )
                .map_err(|source| network_error(span, source))?;
                let headers = VmValue::Map(Rc::new(RefCell::new(VmMap {
                    entries: response
                        .headers
                        .into_iter()
                        .map(|(name, value)| (VmValue::String(name), VmValue::String(value)))
                        .collect(),
                })));
                Ok(vm_string_key_map(vec![
                    ("状态", VmValue::Number(f64::from(response.status))),
                    ("地址", VmValue::String(response.url)),
                    ("首部", headers),
                    ("正文", VmValue::Bytes(Rc::new(response.body))),
                ]))
            }
            Std::SocketTcpConnect => {
                let address = vm_string(&arguments[0], "套接字.TCP连接", span)?;
                let timeout = vm_socket_timeout(&arguments[1], "套接字.TCP连接", span)?;
                crate::stdlib::socket_tcp_connect_guarded(
                    address,
                    timeout,
                    &self.permissions,
                    &self.socket_quota,
                )
                .map(|socket| VmValue::Socket(Rc::new(RefCell::new(socket))))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketTcpListen => {
                let address = vm_string(&arguments[0], "套接字.TCP监听", span)?;
                crate::stdlib::socket_tcp_listen_guarded(
                    address,
                    &self.permissions,
                    &self.socket_quota,
                )
                .map(|socket| VmValue::Socket(Rc::new(RefCell::new(socket))))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketAccept => {
                let socket = vm_socket(&arguments[0], "套接字.接受", span)?;
                let timeout = vm_socket_timeout(&arguments[1], "套接字.接受", span)?;
                let (accepted, peer) =
                    crate::stdlib::socket_accept(&mut socket.borrow_mut(), timeout)
                        .map_err(|source| socket_error(span, source))?;
                Ok(vm_string_key_map(vec![
                    ("套接字", VmValue::Socket(Rc::new(RefCell::new(accepted)))),
                    ("对端", VmValue::String(peer)),
                ]))
            }
            Std::SocketSend => {
                let socket = vm_socket(&arguments[0], "套接字.发送", span)?;
                let text = vm_string(&arguments[1], "套接字.发送", span)?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.发送", span)?;
                crate::stdlib::socket_send(&mut socket.borrow_mut(), text, timeout)
                    .map(|written| VmValue::Number(written as f64))
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketReceive => {
                let socket = vm_socket(&arguments[0], "套接字.接收", span)?;
                let max_bytes = vm_socket_max_bytes(
                    &arguments[1],
                    "套接字.接收",
                    self.resources.host_limits().max_socket_read_bytes(),
                    span,
                )?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.接收", span)?;
                crate::stdlib::socket_receive(&mut socket.borrow_mut(), max_bytes, timeout)
                    .map(VmValue::String)
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketSendBytes => {
                let socket = vm_socket(&arguments[0], "套接字.发送字节", span)?;
                let bytes = vm_bytes(&arguments[1], "套接字.发送字节", span)?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.发送字节", span)?;
                crate::stdlib::socket_send_bytes(&mut socket.borrow_mut(), &bytes, timeout)
                    .map(|written| VmValue::Number(written as f64))
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketReceiveBytes => {
                let socket = vm_socket(&arguments[0], "套接字.接收字节", span)?;
                let max_bytes = vm_socket_max_bytes(
                    &arguments[1],
                    "套接字.接收字节",
                    self.resources.host_limits().max_socket_read_bytes(),
                    span,
                )?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.接收字节", span)?;
                let received = crate::stdlib::socket_receive_bytes(
                    &mut socket.borrow_mut(),
                    max_bytes,
                    timeout,
                )
                .map_err(|source| socket_error(span, source))?;
                Ok(vm_string_key_map(vec![
                    ("数据", VmValue::Bytes(Rc::new(received.bytes))),
                    ("已结束", VmValue::Bool(received.eof)),
                ]))
            }
            Std::SocketReadExact => {
                let socket = vm_socket(&arguments[0], "套接字.精确读取", span)?;
                let byte_count = vm_socket_max_bytes(
                    &arguments[1],
                    "套接字.精确读取",
                    self.resources.host_limits().max_socket_read_bytes(),
                    span,
                )?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.精确读取", span)?;
                crate::stdlib::socket_read_exact_bytes(
                    &mut socket.borrow_mut(),
                    byte_count,
                    timeout,
                )
                .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketUdpBind => {
                let address = vm_string(&arguments[0], "套接字.UDP绑定", span)?;
                crate::stdlib::socket_udp_bind_guarded(
                    address,
                    &self.permissions,
                    &self.socket_quota,
                )
                .map(|socket| VmValue::Socket(Rc::new(RefCell::new(socket))))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketUdpSendTo => {
                let socket = vm_socket(&arguments[0], "套接字.UDP发送至", span)?;
                let text = vm_string(&arguments[1], "套接字.UDP发送至", span)?;
                let address = vm_string(&arguments[2], "套接字.UDP发送至", span)?;
                let timeout = vm_socket_timeout(&arguments[3], "套接字.UDP发送至", span)?;
                crate::stdlib::socket_udp_send_to_guarded(
                    &mut socket.borrow_mut(),
                    text,
                    address,
                    timeout,
                    &self.permissions,
                )
                .map(|written| VmValue::Number(written as f64))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketUdpReceiveFrom => {
                let socket = vm_socket(&arguments[0], "套接字.UDP接收自", span)?;
                let max_bytes = vm_socket_max_bytes(
                    &arguments[1],
                    "套接字.UDP接收自",
                    self.resources.host_limits().max_socket_read_bytes(),
                    span,
                )?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.UDP接收自", span)?;
                let (text, peer) = crate::stdlib::socket_udp_receive_from(
                    &mut socket.borrow_mut(),
                    max_bytes,
                    timeout,
                )
                .map_err(|source| socket_error(span, source))?;
                Ok(vm_string_key_map(vec![
                    ("正文", VmValue::String(text)),
                    ("对端", VmValue::String(peer)),
                ]))
            }
            Std::SocketUdpSendBytesTo => {
                let socket = vm_socket(&arguments[0], "套接字.UDP发送字节至", span)?;
                let bytes = vm_bytes(&arguments[1], "套接字.UDP发送字节至", span)?;
                let address = vm_string(&arguments[2], "套接字.UDP发送字节至", span)?;
                let timeout = vm_socket_timeout(&arguments[3], "套接字.UDP发送字节至", span)?;
                crate::stdlib::socket_udp_send_bytes_to_guarded(
                    &mut socket.borrow_mut(),
                    &bytes,
                    address,
                    timeout,
                    &self.permissions,
                )
                .map(|written| VmValue::Number(written as f64))
                .map_err(|source| socket_error(span, source))
            }
            Std::SocketUdpReceiveBytesFrom => {
                let socket = vm_socket(&arguments[0], "套接字.UDP接收字节自", span)?;
                let max_bytes = vm_socket_max_bytes(
                    &arguments[1],
                    "套接字.UDP接收字节自",
                    self.resources.host_limits().max_socket_read_bytes(),
                    span,
                )?;
                let timeout = vm_socket_timeout(&arguments[2], "套接字.UDP接收字节自", span)?;
                let (bytes, peer) = crate::stdlib::socket_udp_receive_bytes_from(
                    &mut socket.borrow_mut(),
                    max_bytes,
                    timeout,
                )
                .map_err(|source| socket_error(span, source))?;
                Ok(vm_string_key_map(vec![
                    ("数据", VmValue::Bytes(Rc::new(bytes))),
                    ("对端", VmValue::String(peer)),
                ]))
            }
            Std::SocketLocalAddress => {
                let socket = vm_socket(&arguments[0], "套接字.本地地址", span)?;
                crate::stdlib::socket_local_address(&socket.borrow())
                    .map(VmValue::String)
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketPeerAddress => {
                let socket = vm_socket(&arguments[0], "套接字.对端地址", span)?;
                crate::stdlib::socket_peer_address(&socket.borrow())
                    .map(vm_optional_string)
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketClose => {
                let socket = vm_socket(&arguments[0], "套接字.关闭", span)?;
                crate::stdlib::socket_close(&mut socket.borrow_mut())
                    .map(|()| VmValue::Nil)
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketShutdownWrite => {
                let socket = vm_socket(&arguments[0], "套接字.关闭写端", span)?;
                crate::stdlib::socket_shutdown_write(&mut socket.borrow_mut())
                    .map(|()| VmValue::Nil)
                    .map_err(|source| socket_error(span, source))
            }
            Std::SocketSetNodelay => {
                let socket = vm_socket(&arguments[0], "套接字.TCP无延迟", span)?;
                let enabled = vm_bool(&arguments[1], "套接字.TCP无延迟", span)?;
                crate::stdlib::socket_set_nodelay(&mut socket.borrow_mut(), enabled)
                    .map(|()| VmValue::Nil)
                    .map_err(|source| socket_error(span, source))
            }
            Std::Assert => {
                if arguments[0].truthy() {
                    Ok(VmValue::Nil)
                } else {
                    Err(error(span, format!("断言失败：{}", arguments[1])))
                }
            }
            Std::AssertEqual => {
                if values_equal(&arguments[0], &arguments[1]) {
                    Ok(VmValue::Nil)
                } else {
                    Err(error(
                        span,
                        format!("相等断言失败：左为 {}，右为 {}", arguments[0], arguments[1]),
                    ))
                }
            }
            Std::AssertNotNil => {
                if matches!(arguments[0], VmValue::Nil) {
                    Err(error(span, format!("非空断言失败：{}", arguments[1])))
                } else {
                    Ok(VmValue::Nil)
                }
            }
            Std::PathJoin => Ok(VmValue::String(crate::stdlib::path_join(
                vm_string(&arguments[0], "合并", span)?,
                vm_string(&arguments[1], "合并", span)?,
            ))),
            Std::PathParent => Ok(vm_optional_string(crate::stdlib::path_parent(vm_string(
                &arguments[0],
                "父级",
                span,
            )?))),
            Std::PathFileName => Ok(vm_optional_string(crate::stdlib::path_file_name(
                vm_string(&arguments[0], "文件名", span)?,
            ))),
            Std::PathExtension => Ok(vm_optional_string(crate::stdlib::path_extension(
                vm_string(&arguments[0], "扩展名", span)?,
            ))),
            Std::PathIsAbsolute => Ok(VmValue::Bool(crate::stdlib::path_is_absolute(vm_string(
                &arguments[0],
                "是否绝对",
                span,
            )?))),
            Std::PathNormalize => Ok(VmValue::String(crate::stdlib::path_normalize(vm_string(
                &arguments[0],
                "规范化",
                span,
            )?))),
            Std::EnvRead => {
                let name = vm_string(&arguments[0], "环境.读取", span)?;
                self.permissions
                    .check_environment(name)
                    .map_err(|permission| error(span, permission.to_string()))?;
                match std::env::var(name) {
                    Ok(value) => Ok(VmValue::String(value)),
                    Err(std::env::VarError::NotPresent) => Ok(VmValue::Nil),
                    Err(std::env::VarError::NotUnicode(_)) => {
                        Err(error(span, format!("环境变量“{name}”不是 UTF-8 文字")))
                    }
                }
            }
            Std::EnvExists => {
                let name = vm_string(&arguments[0], "环境.存在", span)?;
                self.permissions
                    .check_environment(name)
                    .map_err(|permission| error(span, permission.to_string()))?;
                Ok(VmValue::Bool(std::env::var_os(name).is_some()))
            }
            Std::CurrentDir => std::env::current_dir()
                .map(|path| VmValue::String(path.to_string_lossy().into_owned()))
                .map_err(|runtime_error| error(span, format!("不能取得当前目录：{runtime_error}"))),
            Std::Os => Ok(VmValue::String(std::env::consts::OS.into())),
            Std::Arch => Ok(VmValue::String(std::env::consts::ARCH.into())),
            Std::Arguments => Ok(VmValue::List(Rc::new(RefCell::new(
                self.arguments
                    .iter()
                    .cloned()
                    .map(VmValue::String)
                    .collect(),
            )))),
            Std::ProcessRun => {
                self.permissions
                    .check_process()
                    .map_err(|permission| error(span, permission.to_string()))?;
                let program = vm_string(&arguments[0], "进程.执行", span)?;
                let process_arguments = vm_string_sequence(&arguments[1], "进程.执行", span)?;
                let directory = match &arguments[2] {
                    VmValue::Nil => None,
                    VmValue::String(directory) => Some(directory.as_str()),
                    value => {
                        return Err(error(
                            span,
                            format!("“进程.执行”第三参数须为文或空，不可为{}", value.type_name()),
                        ));
                    }
                };
                let timeout = vm_nonnegative_safe_u64(&arguments[3], "进程.执行", span)?;
                let output =
                    crate::stdlib::process_run(program, &process_arguments, directory, timeout)
                        .map_err(|message| error(span, message))?;
                Ok(vm_string_key_map(vec![
                    ("状态", VmValue::Number(f64::from(output.status))),
                    ("成功", VmValue::Bool(output.success)),
                    ("标准输出", VmValue::String(output.stdout)),
                    ("标准错误", VmValue::String(output.stderr)),
                ]))
            }
            Std::ResourceReadBytes | Std::ResourceReadText => {
                let requested = vm_string(&arguments[0], "资源.读取", span)?;
                let bytes = if let Some(resources) = &self.application_resources {
                    let key = crate::application::normalize_resource_key(requested)
                        .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                    resources
                        .get(&key)
                        .cloned()
                        .ok_or_else(|| error(span, format!("YXB 中没有资源“{requested}”")))?
                } else {
                    let path = crate::application::resolve_declared_resource(
                        self.package_root.as_deref(),
                        requested,
                    )
                    .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                    crate::stdlib::read_file_bytes(&path)
                        .map_err(|runtime_error| error(span, format!("{runtime_error:?}")))?
                };
                if matches!(function, Std::ResourceReadBytes) {
                    Ok(VmValue::Bytes(Rc::new(bytes)))
                } else {
                    String::from_utf8(bytes)
                        .map(VmValue::String)
                        .map_err(|_| error(span, "资源不是 UTF-8 文字"))
                }
            }
            Std::ResourceList => {
                let requested = vm_string(&arguments[0], "资源.目录", span)?;
                let mut names: Vec<String> = if let Some(resources) = &self.application_resources {
                    let key = crate::application::normalize_resource_key(requested)
                        .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                    let prefix = format!("{}/", key.trim_end_matches('/'));
                    resources
                        .keys()
                        .filter_map(|path| {
                            path.strip_prefix(&prefix)
                                .and_then(|rest| rest.split('/').next())
                                .map(str::to_owned)
                        })
                        .collect()
                } else {
                    let path = crate::application::resolve_declared_resource(
                        self.package_root.as_deref(),
                        requested,
                    )
                    .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                    fs::read_dir(path)
                        .map_err(|runtime_error| error(span, runtime_error.to_string()))?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|runtime_error| error(span, runtime_error.to_string()))?
                        .into_iter()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect()
                };
                names.sort();
                names.dedup();
                Ok(VmValue::List(Rc::new(RefCell::new(
                    names.into_iter().map(VmValue::String).collect(),
                ))))
            }
            Std::NativeLoad => {
                let package = vm_string(&arguments[0], "原生.加载", span)?;
                self.load_native_v2(package, directory, span)
                    .map(VmValue::NativeModuleV2)
            }
            Std::NativeCall => {
                let VmValue::NativeModuleV2(extension) = &arguments[0] else {
                    return Err(error(span, "“原生.调用”第一参数须为 ABI v2 原生模块"));
                };
                let function = vm_string(&arguments[1], "原生.调用", span)?;
                let call_arguments = match &arguments[2] {
                    VmValue::List(values) => values.borrow().clone(),
                    VmValue::Tuple(values) => values.as_ref().clone(),
                    value => {
                        return Err(error(
                            span,
                            format!("“原生.调用”第三参数须为列或元，不可为{}", value.type_name()),
                        ));
                    }
                };
                self.call_native_v2(
                    extension.clone(),
                    function,
                    &call_arguments,
                    span,
                    directory,
                )
            }
            Std::NativeCloseResource => {
                let VmValue::NativeResource(handle) = arguments[0] else {
                    return Err(error(span, "“原生.关闭资源”须收原生资源"));
                };
                self.host_state
                    .resources
                    .borrow_mut()
                    .close(handle)
                    .map_err(|runtime_error| host_event_error(span, runtime_error))?;
                Ok(VmValue::Nil)
            }
            Std::NativeResourceType => {
                let VmValue::NativeResource(handle) = arguments[0] else {
                    return Err(error(span, "“原生.资源类型”须收原生资源"));
                };
                let type_name = self
                    .host_state
                    .resources
                    .borrow()
                    .info(handle)
                    .map_err(|runtime_error| host_event_error(span, runtime_error))?
                    .type_name;
                Ok(VmValue::String(type_name))
            }
            Std::NativeLeakStatistics => {
                let statistics = self.host_state.resources.borrow().leak_statistics();
                Ok(VmValue::Map(Rc::new(RefCell::new(VmMap {
                    entries: statistics
                        .into_iter()
                        .map(|(name, count)| (VmValue::String(name), VmValue::Number(count as f64)))
                        .collect(),
                }))))
            }
            Std::Sha256 => Ok(VmValue::String(crate::stdlib::sha256(vm_string(
                &arguments[0],
                "SHA256",
                span,
            )?))),
            Std::HmacSha256 => {
                let key = vm_bytes(&arguments[0], "哈希.HMACSHA256", span)?;
                let body = vm_bytes(&arguments[1], "哈希.HMACSHA256", span)?;
                crate::stdlib::hmac_sha256(&key, &body)
                    .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                    .map_err(|message| bytes_error(span, "BYTES_CRYPTO", message))
            }
            Std::ConstantTimeEqual => {
                let left = vm_bytes(&arguments[0], "哈希.恒时相等", span)?;
                let right = vm_bytes(&arguments[1], "哈希.恒时相等", span)?;
                Ok(VmValue::Bool(crate::stdlib::constant_time_equal(
                    &left, &right,
                )))
            }
            Std::HexEncode => Ok(VmValue::String(crate::stdlib::hex_encode(vm_string(
                &arguments[0],
                "十六进制",
                span,
            )?))),
            Std::HexDecode => {
                crate::stdlib::hex_decode(vm_string(&arguments[0], "解十六进制", span)?)
                    .map(VmValue::String)
                    .map_err(|message| error(span, message))
            }
            Std::PercentEncode => Ok(VmValue::String(crate::stdlib::percent_encode(vm_string(
                &arguments[0],
                "百分号",
                span,
            )?))),
            Std::PercentDecode => {
                crate::stdlib::percent_decode(vm_string(&arguments[0], "解百分号", span)?)
                    .map(VmValue::String)
                    .map_err(|message| error(span, message))
            }
            Std::StatsSum => vm_statistic(arguments, "总和", crate::stdlib::stats_sum, span),
            Std::StatsMean => vm_statistic(arguments, "平均", crate::stdlib::stats_mean, span),
            Std::StatsMedian => {
                vm_statistic(arguments, "中位数", crate::stdlib::stats_median, span)
            }
            Std::StatsVariance => {
                vm_statistic(arguments, "方差", crate::stdlib::stats_variance, span)
            }
            Std::StatsStddev => {
                vm_statistic(arguments, "标准差", crate::stdlib::stats_stddev, span)
            }
            Std::CsvParse => {
                let rows = crate::stdlib::csv_parse(vm_string(&arguments[0], "CSV.解析", span)?)
                    .map_err(|message| error(span, message))?;
                Ok(VmValue::List(Rc::new(RefCell::new(
                    rows.into_iter()
                        .map(|row| {
                            VmValue::List(Rc::new(RefCell::new(
                                row.into_iter().map(VmValue::String).collect(),
                            )))
                        })
                        .collect(),
                ))))
            }
            Std::CsvStringify => Ok(VmValue::String(crate::stdlib::csv_stringify(
                &vm_string_table(&arguments[0], "CSV.序列化", span)?,
            ))),
            Std::RandomUnit => crate::stdlib::seeded_random_unit(number(&arguments[0], span)?)
                .map(VmValue::Number)
                .map_err(|message| error(span, message)),
            Std::RandomInteger => crate::stdlib::seeded_random_integer(
                number(&arguments[0], span)?,
                number(&arguments[1], span)?,
                number(&arguments[2], span)?,
            )
            .map(VmValue::Number)
            .map_err(|message| error(span, message)),
            Std::RandomBool => crate::stdlib::seeded_random_bool(number(&arguments[0], span)?)
                .map(VmValue::Bool)
                .map_err(|message| error(span, message)),
            Std::SecureRandomBytes => {
                let length = vm_nonnegative_usize(
                    &arguments[0],
                    "随机.安全字节",
                    crate::stdlib::SECURE_RANDOM_MAX_BYTES,
                    span,
                )?;
                crate::stdlib::secure_random_bytes(length)
                    .map(|bytes| VmValue::Bytes(Rc::new(bytes)))
                    .map_err(|message| bytes_error(span, "BYTES_RANDOM", message))
            }
            Std::StableUuid => Ok(VmValue::String(crate::stdlib::stable_uuid(vm_string(
                &arguments[0],
                "标识.稳定UUID",
                span,
            )?))),
            Std::IsUuid => Ok(VmValue::Bool(crate::stdlib::is_uuid(vm_string(
                &arguments[0],
                "标识.是否UUID",
                span,
            )?))),
            Std::StableShortId => crate::stdlib::stable_short_id(
                vm_string(&arguments[0], "标识.稳定短码", span)?,
                number(&arguments[1], span)?,
            )
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::TemplateInterpolate => crate::stdlib::template_interpolate(
                vm_string(&arguments[0], "模板.插值", span)?,
                vm_string(&arguments[1], "模板.插值", span)?,
                vm_string(&arguments[2], "模板.插值", span)?,
            )
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::HtmlEscape => Ok(VmValue::String(crate::stdlib::html_escape(vm_string(
                &arguments[0],
                "模板.转义HTML",
                span,
            )?))),
            Std::HtmlUnescape => Ok(VmValue::String(crate::stdlib::html_unescape(vm_string(
                &arguments[0],
                "模板.反转义HTML",
                span,
            )?))),
            Std::IsEmail => Ok(VmValue::Bool(crate::stdlib::is_email(vm_string(
                &arguments[0],
                "校验.电子邮件",
                span,
            )?))),
            Std::IsIpv4 => Ok(VmValue::Bool(crate::stdlib::is_ipv4(vm_string(
                &arguments[0],
                "校验.IPv4",
                span,
            )?))),
            Std::IsHexColor => Ok(VmValue::Bool(crate::stdlib::is_hex_color(vm_string(
                &arguments[0],
                "校验.十六进制色",
                span,
            )?))),
            Std::IsIdentifier => Ok(VmValue::Bool(crate::stdlib::is_identifier(vm_string(
                &arguments[0],
                "校验.标识符",
                span,
            )?))),
            Std::Base64Encode => Ok(VmValue::String(crate::stdlib::base64_encode(vm_string(
                &arguments[0],
                "Base64.编码",
                span,
            )?))),
            Std::Base64Decode => {
                crate::stdlib::base64_decode(vm_string(&arguments[0], "Base64.解码", span)?)
                    .map(VmValue::String)
                    .map_err(|message| error(span, message))
            }
            Std::Base64UrlEncode => Ok(VmValue::String(crate::stdlib::base64_url_encode(
                vm_string(&arguments[0], "Base64.网址编码", span)?,
            ))),
            Std::Base64UrlDecode => crate::stdlib::base64_url_decode(vm_string(
                &arguments[0],
                "Base64.解网址编码",
                span,
            )?)
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::RegexIsMatch => crate::stdlib::regex_is_match(
                vm_string(&arguments[0], "正则.匹配", span)?,
                vm_string(&arguments[1], "正则.匹配", span)?,
            )
            .map(VmValue::Bool)
            .map_err(|message| error(span, message)),
            Std::RegexFirst => crate::stdlib::regex_first(
                vm_string(&arguments[0], "正则.首项", span)?,
                vm_string(&arguments[1], "正则.首项", span)?,
            )
            .map(vm_optional_string)
            .map_err(|message| error(span, message)),
            Std::RegexReplaceAll => crate::stdlib::regex_replace_all(
                vm_string(&arguments[0], "正则.替换全部", span)?,
                vm_string(&arguments[1], "正则.替换全部", span)?,
                vm_string(&arguments[2], "正则.替换全部", span)?,
            )
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::RegexSplit => crate::stdlib::regex_split(
                vm_string(&arguments[0], "正则.分割", span)?,
                vm_string(&arguments[1], "正则.分割", span)?,
            )
            .map(|parts| {
                VmValue::List(Rc::new(RefCell::new(
                    parts.into_iter().map(VmValue::String).collect(),
                )))
            })
            .map_err(|message| error(span, message)),
            Std::UrlIsValid => Ok(VmValue::Bool(crate::stdlib::url_is_valid(vm_string(
                &arguments[0],
                "URL.是否合法",
                span,
            )?))),
            Std::UrlScheme => {
                crate::stdlib::url_scheme(vm_string(&arguments[0], "URL.协议", span)?)
                    .map(VmValue::String)
                    .map_err(|message| error(span, message))
            }
            Std::UrlHost => crate::stdlib::url_host(vm_string(&arguments[0], "URL.主机", span)?)
                .map(vm_optional_string)
                .map_err(|message| error(span, message)),
            Std::UrlPort => crate::stdlib::url_port(vm_string(&arguments[0], "URL.端口", span)?)
                .map(|port| port.map_or(VmValue::Nil, VmValue::Number))
                .map_err(|message| error(span, message)),
            Std::UrlPath => crate::stdlib::url_path(vm_string(&arguments[0], "URL.路径", span)?)
                .map(VmValue::String)
                .map_err(|message| error(span, message)),
            Std::UrlQueryValue => crate::stdlib::url_query_value(
                vm_string(&arguments[0], "URL.查询值", span)?,
                vm_string(&arguments[1], "URL.查询值", span)?,
            )
            .map(vm_optional_string)
            .map_err(|message| error(span, message)),
            Std::UrlJoin => crate::stdlib::url_join(
                vm_string(&arguments[0], "URL.合并", span)?,
                vm_string(&arguments[1], "URL.合并", span)?,
            )
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::DateIsValid => Ok(VmValue::Bool(crate::stdlib::date_is_valid(vm_string(
                &arguments[0],
                "日期.是否合法",
                span,
            )?))),
            Std::DateIsLeapYear => crate::stdlib::date_is_leap_year(number(&arguments[0], span)?)
                .map(VmValue::Bool)
                .map_err(|message| error(span, message)),
            Std::DateAddDays => crate::stdlib::date_add_days(
                vm_string(&arguments[0], "日期.加天", span)?,
                number(&arguments[1], span)?,
            )
            .map(VmValue::String)
            .map_err(|message| error(span, message)),
            Std::DateDaysBetween => crate::stdlib::date_days_between(
                vm_string(&arguments[0], "日期.相差天数", span)?,
                vm_string(&arguments[1], "日期.相差天数", span)?,
            )
            .map(VmValue::Number)
            .map_err(|message| error(span, message)),
            Std::HttpDate => {
                let millis = vm_nonnegative_safe_u64(&arguments[0], "日期.HTTP日期", span)?;
                crate::stdlib::format_http_date(millis)
                    .map(VmValue::String)
                    .map_err(|message| error(span, message))
            }
            Std::ParseHttpDate => Ok(crate::stdlib::parse_http_date(vm_string(
                &arguments[0],
                "日期.解析HTTP日期",
                span,
            )?)
            .map_or(VmValue::Nil, |millis| VmValue::Number(millis as f64))),
        }
    }

    fn load_native_v2(
        &mut self,
        package_name: &str,
        directory: &Path,
        span: &Span,
    ) -> Result<Rc<native_abi_v2::NativeExtensionV2>, VmError> {
        if let Some(extension) = self.native_extensions_v2.get(package_name) {
            return Ok(extension.clone());
        }
        if let Some(native_modules) = &self.application_native_modules {
            let module = native_modules.get(package_name).ok_or_else(|| {
                error(span, format!("YXB 没有名为“{package_name}”的锁定原生模块"))
            })?;
            if module.metadata.abi != native_abi_v2::NATIVE_ABI_VERSION_V2 {
                return Err(error(
                    span,
                    format!(
                        "YXB 原生模块“{package_name}”使用 ABI {}，标准:原生只支持 ABI v2",
                        module.metadata.abi
                    ),
                ));
            }
            let artifact = crate::package::NativeArtifact {
                abi: module.metadata.abi,
                target: module.metadata.target.clone(),
                path: module.metadata.file.clone(),
                checksum: module.metadata.checksum.clone(),
                size: module.metadata.size,
            };
            let extension = native_abi_v2::NativeExtensionV2::load_verified_bytes(
                &module.bytes,
                &artifact,
                &self.permissions,
                package_name,
                native_abi_v2::NativeLoadAuthority::NativeExtension,
            )
            .map_err(|runtime_error| native_v2_error(span, runtime_error))?;
            let extension = Rc::new(extension);
            self.native_extensions_v2
                .insert(package_name.to_owned(), extension.clone());
            return Ok(extension);
        }
        let root = self.package_root.as_deref().unwrap_or(directory);
        let manifest = crate::package::discover(root)
            .map_err(|runtime_error| error(span, runtime_error.to_string()))?
            .ok_or_else(|| error(span, "当前程序不属于包，不能装载锁定原生扩展"))?;
        let offline = std::env::var_os("YANXU_OFFLINE").is_some();
        let graph = crate::package::resolve_graph(&manifest, offline)
            .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
        let mut matches = graph
            .packages
            .values()
            .filter(|dependency| {
                dependency.locked.name == package_name && dependency.locked.native.is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(error(
                span,
                if matches.is_empty() {
                    format!("锁定依赖图没有名为“{package_name}”的原生制品")
                } else {
                    format!("锁定依赖图含多个名为“{package_name}”的原生制品，不能消歧")
                },
            ));
        }
        let dependency = matches.pop().expect("one native dependency");
        let artifact = dependency.locked.native.as_ref().expect("filtered native");
        let extension = native_abi_v2::NativeExtensionV2::load_verified(
            dependency.root.join(&artifact.path),
            artifact,
            &self.permissions,
            package_name,
            native_abi_v2::NativeLoadAuthority::NativeExtension,
        )
        .map_err(|runtime_error| native_v2_error(span, runtime_error))?;
        let extension = Rc::new(extension);
        self.native_extensions_v2
            .insert(package_name.to_owned(), extension.clone());
        Ok(extension)
    }

    fn call_native_v2(
        &mut self,
        extension: Rc<native_abi_v2::NativeExtensionV2>,
        function: &str,
        arguments: &[VmValue],
        span: &Span,
        directory: &Path,
    ) -> Result<VmValue, VmError> {
        let mut temporary_callbacks = Vec::new();
        let host_arguments = arguments
            .iter()
            .map(|argument| self.vm_to_host_value(argument, span, &mut temporary_callbacks))
            .collect::<Result<Vec<_>, _>>()?;
        let run_guard = if matches!(function, "run" | "运行" | "应用运行") {
            Some(
                self.host_state
                    .shared
                    .event_loop
                    .begin_run()
                    .map_err(|runtime_error| host_event_error(span, runtime_error))?,
            )
        } else {
            None
        };
        let vm_pointer: *mut Vm = self;
        let previous_vm = self.host_state.vm.replace(vm_pointer);
        let previous_directory = std::mem::replace(
            &mut *self.host_state.current_directory.borrow_mut(),
            directory.to_path_buf(),
        );
        let previous_extension = self
            .host_state
            .active_extension
            .borrow_mut()
            .replace(extension.name().to_owned());
        let previous_pump_error = self.host_state.last_pump_error.borrow_mut().take();
        let native_result = extension.call(function, &host_arguments, Some(&self.host_state.host));
        let call_pump_error = self.host_state.last_pump_error.borrow_mut().take();
        self.host_state.vm.set(previous_vm);
        *self.host_state.current_directory.borrow_mut() = previous_directory;
        *self.host_state.active_extension.borrow_mut() = previous_extension;
        *self.host_state.last_pump_error.borrow_mut() = previous_pump_error;
        drop(run_guard);
        let callback_release_error = {
            let mut callbacks = self.host_state.callbacks.borrow_mut();
            temporary_callbacks
                .into_iter()
                .find_map(|callback| callbacks.release(callback).err())
        };
        if let Some(runtime_error) = call_pump_error {
            return Err(runtime_error);
        }
        if let Some(runtime_error) = callback_release_error {
            return Err(host_event_error(span, runtime_error));
        }
        match native_result.map_err(|runtime_error| native_v2_error(span, runtime_error))? {
            native_abi_v2::NativeV2CallResult::Value(value) => Self::host_to_vm_value(value, span),
            native_abi_v2::NativeV2CallResult::Resource(resource) => {
                let type_name = resource.type_name().to_owned();
                let parent = resource.parent();
                let raw_pointer = resource.as_raw() as usize;
                let extension_name = extension.name().to_owned();
                let handle = self
                    .host_state
                    .resources
                    .borrow_mut()
                    .create_native(type_name, extension_name, parent, raw_pointer, move || {
                        drop(resource)
                    })
                    .map_err(|runtime_error| host_event_error(span, runtime_error))?;
                Ok(VmValue::NativeResource(handle))
            }
        }
    }

    fn vm_to_host_value(
        &self,
        value: &VmValue,
        span: &Span,
        temporary_callbacks: &mut Vec<u64>,
    ) -> Result<host_events::HostValue, VmError> {
        Ok(match value {
            VmValue::Nil => host_events::HostValue::Nil,
            VmValue::Bool(value) => host_events::HostValue::Bool(*value),
            VmValue::Number(value) if !value.is_finite() => {
                return Err(error(span, "非有限数不可传给 ABI v2"));
            }
            VmValue::Number(value)
                if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 =>
            {
                host_events::HostValue::Integer(*value as i64)
            }
            VmValue::Number(value) => host_events::HostValue::Number(*value),
            VmValue::String(value) => host_events::HostValue::String(value.clone()),
            VmValue::Bytes(value) => host_events::HostValue::Bytes(value.as_ref().clone()),
            VmValue::List(values) => host_events::HostValue::Array(
                values
                    .borrow()
                    .iter()
                    .map(|value| self.vm_to_host_value(value, span, temporary_callbacks))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            VmValue::Tuple(values) => host_events::HostValue::Array(
                values
                    .iter()
                    .map(|value| self.vm_to_host_value(value, span, temporary_callbacks))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            VmValue::Map(map) => host_events::HostValue::Map(
                map.borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            self.vm_to_host_value(key, span, temporary_callbacks)?,
                            self.vm_to_host_value(value, span, temporary_callbacks)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, VmError>>()?,
            ),
            VmValue::Closure(_) | VmValue::BoundMethod(_, _) | VmValue::Native(_) => {
                let callback = self
                    .host_state
                    .callbacks
                    .borrow_mut()
                    .create(value.clone())
                    .map_err(|runtime_error| host_event_error(span, runtime_error))?;
                temporary_callbacks.push(callback);
                host_events::HostValue::Callback(callback)
            }
            VmValue::NativeResource(handle) => host_events::HostValue::Resource(*handle),
            value => {
                return Err(error(span, format!("{}不可传给 ABI v2", value.type_name())));
            }
        })
    }

    fn host_to_vm_value(value: host_events::HostValue, span: &Span) -> Result<VmValue, VmError> {
        Ok(match value {
            host_events::HostValue::Nil => VmValue::Nil,
            host_events::HostValue::Bool(value) => VmValue::Bool(value),
            host_events::HostValue::Integer(value) => VmValue::Number(value as f64),
            host_events::HostValue::Number(value) => VmValue::Number(value),
            host_events::HostValue::String(value) => VmValue::String(value),
            host_events::HostValue::Bytes(value) => VmValue::Bytes(Rc::new(value)),
            host_events::HostValue::Array(values) => VmValue::List(Rc::new(RefCell::new(
                values
                    .into_iter()
                    .map(|value| Self::host_to_vm_value(value, span))
                    .collect::<Result<Vec<_>, _>>()?,
            ))),
            host_events::HostValue::Map(entries) => VmValue::Map(Rc::new(RefCell::new(VmMap {
                entries: entries
                    .into_iter()
                    .map(|(key, value)| {
                        Ok((
                            Self::host_to_vm_value(key, span)?,
                            Self::host_to_vm_value(value, span)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, VmError>>()?,
            }))),
            host_events::HostValue::Resource(handle) => VmValue::NativeResource(handle),
            host_events::HostValue::Callback(_) => {
                return Err(error(span, "原生扩展不可向言序返回外部回调句柄"));
            }
            host_events::HostValue::Error {
                code,
                message,
                details,
            } => VmValue::Error(Rc::new(VmErrorValue {
                code: "NATIVE_ERROR",
                category: "原生".into(),
                message: if let Some(details) = details {
                    format!("[{code}] {message}（详情：{details:?}）")
                } else {
                    format!("[{code}] {message}")
                },
                frames: Vec::new(),
                span: span.clone(),
            })),
        })
    }

    fn pump_host_events(&mut self, maximum_events: usize) -> Result<usize, VmError> {
        let mut processed = 0;
        while processed < maximum_events {
            let event = match self.host_state.shared.event_loop.try_next() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(runtime_error) => {
                    return Err(host_event_error(&Span::synthetic(), runtime_error));
                }
            };
            processed += 1;
            match event {
                host_events::HostEvent::Callback {
                    callback,
                    arguments,
                } => {
                    let callable = self.host_state.callbacks.borrow().get(callback).map_err(
                        |runtime_error| host_event_error(&Span::synthetic(), runtime_error),
                    )?;
                    let arguments = arguments
                        .into_iter()
                        .map(|argument| Self::host_to_vm_value(argument, &Span::synthetic()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let directory = self.host_state.current_directory.borrow().clone();
                    // 常驻程序（GUI、服务）的每个宿主回调独立计量步数预算，
                    // 防死循环检查仍对单次回调生效，但预算不再跨事件累计。
                    let saved_steps = self.resources.open_step_window();
                    let result =
                        self.call_value(callable, arguments, &Span::synthetic(), &directory);
                    self.resources.close_step_window(saved_steps);
                    result?;
                }
                host_events::HostEvent::Timer { timer, callback } => {
                    if let Some(callback) = callback {
                        let callable = self.host_state.callbacks.borrow().get(callback).map_err(
                            |runtime_error| host_event_error(&Span::synthetic(), runtime_error),
                        )?;
                        let directory = self.host_state.current_directory.borrow().clone();
                        let saved_steps = self.resources.open_step_window();
                        let result = self.call_value(
                            callable,
                            vec![VmValue::Number(timer as f64)],
                            &Span::synthetic(),
                            &directory,
                        );
                        self.resources.close_step_window(saved_steps);
                        result?;
                    }
                }
                host_events::HostEvent::Quit => {
                    host_events::HostEventLoop::quit(&self.host_state.shared.event_loop);
                    break;
                }
                host_events::HostEvent::MouseMove { .. }
                | host_events::HostEvent::WindowResize { .. }
                | host_events::HostEvent::Custom { .. }
                | host_events::HostEvent::Wake => {}
            }
        }
        Ok(processed)
    }

    fn load_module(
        &mut self,
        requested: &str,
        directory: &Path,
        span: &Span,
    ) -> Result<Rc<VmModule>, VmError> {
        crate::package::validate_portable_path_text(requested)
            .map_err(|runtime_error| package_path_error(span, runtime_error))?;
        if let Some(name) = requested.strip_prefix("标准:") {
            return self.standard_module(name, span);
        }
        if let Some(id) = requested.strip_prefix("归档:") {
            return self.load_application_module(id, directory, span);
        }
        let (joined, package_import) = if let Some(name) = requested.strip_prefix("包:") {
            let (dependency, capabilities) =
                crate::package::resolve_dependency_scoped_with_capabilities(
                    self.package_root.as_deref(),
                    directory,
                    name,
                )
                .map_err(|runtime_error| package_error(span, runtime_error))?;
            capabilities
                .extend(&mut self.package_module_roots)
                .map_err(|runtime_error| package_path_error(span, runtime_error))?;
            (dependency.entry, true)
        } else {
            let path = Path::new(requested);
            if path.is_absolute() {
                (path.into(), false)
            } else {
                (directory.join(path), false)
            }
        };
        if !package_import && self.package_module_roots.matching_root(&joined).is_none() {
            self.permissions
                .check_file(&joined)
                .map_err(|permission| error(span, permission.to_string()))?;
        }
        let (resolved, authority) = self
            .package_module_roots
            .resolve_import_file(directory, &joined, package_import)
            .map_err(|runtime_error| package_error(span, runtime_error))?;
        let canonical = resolved.path().to_path_buf();
        if let Err(permission) = self.permissions.check_file(&canonical)
            && !authority.is_verified()
        {
            return Err(error(span, permission.to_string()));
        }
        if let Some(module) = self.module_cache.get(&canonical) {
            self.cache_stats.module_hits += 1;
            return Ok(module.clone());
        }
        if let Some(start) = self
            .loading_modules
            .iter()
            .position(|path| path == &canonical)
        {
            let mut chain = self.loading_modules[start..]
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            chain.push(canonical.display().to_string());
            return Err(error(span, format!("模块循环相引：{}", chain.join(" → "))));
        }

        let resolved = resolved
            .open()
            .map_err(|runtime_error| package_error(span, runtime_error))?;
        self.loading_modules.push(canonical.clone());
        self.cache_stats.module_misses += 1;
        let result = (|| {
            let metadata = resolved
                .metadata()
                .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
            let modified = metadata.modified().ok();
            let length = metadata.len();
            let cached = self
                .bytecode_cache
                .get(&canonical)
                .filter(|cache| cache.length == length && cache.modified == modified)
                .map(|cache| cache.chunk.clone());
            let chunk = if let Some(chunk) = cached {
                self.cache_stats.module_hits += 1;
                chunk
            } else {
                let source = crate::package::read_resolved_module_source_snapshot(resolved)
                    .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                let statements = crate::parse_named(&source, canonical.display().to_string())
                    .map_err(|runtime_error| error(span, runtime_error.to_string()))?;
                let chunk = Rc::new(
                    crate::bytecode::compile(&statements)
                        .map_err(|runtime_error| error(span, runtime_error.to_string()))?,
                );
                self.bytecode_cache.insert(
                    canonical.clone(),
                    CachedChunk {
                        length,
                        modified,
                        chunk: chunk.clone(),
                    },
                );
                chunk
            };
            let environment = self.child_env(self.globals.clone());
            let module_directory = canonical.parent().unwrap_or_else(|| Path::new("."));
            self.run_chunk(
                chunk.clone(),
                environment.clone(),
                format!("模块“{}”", canonical.display()),
                span.clone(),
                module_directory.into(),
                None,
            )?;
            Ok((chunk, environment))
        })();
        self.loading_modules.pop();
        let (chunk, environment) = result?;
        let module = Rc::new(VmModule {
            name: canonical
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("无名")
                .into(),
            module_id: chunk.module_id.clone(),
            environment,
            exports: chunk.exports.iter().cloned().collect(),
        });
        self.module_cache.insert(canonical, module.clone());
        Ok(module)
    }

    fn load_application_module(
        &mut self,
        id: &str,
        directory: &Path,
        span: &Span,
    ) -> Result<Rc<VmModule>, VmError> {
        if let Some(module) = self.application_module_cache.get(id) {
            self.cache_stats.module_hits += 1;
            return Ok(module.clone());
        }
        if let Some(start) = self
            .loading_application_modules
            .iter()
            .position(|loading| loading == id)
        {
            let mut chain = self.loading_application_modules[start..].to_vec();
            chain.push(id.to_owned());
            return Err(error(
                span,
                format!("归档模块循环相引：{}", chain.join(" → ")),
            ));
        }
        let application_module = self
            .application_modules
            .get(id)
            .cloned()
            .ok_or_else(|| error(span, format!("YXB 未包含归档模块“{id}”")))?;
        self.loading_application_modules.push(id.to_owned());
        self.cache_stats.module_misses += 1;
        let environment = self.child_env(self.globals.clone());
        let execution = self.run_chunk(
            Rc::new(application_module.chunk.clone()),
            environment.clone(),
            format!("归档模块“{}”", application_module.display_path),
            span.clone(),
            directory.to_path_buf(),
            None,
        );
        self.loading_application_modules.pop();
        execution?;
        let name = application_module
            .display_path
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_suffix(".yx"))
            .unwrap_or("无名")
            .to_owned();
        let module = Rc::new(VmModule {
            name,
            module_id: application_module.chunk.module_id.clone(),
            environment,
            exports: application_module.chunk.exports.iter().cloned().collect(),
        });
        self.application_module_cache
            .insert(id.to_owned(), module.clone());
        Ok(module)
    }

    fn standard_module(&mut self, name: &str, span: &Span) -> Result<Rc<VmModule>, VmError> {
        let environment = self.child_env(self.globals.clone());
        let definitions: &[(&str, usize, NativeKind)] = match name {
            "数学" => &[
                ("绝对值", 1, NativeKind::Abs),
                ("平方根", 1, NativeKind::Sqrt),
                ("幂", 2, NativeKind::Pow),
                ("下取整", 1, NativeKind::Standard(StandardNative::Floor)),
                ("上取整", 1, NativeKind::Standard(StandardNative::Ceil)),
                ("四舍五入", 1, NativeKind::Standard(StandardNative::Round)),
                ("正弦", 1, NativeKind::Standard(StandardNative::Sin)),
                ("余弦", 1, NativeKind::Standard(StandardNative::Cos)),
                ("最小", 2, NativeKind::Standard(StandardNative::Min)),
                ("最大", 2, NativeKind::Standard(StandardNative::Max)),
            ],
            "文字" => &[
                ("修剪", 1, NativeKind::Standard(StandardNative::Trim)),
                ("分割", 2, NativeKind::Standard(StandardNative::Split)),
                ("替换", 3, NativeKind::Standard(StandardNative::Replace)),
                ("始于", 2, NativeKind::Standard(StandardNative::StartsWith)),
                ("终于", 2, NativeKind::Standard(StandardNative::EndsWith)),
                ("大写", 1, NativeKind::Standard(StandardNative::Uppercase)),
                ("小写", 1, NativeKind::Standard(StandardNative::Lowercase)),
                (
                    "字符列",
                    1,
                    NativeKind::Standard(StandardNative::Characters),
                ),
                ("联结", 2, NativeKind::Standard(StandardNative::Join)),
            ],
            "字节" => &[
                (
                    "从文字",
                    1,
                    NativeKind::Standard(StandardNative::BytesFromText),
                ),
                (
                    "转文字",
                    1,
                    NativeKind::Standard(StandardNative::BytesToText),
                ),
                ("长度", 1, NativeKind::Standard(StandardNative::BytesLength)),
                ("切片", 3, NativeKind::Standard(StandardNative::BytesSlice)),
                ("拼接", 2, NativeKind::Standard(StandardNative::BytesConcat)),
                ("查找", 2, NativeKind::Standard(StandardNative::BytesFind)),
                (
                    "从数列",
                    1,
                    NativeKind::Standard(StandardNative::BytesFromNumbers),
                ),
                (
                    "转数列",
                    1,
                    NativeKind::Standard(StandardNative::BytesToNumbers),
                ),
            ],
            "时间" => &[
                ("今", 0, NativeKind::Clock),
                ("毫秒", 0, NativeKind::Standard(StandardNative::Millis)),
                ("等待", 1, NativeKind::Standard(StandardNative::Sleep)),
            ],
            "文件" => &[
                ("读取", 1, NativeKind::Standard(StandardNative::ReadFile)),
                (
                    "读取字节",
                    1,
                    NativeKind::Standard(StandardNative::ReadBytes),
                ),
                ("写入", 2, NativeKind::Standard(StandardNative::WriteFile)),
                (
                    "写入字节",
                    2,
                    NativeKind::Standard(StandardNative::WriteBytes),
                ),
                ("追加", 2, NativeKind::Standard(StandardNative::AppendFile)),
                (
                    "追加字节",
                    2,
                    NativeKind::Standard(StandardNative::AppendBytes),
                ),
                ("状态", 1, NativeKind::Standard(StandardNative::FileStatus)),
                ("存在", 1, NativeKind::Standard(StandardNative::PathExists)),
                (
                    "目录",
                    1,
                    NativeKind::Standard(StandardNative::ReadDirectory),
                ),
                (
                    "创建目录",
                    1,
                    NativeKind::Standard(StandardNative::CreateDirectory),
                ),
                ("删除", 2, NativeKind::Standard(StandardNative::RemovePath)),
            ],
            "JSON" | "json" => &[
                ("解析", 1, NativeKind::Standard(StandardNative::JsonParse)),
                (
                    "序列化",
                    1,
                    NativeKind::Standard(StandardNative::JsonStringify),
                ),
            ],
            "网络" => &[
                ("获取", 1, NativeKind::Standard(StandardNative::HttpGet)),
                ("发文", 2, NativeKind::Standard(StandardNative::HttpPost)),
                ("请求", 5, NativeKind::Standard(StandardNative::HttpRequest)),
                (
                    "请求字节",
                    6,
                    NativeKind::Standard(StandardNative::HttpBytesRequest),
                ),
            ],
            "套接字" => &[
                (
                    "TCP连接",
                    2,
                    NativeKind::Standard(StandardNative::SocketTcpConnect),
                ),
                (
                    "TCP监听",
                    1,
                    NativeKind::Standard(StandardNative::SocketTcpListen),
                ),
                (
                    "接受",
                    2,
                    NativeKind::Standard(StandardNative::SocketAccept),
                ),
                ("发送", 3, NativeKind::Standard(StandardNative::SocketSend)),
                (
                    "发送字节",
                    3,
                    NativeKind::Standard(StandardNative::SocketSendBytes),
                ),
                (
                    "接收",
                    3,
                    NativeKind::Standard(StandardNative::SocketReceive),
                ),
                (
                    "接收字节",
                    3,
                    NativeKind::Standard(StandardNative::SocketReceiveBytes),
                ),
                (
                    "精确读取",
                    3,
                    NativeKind::Standard(StandardNative::SocketReadExact),
                ),
                (
                    "UDP绑定",
                    1,
                    NativeKind::Standard(StandardNative::SocketUdpBind),
                ),
                (
                    "UDP发送至",
                    4,
                    NativeKind::Standard(StandardNative::SocketUdpSendTo),
                ),
                (
                    "UDP接收自",
                    3,
                    NativeKind::Standard(StandardNative::SocketUdpReceiveFrom),
                ),
                (
                    "UDP发送字节至",
                    4,
                    NativeKind::Standard(StandardNative::SocketUdpSendBytesTo),
                ),
                (
                    "UDP接收字节自",
                    3,
                    NativeKind::Standard(StandardNative::SocketUdpReceiveBytesFrom),
                ),
                (
                    "本地地址",
                    1,
                    NativeKind::Standard(StandardNative::SocketLocalAddress),
                ),
                (
                    "对端地址",
                    1,
                    NativeKind::Standard(StandardNative::SocketPeerAddress),
                ),
                ("关闭", 1, NativeKind::Standard(StandardNative::SocketClose)),
                (
                    "关闭写端",
                    1,
                    NativeKind::Standard(StandardNative::SocketShutdownWrite),
                ),
                (
                    "TCP无延迟",
                    2,
                    NativeKind::Standard(StandardNative::SocketSetNodelay),
                ),
            ],
            "测试" => &[
                ("断言", 2, NativeKind::Standard(StandardNative::Assert)),
                ("相等", 2, NativeKind::Standard(StandardNative::AssertEqual)),
                (
                    "非空",
                    2,
                    NativeKind::Standard(StandardNative::AssertNotNil),
                ),
            ],
            "路径" => &[
                ("合并", 2, NativeKind::Standard(StandardNative::PathJoin)),
                ("父级", 1, NativeKind::Standard(StandardNative::PathParent)),
                (
                    "文件名",
                    1,
                    NativeKind::Standard(StandardNative::PathFileName),
                ),
                (
                    "扩展名",
                    1,
                    NativeKind::Standard(StandardNative::PathExtension),
                ),
                (
                    "是否绝对",
                    1,
                    NativeKind::Standard(StandardNative::PathIsAbsolute),
                ),
                (
                    "规范化",
                    1,
                    NativeKind::Standard(StandardNative::PathNormalize),
                ),
            ],
            "环境" => &[
                ("读取", 1, NativeKind::Standard(StandardNative::EnvRead)),
                ("存在", 1, NativeKind::Standard(StandardNative::EnvExists)),
                (
                    "当前目录",
                    0,
                    NativeKind::Standard(StandardNative::CurrentDir),
                ),
                ("系统", 0, NativeKind::Standard(StandardNative::Os)),
                ("架构", 0, NativeKind::Standard(StandardNative::Arch)),
                ("参数", 0, NativeKind::Standard(StandardNative::Arguments)),
            ],
            "进程" => &[("执行", 4, NativeKind::Standard(StandardNative::ProcessRun))],
            "资源" => &[
                (
                    "读取字节",
                    1,
                    NativeKind::Standard(StandardNative::ResourceReadBytes),
                ),
                (
                    "读取文字",
                    1,
                    NativeKind::Standard(StandardNative::ResourceReadText),
                ),
                (
                    "目录",
                    1,
                    NativeKind::Standard(StandardNative::ResourceList),
                ),
            ],
            "原生" => &[
                ("加载", 1, NativeKind::Standard(StandardNative::NativeLoad)),
                ("调用", 3, NativeKind::Standard(StandardNative::NativeCall)),
                (
                    "关闭资源",
                    1,
                    NativeKind::Standard(StandardNative::NativeCloseResource),
                ),
                (
                    "资源类型",
                    1,
                    NativeKind::Standard(StandardNative::NativeResourceType),
                ),
                (
                    "泄漏统计",
                    0,
                    NativeKind::Standard(StandardNative::NativeLeakStatistics),
                ),
            ],
            "哈希" => &[
                ("SHA256", 1, NativeKind::Standard(StandardNative::Sha256)),
                (
                    "HMACSHA256",
                    2,
                    NativeKind::Standard(StandardNative::HmacSha256),
                ),
                (
                    "恒时相等",
                    2,
                    NativeKind::Standard(StandardNative::ConstantTimeEqual),
                ),
            ],
            "编码" => &[
                (
                    "十六进制",
                    1,
                    NativeKind::Standard(StandardNative::HexEncode),
                ),
                (
                    "解十六进制",
                    1,
                    NativeKind::Standard(StandardNative::HexDecode),
                ),
                (
                    "百分号",
                    1,
                    NativeKind::Standard(StandardNative::PercentEncode),
                ),
                (
                    "解百分号",
                    1,
                    NativeKind::Standard(StandardNative::PercentDecode),
                ),
            ],
            "统计" => &[
                ("总和", 1, NativeKind::Standard(StandardNative::StatsSum)),
                ("平均", 1, NativeKind::Standard(StandardNative::StatsMean)),
                (
                    "中位数",
                    1,
                    NativeKind::Standard(StandardNative::StatsMedian),
                ),
                (
                    "方差",
                    1,
                    NativeKind::Standard(StandardNative::StatsVariance),
                ),
                (
                    "标准差",
                    1,
                    NativeKind::Standard(StandardNative::StatsStddev),
                ),
            ],
            "CSV" | "csv" => &[
                ("解析", 1, NativeKind::Standard(StandardNative::CsvParse)),
                (
                    "序列化",
                    1,
                    NativeKind::Standard(StandardNative::CsvStringify),
                ),
            ],
            "随机" => &[
                ("小数", 1, NativeKind::Standard(StandardNative::RandomUnit)),
                (
                    "整数",
                    3,
                    NativeKind::Standard(StandardNative::RandomInteger),
                ),
                ("布尔", 1, NativeKind::Standard(StandardNative::RandomBool)),
                (
                    "安全字节",
                    1,
                    NativeKind::Standard(StandardNative::SecureRandomBytes),
                ),
            ],
            "标识" => &[
                (
                    "稳定UUID",
                    1,
                    NativeKind::Standard(StandardNative::StableUuid),
                ),
                ("是否UUID", 1, NativeKind::Standard(StandardNative::IsUuid)),
                (
                    "稳定短码",
                    2,
                    NativeKind::Standard(StandardNative::StableShortId),
                ),
            ],
            "模板" => &[
                (
                    "插值",
                    3,
                    NativeKind::Standard(StandardNative::TemplateInterpolate),
                ),
                (
                    "转义HTML",
                    1,
                    NativeKind::Standard(StandardNative::HtmlEscape),
                ),
                (
                    "反转义HTML",
                    1,
                    NativeKind::Standard(StandardNative::HtmlUnescape),
                ),
            ],
            "校验" => &[
                ("电子邮件", 1, NativeKind::Standard(StandardNative::IsEmail)),
                ("IPv4", 1, NativeKind::Standard(StandardNative::IsIpv4)),
                (
                    "十六进制色",
                    1,
                    NativeKind::Standard(StandardNative::IsHexColor),
                ),
                (
                    "标识符",
                    1,
                    NativeKind::Standard(StandardNative::IsIdentifier),
                ),
            ],
            "Base64" => &[
                (
                    "编码",
                    1,
                    NativeKind::Standard(StandardNative::Base64Encode),
                ),
                (
                    "解码",
                    1,
                    NativeKind::Standard(StandardNative::Base64Decode),
                ),
                (
                    "网址编码",
                    1,
                    NativeKind::Standard(StandardNative::Base64UrlEncode),
                ),
                (
                    "解网址编码",
                    1,
                    NativeKind::Standard(StandardNative::Base64UrlDecode),
                ),
            ],
            "正则" => &[
                (
                    "匹配",
                    2,
                    NativeKind::Standard(StandardNative::RegexIsMatch),
                ),
                ("首项", 2, NativeKind::Standard(StandardNative::RegexFirst)),
                (
                    "替换全部",
                    3,
                    NativeKind::Standard(StandardNative::RegexReplaceAll),
                ),
                ("分割", 2, NativeKind::Standard(StandardNative::RegexSplit)),
            ],
            "URL" => &[
                (
                    "是否合法",
                    1,
                    NativeKind::Standard(StandardNative::UrlIsValid),
                ),
                ("协议", 1, NativeKind::Standard(StandardNative::UrlScheme)),
                ("主机", 1, NativeKind::Standard(StandardNative::UrlHost)),
                ("端口", 1, NativeKind::Standard(StandardNative::UrlPort)),
                ("路径", 1, NativeKind::Standard(StandardNative::UrlPath)),
                (
                    "查询值",
                    2,
                    NativeKind::Standard(StandardNative::UrlQueryValue),
                ),
                ("合并", 2, NativeKind::Standard(StandardNative::UrlJoin)),
            ],
            "日期" => &[
                (
                    "是否合法",
                    1,
                    NativeKind::Standard(StandardNative::DateIsValid),
                ),
                (
                    "是否闰年",
                    1,
                    NativeKind::Standard(StandardNative::DateIsLeapYear),
                ),
                ("加天", 2, NativeKind::Standard(StandardNative::DateAddDays)),
                (
                    "相差天数",
                    2,
                    NativeKind::Standard(StandardNative::DateDaysBetween),
                ),
                (
                    "HTTP日期",
                    1,
                    NativeKind::Standard(StandardNative::HttpDate),
                ),
                (
                    "解析HTTP日期",
                    1,
                    NativeKind::Standard(StandardNative::ParseHttpDate),
                ),
            ],
            _ => return Err(error(span, format!("VM 未有标准模块“{name}”"))),
        };
        let mut exports = HashSet::new();
        if name == "数学" {
            environment.borrow_mut().values.insert(
                "圆周率".into(),
                Binding {
                    value: VmValue::Number(std::f64::consts::PI),
                    mutable: false,
                    type_ref: Some(RuntimeType::named("数")),
                    type_environment: Some(Rc::downgrade(&environment)),
                },
            );
            exports.insert("圆周率".into());
        }
        for (function, arity, kind) in definitions {
            self.define_native(&environment, function, *arity, *kind);
            exports.insert((*function).into());
        }
        Ok(Rc::new(VmModule {
            name: format!("标准:{name}"),
            module_id: ModuleId::standard(name),
            environment,
            exports,
        }))
    }

    fn define_native(
        &self,
        environment: &EnvRef,
        name: &'static str,
        arity: usize,
        kind: NativeKind,
    ) {
        environment.borrow_mut().values.insert(
            name.into(),
            Binding {
                value: VmValue::Native(Rc::new(VmNative { name, arity, kind })),
                mutable: false,
                type_ref: Some(RuntimeType::named("法")),
                type_environment: Some(Rc::downgrade(environment)),
            },
        );
    }

    fn child_env(&mut self, parent: EnvRef) -> EnvRef {
        let environment = Rc::new(RefCell::new(Environment {
            values: HashMap::new(),
            parent: Some(parent),
        }));
        self.heap_environments.push(Rc::downgrade(&environment));
        self.gc_stats.allocated_environments += 1;
        self.gc_stats.live_environments += 1;
        environment
    }

    fn pop(&mut self, span: &Span) -> Result<VmValue, VmError> {
        self.stack.pop().ok_or_else(|| error(span, "值栈为空"))
    }

    fn peek(&self, span: &Span) -> Result<&VmValue, VmError> {
        self.stack.last().ok_or_else(|| error(span, "值栈为空"))
    }

    fn take(&mut self, count: usize, span: &Span) -> Result<Vec<VmValue>, VmError> {
        if self.stack.len() < count {
            return Err(error(span, "值栈不足"));
        }
        Ok(self.stack.split_off(self.stack.len() - count))
    }

    fn binary(
        &mut self,
        span: &Span,
        operation: fn(VmValue, VmValue, &Span) -> Result<VmValue, VmError>,
    ) -> Result<(), VmError> {
        let right = self.pop(span)?;
        let left = self.pop(span)?;
        self.stack.push(operation(left, right, span)?);
        Ok(())
    }

    fn numeric(
        &mut self,
        span: &Span,
        action: &str,
        operation: impl FnOnce(f64, f64) -> f64,
    ) -> Result<(), VmError> {
        let right = self.pop(span)?;
        let left = self.pop(span)?;
        match (left, right) {
            (VmValue::Number(_), VmValue::Number(0.0)) if action == "相除" => {
                Err(error(span, "不可除以零"))
            }
            (VmValue::Number(left), VmValue::Number(right)) => {
                self.stack.push(VmValue::Number(operation(left, right)));
                Ok(())
            }
            (left, right) => Err(error(
                span,
                format!(
                    "不可以{} 与 {} {action}",
                    left.type_name(),
                    right.type_name()
                ),
            )),
        }
    }

    fn compare_values(&mut self, span: &Span, invert: bool) -> Result<(), VmError> {
        let right = self.pop(span)?;
        let left = self.pop(span)?;
        self.stack
            .push(VmValue::Bool(values_equal(&left, &right) ^ invert));
        Ok(())
    }

    fn compare_numbers(
        &mut self,
        span: &Span,
        compare: impl FnOnce(f64, f64) -> bool,
    ) -> Result<(), VmError> {
        let right = self.pop(span)?;
        let left = self.pop(span)?;
        match (left, right) {
            (VmValue::Number(left), VmValue::Number(right)) => {
                self.stack.push(VmValue::Bool(compare(left, right)));
                Ok(())
            }
            (left, right) => Err(error(
                span,
                format!("不可比较{} 与 {}", left.type_name(), right.type_name()),
            )),
        }
    }

    pub fn collect_garbage(&mut self) -> GcStats {
        let mut marked = HashSet::new();
        mark_environment(&self.globals, &mut marked);
        for frame in &self.frames {
            mark_environment(&frame.environment, &mut marked);
        }
        for value in &self.stack {
            mark_value(value, &mut marked);
        }
        for module in self.module_cache.values() {
            mark_environment(&module.environment, &mut marked);
        }
        let mut collected = 0;
        self.heap_environments.retain(|weak| {
            if let Some(environment) = weak.upgrade() {
                let id = Rc::as_ptr(&environment) as usize;
                if !marked.contains(&id) {
                    let mut environment = environment.borrow_mut();
                    environment.values.clear();
                    environment.parent = None;
                    collected += 1;
                }
                true
            } else {
                false
            }
        });
        self.gc_stats.collected_environments += collected;
        self.gc_stats.live_environments = self
            .heap_environments
            .iter()
            .filter(|weak| weak.strong_count() > 0)
            .count();
        self.gc_stats
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.stack.clear();
        self.frames.clear();
        self.module_cache.clear();
        self.application_module_cache.clear();
        let environments = self
            .heap_environments
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        for environment in environments {
            let mut environment = environment.borrow_mut();
            environment.values.clear();
            environment.parent = None;
        }
    }
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

fn constant(chunk: &Chunk, index: usize, span: &Span) -> Result<VmValue, VmError> {
    chunk
        .constants
        .get(index)
        .map(|constant| match constant {
            Constant::Number(value) => VmValue::Number(*value),
            Constant::String(value) => VmValue::String(value.clone()),
            Constant::Bool(value) => VmValue::Bool(*value),
            Constant::Nil => VmValue::Nil,
        })
        .ok_or_else(|| error(span, "常量池下标越界"))
}

fn add(left: VmValue, right: VmValue, span: &Span) -> Result<VmValue, VmError> {
    match (left, right) {
        (VmValue::Number(left), VmValue::Number(right)) => Ok(VmValue::Number(left + right)),
        (VmValue::String(left), VmValue::String(right)) => Ok(VmValue::String(left + &right)),
        (left, right) => Err(error(
            span,
            format!("不可以{} 与 {} 相加", left.type_name(), right.type_name()),
        )),
    }
}

fn values_equal(left: &VmValue, right: &VmValue) -> bool {
    match (left, right) {
        (VmValue::Nil, VmValue::Nil) => true,
        (VmValue::Bool(left), VmValue::Bool(right)) => left == right,
        (VmValue::Number(left), VmValue::Number(right)) => left == right,
        (VmValue::String(left), VmValue::String(right)) => left == right,
        (VmValue::Bytes(left), VmValue::Bytes(right)) => left == right,
        (VmValue::Tuple(left), VmValue::Tuple(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| values_equal(left, right))
        }
        (VmValue::List(left), VmValue::List(right)) => Rc::ptr_eq(left, right),
        (VmValue::Map(left), VmValue::Map(right)) => Rc::ptr_eq(left, right),
        (VmValue::Closure(left), VmValue::Closure(right)) => Rc::ptr_eq(left, right),
        (VmValue::Class(left), VmValue::Class(right)) => Rc::ptr_eq(left, right),
        (VmValue::Instance(left), VmValue::Instance(right)) => Rc::ptr_eq(left, right),
        (VmValue::Module(left), VmValue::Module(right)) => Rc::ptr_eq(left, right),
        (VmValue::Iterator(left), VmValue::Iterator(right)) => Rc::ptr_eq(left, right),
        (VmValue::Task(left), VmValue::Task(right)) => Rc::ptr_eq(left, right),
        (VmValue::Socket(left), VmValue::Socket(right)) => Rc::ptr_eq(left, right),
        (VmValue::NativeModuleV2(left), VmValue::NativeModuleV2(right)) => Rc::ptr_eq(left, right),
        (VmValue::NativeResource(left), VmValue::NativeResource(right)) => left == right,
        _ => false,
    }
}

fn compare_values_for_sort(left: &VmValue, right: &VmValue) -> Ordering {
    match (left, right) {
        (VmValue::Number(left), VmValue::Number(right)) => left.total_cmp(right),
        (VmValue::String(left), VmValue::String(right)) => left.cmp(right),
        (left, right) => left
            .type_name()
            .cmp(&right.type_name())
            .then_with(|| left.to_string().cmp(&right.to_string())),
    }
}

fn list_index(value: &VmValue, span: &Span) -> Result<usize, VmError> {
    match value {
        VmValue::Number(number)
            if number.is_finite() && *number >= 0.0 && number.fract() == 0.0 =>
        {
            Ok(*number as usize)
        }
        _ => Err(error(span, "下标须为非负整数")),
    }
}

fn index_value(object: VmValue, index: VmValue, span: &Span) -> Result<VmValue, VmError> {
    match object {
        VmValue::List(items) => {
            let index = list_index(&index, span)?;
            items
                .borrow()
                .get(index)
                .cloned()
                .ok_or_else(|| error(span, format!("列下标 {index} 超出范围")))
        }
        VmValue::Tuple(items) => {
            let index = list_index(&index, span)?;
            items
                .get(index)
                .cloned()
                .ok_or_else(|| error(span, format!("元组下标 {index} 超出范围")))
        }
        VmValue::String(text) => {
            let index = list_index(&index, span)?;
            text.chars()
                .nth(index)
                .map(|character| VmValue::String(character.to_string()))
                .ok_or_else(|| error(span, format!("文字下标 {index} 超出范围")))
        }
        VmValue::Map(map) => map
            .borrow()
            .entries
            .iter()
            .find(|(key, _)| values_equal(key, &index))
            .map(|(_, value)| value.clone())
            .ok_or_else(|| error(span, format!("典中未有键“{index}”"))),
        value => Err(error(span, format!("{}不可用下标读取", value.type_name()))),
    }
}

fn slice_value(
    object: VmValue,
    start: VmValue,
    end: VmValue,
    span: &Span,
) -> Result<VmValue, VmError> {
    match object {
        VmValue::List(items) => {
            let items = items.borrow();
            let (start, end) = bounds(&start, &end, items.len(), span)?;
            Ok(VmValue::List(Rc::new(RefCell::new(
                items[start..end].to_vec(),
            ))))
        }
        VmValue::Tuple(items) => {
            let (start, end) = bounds(&start, &end, items.len(), span)?;
            Ok(VmValue::Tuple(Rc::new(items[start..end].to_vec())))
        }
        VmValue::String(text) => {
            let characters = text.chars().collect::<Vec<_>>();
            let (start, end) = bounds(&start, &end, characters.len(), span)?;
            Ok(VmValue::String(characters[start..end].iter().collect()))
        }
        value => Err(error(span, format!("{}不可切片", value.type_name()))),
    }
}

fn bounds(
    start: &VmValue,
    end: &VmValue,
    length: usize,
    span: &Span,
) -> Result<(usize, usize), VmError> {
    let start = if matches!(start, VmValue::Nil) {
        0
    } else {
        list_index(start, span)?
    };
    let end = if matches!(end, VmValue::Nil) {
        length
    } else {
        list_index(end, span)?
    };
    if start > end || end > length {
        return Err(error(span, "切片范围无效"));
    }
    Ok((start, end))
}

fn map_insert(map: &mut VmMap, key: VmValue, value: VmValue, span: &Span) -> Result<(), VmError> {
    if !matches!(
        key,
        VmValue::Number(_) | VmValue::String(_) | VmValue::Bool(_) | VmValue::Nil
    ) {
        return Err(error(span, "典键须为数、文、理或空"));
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

fn deep_clone(value: &VmValue) -> VmValue {
    match value {
        VmValue::List(items) => VmValue::List(Rc::new(RefCell::new(
            items.borrow().iter().map(deep_clone).collect(),
        ))),
        VmValue::Tuple(items) => VmValue::Tuple(Rc::new(items.iter().map(deep_clone).collect())),
        VmValue::Map(map) => VmValue::Map(Rc::new(RefCell::new(VmMap {
            entries: map
                .borrow()
                .entries
                .iter()
                .map(|(key, value)| (deep_clone(key), deep_clone(value)))
                .collect(),
        }))),
        value => value.clone(),
    }
}

fn iterator_result(value: Option<VmValue>) -> VmValue {
    let (available, value) = value.map_or((false, VmValue::Nil), |value| (true, value));
    VmValue::Tuple(Rc::new(vec![VmValue::Bool(available), value]))
}

fn parse_iterator_result(value: VmValue, span: &Span) -> Result<Option<VmValue>, VmError> {
    let VmValue::Tuple(items) = value else {
        return Err(error(span, "“遍次”须归还二元组"));
    };
    match items.as_slice() {
        [VmValue::Bool(true), value] => Ok(Some(value.clone())),
        [VmValue::Bool(false), _] => Ok(None),
        _ => Err(error(span, "“遍次”须归还（是否尚有，值）")),
    }
}

fn number(value: &VmValue, span: &Span) -> Result<f64, VmError> {
    match value {
        VmValue::Number(value) if value.is_finite() => Ok(*value),
        value => Err(error(
            span,
            format!("须为有限数，不可为{}", value.type_name()),
        )),
    }
}

fn vm_positive_u64(
    value: &VmValue,
    function: &str,
    name: &str,
    span: &Span,
) -> Result<u64, VmError> {
    let number = number(value, span)?;
    if number <= 0.0 || number.fract() != 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(error(span, format!("“{function}”之{name}须为安全正整数")));
    }
    Ok(number as u64)
}

fn vm_nonnegative_safe_u64(value: &VmValue, function: &str, span: &Span) -> Result<u64, VmError> {
    let number = number(value, span)?;
    if number < 0.0 || number.fract() != 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(error(span, format!("“{function}”参数须为安全非负整数")));
    }
    Ok(number as u64)
}

fn vm_nonnegative_usize(
    value: &VmValue,
    function: &str,
    maximum: usize,
    span: &Span,
) -> Result<usize, VmError> {
    let number = number(value, span)?;
    if number < 0.0 || number.fract() != 0.0 || number > maximum as f64 {
        return Err(bytes_error(
            span,
            "BYTES_RANGE",
            format!("“{function}”参数须为 0..={maximum} 的整数"),
        ));
    }
    Ok(number as usize)
}

fn vm_socket_timeout(value: &VmValue, _function: &str, span: &Span) -> Result<u64, VmError> {
    let number = number(value, span)?;
    if number <= 0.0
        || number.fract() != 0.0
        || number > crate::stdlib::SOCKET_MAX_TIMEOUT_MILLIS as f64
    {
        return Err(socket_error(
            span,
            crate::stdlib::SocketError::new(
                "SOCKET_TIMEOUT",
                format!(
                    "套接字超时须在 1..={} 毫秒之间",
                    crate::stdlib::SOCKET_MAX_TIMEOUT_MILLIS
                ),
            ),
        ));
    }
    Ok(number as u64)
}

fn vm_socket_max_bytes(
    value: &VmValue,
    _function: &str,
    host_max_bytes: u64,
    span: &Span,
) -> Result<u64, VmError> {
    let number = number(value, span)?;
    if number <= 0.0 || number.fract() != 0.0 || number > host_max_bytes as f64 {
        return Err(socket_error(
            span,
            crate::stdlib::SocketError::new(
                "SOCKET_LIMIT",
                format!("套接字单次接收上限须在 1..={} 字节之间", host_max_bytes),
            ),
        ));
    }
    Ok(number as u64)
}

fn vm_string<'a>(value: &'a VmValue, function: &str, span: &Span) -> Result<&'a str, VmError> {
    match value {
        VmValue::String(text) => Ok(text),
        value => Err(error(
            span,
            format!("“{function}”参数须为文，不可为{}", value.type_name()),
        )),
    }
}

fn vm_bool(value: &VmValue, function: &str, span: &Span) -> Result<bool, VmError> {
    match value {
        VmValue::Bool(value) => Ok(*value),
        value => Err(error(
            span,
            format!("“{function}”参数须为理，不可为{}", value.type_name()),
        )),
    }
}

fn vm_bytes(value: &VmValue, function: &str, span: &Span) -> Result<Rc<Vec<u8>>, VmError> {
    match value {
        VmValue::Bytes(bytes) => Ok(bytes.clone()),
        value => Err(bytes_error(
            span,
            "BYTES_TYPE",
            format!("“{function}”参数须为字节串，不可为{}", value.type_name()),
        )),
    }
}

fn vm_string_map(
    value: &VmValue,
    function: &str,
    span: &Span,
) -> Result<Vec<(String, String)>, VmError> {
    let VmValue::Map(map) = value else {
        return Err(error(
            span,
            format!(
                "“{function}”参数须为文至文之典，不可为{}",
                value.type_name()
            ),
        ));
    };
    map.borrow()
        .entries
        .iter()
        .enumerate()
        .map(|(index, (key, value))| match (key, value) {
            (VmValue::String(key), VmValue::String(value)) => Ok((key.clone(), value.clone())),
            _ => Err(error(
                span,
                format!("“{function}”首部第 {} 项之键和值皆须为文", index + 1),
            )),
        })
        .collect()
}

fn vm_socket(
    value: &VmValue,
    function: &str,
    span: &Span,
) -> Result<Rc<RefCell<crate::stdlib::SocketHandle>>, VmError> {
    match value {
        VmValue::Socket(socket) => Ok(socket.clone()),
        value => Err(error(
            span,
            format!("“{function}”参数须为套接字，不可为{}", value.type_name()),
        )),
    }
}

fn vm_string_key_map(entries: Vec<(&'static str, VmValue)>) -> VmValue {
    VmValue::Map(Rc::new(RefCell::new(VmMap {
        entries: entries
            .into_iter()
            .map(|(key, value)| (VmValue::String(key.into()), value))
            .collect(),
    })))
}

fn vm_optional_string(value: Option<String>) -> VmValue {
    value.map_or(VmValue::Nil, VmValue::String)
}

fn vm_string_sequence(
    value: &VmValue,
    function: &str,
    span: &Span,
) -> Result<Vec<String>, VmError> {
    let values: Vec<VmValue> = match value {
        VmValue::List(values) => values.borrow().clone(),
        VmValue::Tuple(values) => values.as_ref().clone(),
        value => {
            return Err(error(
                span,
                format!("“{function}”须收列或元，不可收{}", value.type_name()),
            ));
        }
    };
    values
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            VmValue::String(text) => Ok(text.clone()),
            value => Err(error(
                span,
                format!(
                    "“{function}”第 {} 项须为文，不可为{}",
                    index + 1,
                    value.type_name()
                ),
            )),
        })
        .collect()
}

fn vm_json_to_value(json: serde_json::Value, span: &Span) -> Result<VmValue, VmError> {
    Ok(match json {
        serde_json::Value::Null => VmValue::Nil,
        serde_json::Value::Bool(value) => VmValue::Bool(value),
        serde_json::Value::Number(value) => VmValue::Number(
            value
                .as_f64()
                .ok_or_else(|| error(span, "JSON 数超出言序数值范围"))?,
        ),
        serde_json::Value::String(value) => VmValue::String(value),
        serde_json::Value::Array(items) => VmValue::List(Rc::new(RefCell::new(
            items
                .into_iter()
                .map(|item| vm_json_to_value(item, span))
                .collect::<Result<Vec<_>, _>>()?,
        ))),
        serde_json::Value::Object(entries) => VmValue::Map(Rc::new(RefCell::new(VmMap {
            entries: entries
                .into_iter()
                .map(|(key, value)| Ok((VmValue::String(key), vm_json_to_value(value, span)?)))
                .collect::<Result<Vec<_>, VmError>>()?,
        }))),
    })
}

fn vm_value_to_json(value: &VmValue, span: &Span) -> Result<serde_json::Value, VmError> {
    Ok(match value {
        VmValue::Nil => serde_json::Value::Null,
        VmValue::Bool(value) => serde_json::Value::Bool(*value),
        VmValue::Number(value) => serde_json::Value::Number(
            serde_json::Number::from_f64(*value)
                .ok_or_else(|| error(span, "非有限数不可序列化为 JSON"))?,
        ),
        VmValue::String(value) => serde_json::Value::String(value.clone()),
        VmValue::List(items) => serde_json::Value::Array(
            items
                .borrow()
                .iter()
                .map(|item| vm_value_to_json(item, span))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        VmValue::Tuple(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| vm_value_to_json(item, span))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        VmValue::Map(map) => {
            let mut object = serde_json::Map::new();
            for (key, value) in &map.borrow().entries {
                let VmValue::String(key) = key else {
                    return Err(error(span, "JSON 对象之典键必须为文"));
                };
                object.insert(key.clone(), vm_value_to_json(value, span)?);
            }
            serde_json::Value::Object(object)
        }
        value => {
            return Err(error(
                span,
                format!("{}不可序列化为 JSON", value.type_name()),
            ));
        }
    })
}

fn vm_number_sequence(value: &VmValue, function: &str, span: &Span) -> Result<Vec<f64>, VmError> {
    let values: Vec<VmValue> = match value {
        VmValue::List(values) => values.borrow().clone(),
        VmValue::Tuple(values) => values.as_ref().clone(),
        value => {
            return Err(error(
                span,
                format!("“{function}”参数须为数列，不可为{}", value.type_name()),
            ));
        }
    };
    values
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            VmValue::Number(number) if number.is_finite() => Ok(*number),
            value => Err(error(
                span,
                format!(
                    "“{function}”数据第 {} 项须为有限数，不可为{}",
                    index + 1,
                    value.type_name()
                ),
            )),
        })
        .collect()
}

fn vm_statistic(
    arguments: &[VmValue],
    function: &str,
    statistic: fn(&[f64]) -> Result<f64, String>,
    span: &Span,
) -> Result<VmValue, VmError> {
    statistic(&vm_number_sequence(&arguments[0], function, span)?)
        .map(VmValue::Number)
        .map_err(|message| error(span, message))
}

fn vm_string_table(
    value: &VmValue,
    function: &str,
    span: &Span,
) -> Result<Vec<Vec<String>>, VmError> {
    let rows: Vec<VmValue> = match value {
        VmValue::List(rows) => rows.borrow().clone(),
        VmValue::Tuple(rows) => rows.as_ref().clone(),
        value => {
            return Err(error(
                span,
                format!("“{function}”参数须为二维文列，不可为{}", value.type_name()),
            ));
        }
    };
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            let fields: Vec<VmValue> = match row {
                VmValue::List(fields) => fields.borrow().clone(),
                VmValue::Tuple(fields) => fields.as_ref().clone(),
                value => {
                    return Err(error(
                        span,
                        format!(
                            "“{function}”第 {} 行须为文列，不可为{}",
                            row_index + 1,
                            value.type_name()
                        ),
                    ));
                }
            };
            fields
                .iter()
                .enumerate()
                .map(|(field_index, field)| match field {
                    VmValue::String(text) => Ok(text.clone()),
                    value => Err(error(
                        span,
                        format!(
                            "“{function}”第 {} 行第 {} 项须为文，不可为{}",
                            row_index + 1,
                            field_index + 1,
                            value.type_name()
                        ),
                    )),
                })
                .collect()
        })
        .collect()
}

fn ensure_callable(value: &VmValue, span: &Span) -> Result<(), VmError> {
    if matches!(
        value,
        VmValue::Closure(_) | VmValue::BoundMethod(_, _) | VmValue::Native(_) | VmValue::Class(_)
    ) {
        Ok(())
    } else {
        Err(error(span, "值不可调用"))
    }
}

fn thrown(value: VmValue, span: &Span) -> VmError {
    match value {
        VmValue::Error(value) => VmError {
            code: value.code,
            message: value.message.clone(),
            span: value.span.clone(),
            frames: value.frames.clone(),
        },
        value => error(span, value.to_string()),
    }
}

fn error(span: &Span, message: impl Into<String>) -> VmError {
    coded_error(span, "RUN000", message)
}

fn coded_error(span: &Span, code: &'static str, message: impl Into<String>) -> VmError {
    VmError {
        code,
        message: message.into(),
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn package_path_error(span: &Span, source: crate::package::PackagePathError) -> VmError {
    coded_error(span, source.code, source.diagnostic_message())
}

fn package_error(span: &Span, source: crate::package::ManifestError) -> VmError {
    if source.code() == "PACKAGE000" {
        error(span, source.to_string())
    } else {
        coded_error(
            span,
            source.code(),
            format!("{}：{}", source.path.display(), source.diagnostic_message()),
        )
    }
}

fn network_error(span: &Span, source: crate::stdlib::NetworkError) -> VmError {
    VmError {
        code: source.code,
        message: source.message,
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn socket_error(span: &Span, source: crate::stdlib::SocketError) -> VmError {
    VmError {
        code: source.code,
        message: source.message,
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn bytes_error(span: &Span, code: &'static str, message: impl Into<String>) -> VmError {
    VmError {
        code,
        message: message.into(),
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn host_event_error(span: &Span, source: host_events::HostEventError) -> VmError {
    VmError {
        code: source.code,
        message: source.message,
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn native_v2_error(span: &Span, source: crate::native_abi::NativeError) -> VmError {
    VmError {
        code: "NATIVE_V2",
        message: format!("[{}] {}", source.code, source.message),
        span: span.clone(),
        frames: Vec::new(),
    }
}

fn render_items(
    formatter: &mut fmt::Formatter<'_>,
    items: &[VmValue],
    open: char,
    close: char,
) -> fmt::Result {
    write!(
        formatter,
        "{open}{}{close}",
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("，")
    )
}

fn mark_environment(environment: &EnvRef, marked: &mut HashSet<usize>) {
    let id = Rc::as_ptr(environment) as usize;
    if !marked.insert(id) {
        return;
    }
    let environment = environment.borrow();
    if let Some(parent) = &environment.parent {
        mark_environment(parent, marked);
    }
    for binding in environment.values.values() {
        mark_value(&binding.value, marked);
    }
}

fn mark_value(value: &VmValue, marked: &mut HashSet<usize>) {
    match value {
        VmValue::Closure(closure) | VmValue::BoundMethod(closure, _) => {
            mark_environment(&closure.closure, marked);
        }
        VmValue::List(items) => {
            for value in items.borrow().iter() {
                mark_value(value, marked);
            }
        }
        VmValue::Tuple(items) => {
            for value in items.iter() {
                mark_value(value, marked);
            }
        }
        VmValue::Map(map) => {
            for (key, value) in &map.borrow().entries {
                mark_value(key, marked);
                mark_value(value, marked);
            }
        }
        VmValue::Class(class) => {
            for method in class.methods.values() {
                mark_environment(&method.closure.closure, marked);
            }
        }
        VmValue::Instance(instance) => {
            for value in instance.borrow().fields.values() {
                mark_value(value, marked);
            }
        }
        VmValue::Module(module) => mark_environment(&module.environment, marked),
        VmValue::Iterator(iterator) => match &*iterator.borrow() {
            VmIterator::Values { values, .. } => {
                for value in values {
                    mark_value(value, marked);
                }
            }
            VmIterator::Mapped { source, mapper } => {
                mark_value(&VmValue::Iterator(source.clone()), marked);
                mark_value(mapper, marked);
            }
            VmIterator::Filtered { source, predicate } => {
                mark_value(&VmValue::Iterator(source.clone()), marked);
                mark_value(predicate, marked);
            }
            VmIterator::Range { .. } | VmIterator::Object(_) => {}
        },
        VmValue::Task(task) => match &task.borrow().state {
            VmTaskState::Pending {
                closure,
                instance,
                arguments,
                ..
            } => {
                mark_environment(&closure.closure, marked);
                if let Some(instance) = instance {
                    mark_value(&VmValue::Instance(instance.clone()), marked);
                }
                for value in arguments {
                    mark_value(value, marked);
                }
            }
            VmTaskState::Completed(value) => mark_value(value, marked),
            VmTaskState::Running | VmTaskState::Failed(_) | VmTaskState::Cancelled => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_vm_releases_the_global_environment() {
        let globals = {
            let statements = crate::parse("法 恒（）：数 则 归 1；终 定 值：法 为 恒；").unwrap();
            let chunk = crate::bytecode::compile(&statements).unwrap();
            let mut vm = Vm::silent();
            let globals = Rc::downgrade(&vm.globals);
            vm.execute(&chunk).unwrap();
            globals
        };
        assert!(globals.upgrade().is_none());
    }

    fn run(source: &str) -> Vm {
        let statements = crate::parse(source).unwrap();
        let chunk = crate::bytecode::compile(&statements).unwrap();
        let mut vm = Vm::silent();
        vm.execute(&chunk).unwrap();
        vm
    }

    #[test]
    fn nested_host_pump_is_a_successful_noop() {
        let state = VmHostState::new(crate::permissions::PermissionSet::sandboxed());
        state.pumping.set(true);
        let mut error = std::mem::MaybeUninit::<native_abi_v2::YanxuNativeErrorV2>::zeroed();
        let status = unsafe { native_host_pump(state.host.context, 1, error.as_mut_ptr()) };
        assert_eq!(status, native_abi_v2::NATIVE_V2_OK);
        assert!(state.pumping.get());
    }

    #[test]
    fn executes_functions_closures_recursion_maps_slices_and_for() {
        let source = r#"
            法 阶乘（值：数）：数 则
                若 值 不大于 1 则 归 1；终
                归 值 乘 阶乘（值 减 1）；
            终
            法 外（甲：数）：法（数）：数 则
                法 内（乙：数）：数 则 归 甲 加 乙；终
                归 内；
            终
            定 加十：法（数）：数 为 外（10）；
            令 合计：数 为 0；
            逐 值：数 于【1，2，3】则 置 合计 为 合计 加 值；终
            定 对照：典<文,数> 为{「甲」：1}；
            置 对照【「乙」】为 2；
            言 阶乘（5）；
            言 加十（5）；
            言 合计；
            言 对照【「乙」】；
            言「天地玄黄」【1：3】；
        "#;
        let vm = run(source);
        assert_eq!(vm.output(), &["120", "15", "6", "2", "地玄"]);
    }

    #[test]
    fn rejects_unknown_bytecode_format_versions() {
        let statements = crate::parse("言 1；").unwrap();
        let mut chunk = crate::bytecode::compile(&statements).unwrap();
        chunk.format_version = crate::bytecode::BYTECODE_FORMAT_VERSION + 1;
        let error = Vm::silent().execute(&chunk).unwrap_err();
        assert!(error.message.contains("不支持字节码格式版本"));
    }

    #[test]
    fn executes_classes_protocols_errors_and_native_iterators() {
        let source = r#"
            协 可名 则 域 名：文；法 显示（）：文；终
            类 人 纳 可名 则
                公 只 域 名：文；
                法 初始化（名：文）则 置 此.名 为 名；终
                法 显示（）：文 则 归 此.名；终
            终
            定 子：可名 为 人（「子路」）；
            言 子.显示（）；
            试 则 抛「坏」；救 错 则 言 错.消息；终
            法 求和（合：数，值：数）：数 则 归 合 加 值；终
            言 折叠（范围（1，4），0，求和）；
        "#;
        let vm = run(source);
        assert_eq!(vm.output(), &["子路", "坏", "6"]);
    }

    #[test]
    fn gc_breaks_unreachable_closure_cycles_and_property_cache_hits() {
        let source = r#"
            法 制造（）：空 则
                法 自环（）：法 则 归 自环；终
                归 空；
            终
            类 盒 则
                域 值：数 为 1；
                法 取（）：数 则 归 此.值；终
            终
            定 盒子：盒 为 盒（）；
            言 盒子.取（）；
            言 盒子.取（）；
            制造（）；
        "#;
        let mut vm = run(source);
        let before = vm.gc_stats();
        let after = vm.collect_garbage();
        assert!(after.collected_environments > before.collected_environments);
        assert!(vm.cache_stats().property_hits > 0);
    }

    #[test]
    fn module_bytecode_cache_reuses_and_invalidates_by_metadata() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-vm-cache-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let module_path = root.join("模块.yx");
        fs::write(&module_path, "公 定 值：数 为 1；").unwrap();
        let canonical = fs::canonicalize(&module_path).unwrap();
        let statements = crate::parse("引「模块.yx」为 模；言 模.值；").unwrap();
        let chunk = crate::bytecode::compile(&statements).unwrap();
        let mut vm = Vm::silent();

        vm.execute_in_directory(&chunk, &root).unwrap();
        vm.module_cache.remove(&canonical);
        let before_reuse = vm.cache_stats();
        vm.execute_in_directory(&chunk, &root).unwrap();
        assert!(vm.cache_stats().module_hits > before_reuse.module_hits);

        fs::write(&module_path, "公 定 值：数 为 222；").unwrap();
        vm.module_cache.remove(&canonical);
        vm.execute_in_directory(&chunk, &root).unwrap();
        assert_eq!(vm.output(), &["1", "1", "222"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn socket_module_runs_tcp_in_the_independent_vm() {
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
        let vm = run(&source);
        server.join().unwrap();
        assert_eq!(
            vm.output(),
            &["套接字", "真", "6", "安好", "真", "SOCKET_STATE", "套接字"]
        );
    }
}

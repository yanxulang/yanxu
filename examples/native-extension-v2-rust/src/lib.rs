use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::OnceLock;

const ABI: u32 = 2;
const OK: i32 = 0;
const ERROR: i32 = 1;
const INTEGER: u32 = 2;
const BYTES: u32 = 5;
const RESOURCE: u32 = 8;
const CALLBACK: u32 = 9;

#[repr(C)]
#[derive(Clone, Copy)]
union ValueData {
    integer: i64,
    number: f64,
    bytes: *const u8,
    items: *const Value,
    resource: *mut NativeResource,
    handle: u64,
}

impl Default for ValueData {
    fn default() -> Self {
        Self { handle: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Value {
    kind: u32,
    flags: u32,
    length: u64,
    data: ValueData,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeError {
    code: *const u8,
    code_length: usize,
    message: *const u8,
    message_length: usize,
}

type DropResource = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct NativeResource {
    struct_size: usize,
    resource: *mut c_void,
    type_name: *const u8,
    type_name_length: usize,
    parent: u64,
    drop_resource: Option<DropResource>,
}

type CallbackRetain = unsafe extern "C" fn(*mut c_void, u64) -> i32;
type CallbackRelease = unsafe extern "C" fn(*mut c_void, u64) -> i32;
type CallbackPost =
    unsafe extern "C" fn(*mut c_void, u64, *const Value, usize, *mut NativeError) -> i32;

#[repr(C)]
struct NativeHost {
    abi_version: u32,
    struct_size: usize,
    context: *mut c_void,
    callback_retain: Option<CallbackRetain>,
    callback_release: Option<CallbackRelease>,
    callback_post: Option<CallbackPost>,
    wake: Option<unsafe extern "C" fn(*mut c_void)>,
    pump: Option<unsafe extern "C" fn(*mut c_void, usize, *mut NativeError) -> i32>,
    has_permission: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    resource_get: Option<unsafe extern "C" fn(*mut c_void, u64, *mut *mut c_void) -> i32>,
    event_loop_id: u64,
    owner_thread_token: u64,
}

type NativeCall = unsafe extern "C" fn(
    *mut c_void,
    *const Value,
    usize,
    *const NativeHost,
    *mut Value,
    *mut NativeError,
) -> i32;

#[repr(C)]
struct NativeFunction {
    name: *const u8,
    name_length: usize,
    context: *mut c_void,
    call: Option<NativeCall>,
}

#[repr(C)]
struct NativeConstant {
    name: *const u8,
    name_length: usize,
    value: *const Value,
}

#[repr(C)]
struct NativeModule {
    abi_version: u32,
    struct_size: usize,
    name: *const u8,
    name_length: usize,
    functions: *const NativeFunction,
    function_count: usize,
    constants: *const NativeConstant,
    constant_count: usize,
    resource_types: *const *const u8,
    resource_type_lengths: *const usize,
    resource_type_count: usize,
    free_value: Option<unsafe extern "C" fn(*mut Value)>,
    capabilities: u64,
}

static MODULE: OnceLock<usize> = OnceLock::new();
static MODULE_NAME: &[u8] = b"v2-example";
static SUM_NAME: &[u8] = b"sum_i64";
static BYTES_NAME: &[u8] = b"binary";
static RESOURCE_NAME: &[u8] = b"resource";
static CALLBACK_NAME: &[u8] = b"callback";
static PANIC_NAME: &[u8] = b"panic";
static ANSWER_NAME: &[u8] = b"answer";
static RESOURCE_TYPE: &[u8] = b"example.v2.resource";
static ARGUMENT_CODE: &[u8] = b"EXAMPLE_ARGUMENT";
static ARGUMENT_MESSAGE: &[u8] = b"expected ABI v2 arguments";
static PANIC_CODE: &[u8] = b"EXAMPLE_PANIC";
static PANIC_MESSAGE: &[u8] = b"panic isolated inside extension";

#[unsafe(no_mangle)]
extern "C" fn yanxu_native_module_v2() -> *const NativeModule {
    *MODULE.get_or_init(|| {
        let functions = Box::leak(
            vec![
                function(SUM_NAME, sum_i64),
                function(BYTES_NAME, binary),
                function(RESOURCE_NAME, resource),
                function(CALLBACK_NAME, callback),
                function(PANIC_NAME, panic_isolated),
            ]
            .into_boxed_slice(),
        );
        let answer = Box::leak(Box::new(Value {
            kind: INTEGER,
            data: ValueData { integer: 42 },
            ..Value::default()
        }));
        let constants = Box::leak(Box::new([NativeConstant {
            name: ANSWER_NAME.as_ptr(),
            name_length: ANSWER_NAME.len(),
            value: answer,
        }]));
        let resource_types = Box::leak(Box::new([RESOURCE_TYPE.as_ptr()]));
        let resource_lengths = Box::leak(Box::new([RESOURCE_TYPE.len()]));
        Box::into_raw(Box::new(NativeModule {
            abi_version: ABI,
            struct_size: std::mem::size_of::<NativeModule>(),
            name: MODULE_NAME.as_ptr(),
            name_length: MODULE_NAME.len(),
            functions: functions.as_ptr(),
            function_count: functions.len(),
            constants: constants.as_ptr(),
            constant_count: constants.len(),
            resource_types: resource_types.as_ptr(),
            resource_type_lengths: resource_lengths.as_ptr(),
            resource_type_count: resource_types.len(),
            free_value: Some(free_value),
            capabilities: 0b111,
        })) as usize
    }) as *const NativeModule
}

fn function(name: &'static [u8], call: NativeCall) -> NativeFunction {
    NativeFunction {
        name: name.as_ptr(),
        name_length: name.len(),
        context: ptr::null_mut(),
        call: Some(call),
    }
}

unsafe extern "C" fn sum_i64(
    _context: *mut c_void,
    arguments: *const Value,
    count: usize,
    _host: *const NativeHost,
    output: *mut Value,
    error: *mut NativeError,
) -> i32 {
    if count != 2 || arguments.is_null() || output.is_null() {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let arguments = unsafe { std::slice::from_raw_parts(arguments, count) };
    if arguments.iter().any(|argument| argument.kind != INTEGER) {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let left = unsafe { arguments[0].data.integer };
    let right = unsafe { arguments[1].data.integer };
    unsafe {
        *output = Value {
            kind: INTEGER,
            data: ValueData {
                integer: left.saturating_add(right),
            },
            ..Value::default()
        };
    }
    OK
}

unsafe extern "C" fn binary(
    _context: *mut c_void,
    _arguments: *const Value,
    count: usize,
    _host: *const NativeHost,
    output: *mut Value,
    error: *mut NativeError,
) -> i32 {
    if count != 0 || output.is_null() {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let bytes = vec![0_u8, 255, 128].into_boxed_slice();
    let length = bytes.len();
    let pointer = Box::into_raw(bytes).cast::<u8>();
    unsafe {
        *output = Value {
            kind: BYTES,
            length: length as u64,
            data: ValueData { bytes: pointer },
            ..Value::default()
        };
    }
    OK
}

unsafe extern "C" fn resource(
    _context: *mut c_void,
    _arguments: *const Value,
    count: usize,
    _host: *const NativeHost,
    output: *mut Value,
    error: *mut NativeError,
) -> i32 {
    if count != 0 || output.is_null() {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let raw = Box::into_raw(Box::new(7_u64)).cast();
    let descriptor = Box::new(NativeResource {
        struct_size: std::mem::size_of::<NativeResource>(),
        resource: raw,
        type_name: RESOURCE_TYPE.as_ptr(),
        type_name_length: RESOURCE_TYPE.len(),
        parent: 0,
        drop_resource: Some(drop_resource),
    });
    unsafe {
        *output = Value {
            kind: RESOURCE,
            data: ValueData {
                resource: Box::into_raw(descriptor),
            },
            ..Value::default()
        };
    }
    OK
}

unsafe extern "C" fn callback(
    _context: *mut c_void,
    arguments: *const Value,
    count: usize,
    host: *const NativeHost,
    output: *mut Value,
    error: *mut NativeError,
) -> i32 {
    if count != 1 || arguments.is_null() || host.is_null() || output.is_null() {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let argument = unsafe { &*arguments };
    let host = unsafe { &*host };
    if argument.kind != CALLBACK
        || host.abi_version != ABI
        || host.callback_retain.is_none()
        || host.callback_post.is_none()
        || host.callback_release.is_none()
    {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let handle = unsafe { argument.data.handle };
    if unsafe { host.callback_retain.unwrap()(host.context, handle) } != OK {
        return fail(error, ARGUMENT_CODE, ARGUMENT_MESSAGE);
    }
    let posted = Value {
        kind: INTEGER,
        data: ValueData { integer: 99 },
        ..Value::default()
    };
    let status = unsafe { host.callback_post.unwrap()(host.context, handle, &posted, 1, error) };
    let pumped = if status == OK {
        host.pump
            .map_or(OK, |pump| unsafe { pump(host.context, 64, error) })
    } else {
        ERROR
    };
    let released = unsafe { host.callback_release.unwrap()(host.context, handle) };
    if status != OK || pumped != OK || released != OK {
        return ERROR;
    }
    unsafe { *output = Value::default() };
    OK
}

unsafe extern "C" fn panic_isolated(
    _context: *mut c_void,
    _arguments: *const Value,
    _count: usize,
    _host: *const NativeHost,
    _output: *mut Value,
    error: *mut NativeError,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| panic!("test panic")));
    if result.is_err() {
        fail(error, PANIC_CODE, PANIC_MESSAGE)
    } else {
        OK
    }
}

unsafe extern "C" fn free_value(value: *mut Value) {
    if value.is_null() {
        return;
    }
    let value = unsafe { &mut *value };
    match value.kind {
        BYTES if value.length > 0 => {
            let pointer = unsafe { value.data.bytes as *mut u8 };
            if !pointer.is_null()
                && let Ok(length) = usize::try_from(value.length)
            {
                drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) });
            }
        }
        RESOURCE => {
            let pointer = unsafe { value.data.resource };
            if !pointer.is_null() {
                let descriptor = unsafe { Box::from_raw(pointer) };
                if !descriptor.resource.is_null()
                    && let Some(drop_resource) = descriptor.drop_resource
                {
                    unsafe { drop_resource(descriptor.resource) };
                }
            }
        }
        _ => {}
    }
    *value = Value::default();
}

unsafe extern "C" fn drop_resource(resource: *mut c_void) {
    if !resource.is_null() {
        drop(unsafe { Box::from_raw(resource.cast::<u64>()) });
    }
}

fn fail(error: *mut NativeError, code: &'static [u8], message: &'static [u8]) -> i32 {
    if let Some(error) = unsafe { error.as_mut() } {
        *error = NativeError {
            code: code.as_ptr(),
            code_length: code.len(),
            message: message.as_ptr(),
            message_length: message.len(),
        };
    }
    ERROR
}

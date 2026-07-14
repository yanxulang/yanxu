use serde_json::{Value, json};
use std::ffi::c_void;
use std::ptr;

const ABI: u32 = 1;
const OK: i32 = 0;
const ERROR: i32 = 1;
const JSON_OUTPUT: u32 = 1;
const RESOURCE_OUTPUT: u32 = 2;

type FreeBytes = unsafe extern "C" fn(*mut u8, usize);
type DropResource = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NativeError {
    code: *const u8,
    code_length: usize,
    message: *const u8,
    message_length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NativeOutput {
    kind: u32,
    json: *mut u8,
    json_length: usize,
    resource: *mut c_void,
    resource_type: *const u8,
    resource_type_length: usize,
    drop_resource: Option<DropResource>,
}

type InvokeCallback = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut NativeOutput,
    *mut NativeError,
) -> i32;

#[repr(C)]
pub struct NativeCallback {
    abi_version: u32,
    struct_size: usize,
    context: *mut c_void,
    invoke: Option<InvokeCallback>,
}

type NativeCall = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const NativeCallback,
    *mut NativeOutput,
    *mut NativeError,
) -> i32;

#[repr(C)]
pub struct NativeFunction {
    name: *const u8,
    name_length: usize,
    context: *mut c_void,
    call: Option<NativeCall>,
}

#[repr(C)]
pub struct NativeConstant {
    name: *const u8,
    name_length: usize,
    value_json: *const u8,
    value_json_length: usize,
}

#[repr(C)]
pub struct NativeModule {
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
    free_bytes: Option<FreeBytes>,
    capabilities: u64,
}

static MODULE_NAME: &[u8] = b"example";
static SUM_NAME: &[u8] = b"sum";
static COUNTER_NAME: &[u8] = b"counter";
static CALLBACK_NAME: &[u8] = b"callback";
static ANSWER_NAME: &[u8] = b"answer";
static ANSWER_JSON: &[u8] = b"42";
static RESOURCE_TYPE: &[u8] = b"example.counter";
static ERROR_CODE: &[u8] = b"EXAMPLE_ARGUMENT";
static ERROR_MESSAGE: &[u8] = b"expected a JSON array of two numbers";

#[unsafe(no_mangle)]
pub extern "C" fn yanxu_native_module_v1() -> *const NativeModule {
    let functions = Box::leak(
        vec![
            NativeFunction {
                name: SUM_NAME.as_ptr(),
                name_length: SUM_NAME.len(),
                context: ptr::null_mut(),
                call: Some(sum),
            },
            NativeFunction {
                name: COUNTER_NAME.as_ptr(),
                name_length: COUNTER_NAME.len(),
                context: ptr::null_mut(),
                call: Some(counter),
            },
            NativeFunction {
                name: CALLBACK_NAME.as_ptr(),
                name_length: CALLBACK_NAME.len(),
                context: ptr::null_mut(),
                call: Some(callback),
            },
        ]
        .into_boxed_slice(),
    );
    let constants = Box::leak(Box::new([NativeConstant {
        name: ANSWER_NAME.as_ptr(),
        name_length: ANSWER_NAME.len(),
        value_json: ANSWER_JSON.as_ptr(),
        value_json_length: ANSWER_JSON.len(),
    }]));
    let resource_types = Box::leak(Box::new([RESOURCE_TYPE.as_ptr()]));
    let resource_lengths = Box::leak(Box::new([RESOURCE_TYPE.len()]));
    Box::leak(Box::new(NativeModule {
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
        free_bytes: Some(free_bytes),
        capabilities: 0b1_1111,
    }))
}

unsafe extern "C" fn sum(
    _context: *mut c_void,
    arguments: *const u8,
    length: usize,
    _callback: *const NativeCallback,
    output: *mut NativeOutput,
    error: *mut NativeError,
) -> i32 {
    let arguments = unsafe { std::slice::from_raw_parts(arguments, length) };
    let parsed: Value = match serde_json::from_slice(arguments) {
        Ok(value) => value,
        Err(_) => return fail(error),
    };
    let Some(items) = parsed.as_array() else {
        return fail(error);
    };
    if items.len() != 2 {
        return fail(error);
    }
    let (Some(left), Some(right)) = (items[0].as_f64(), items[1].as_f64()) else {
        return fail(error);
    };
    unsafe { write_json(output, &json!(left + right)) };
    OK
}

unsafe extern "C" fn counter(
    _context: *mut c_void,
    _arguments: *const u8,
    _length: usize,
    _callback: *const NativeCallback,
    output: *mut NativeOutput,
    _error: *mut NativeError,
) -> i32 {
    let resource = Box::into_raw(Box::new(0_i64)).cast();
    unsafe {
        *output = NativeOutput {
            kind: RESOURCE_OUTPUT,
            json: ptr::null_mut(),
            json_length: 0,
            resource,
            resource_type: RESOURCE_TYPE.as_ptr(),
            resource_type_length: RESOURCE_TYPE.len(),
            drop_resource: Some(drop_counter),
        };
    }
    OK
}

unsafe extern "C" fn callback(
    _context: *mut c_void,
    arguments: *const u8,
    length: usize,
    callback: *const NativeCallback,
    output: *mut NativeOutput,
    error: *mut NativeError,
) -> i32 {
    let Some(callback) = (unsafe { callback.as_ref() }) else {
        return fail(error);
    };
    let Some(invoke) = callback.invoke else {
        return fail(error);
    };
    unsafe {
        invoke(
            callback.context,
            CALLBACK_NAME.as_ptr(),
            CALLBACK_NAME.len(),
            arguments,
            length,
            output,
            error,
        )
    }
}

fn fail(error: *mut NativeError) -> i32 {
    if let Some(error) = unsafe { error.as_mut() } {
        *error = NativeError {
            code: ERROR_CODE.as_ptr(),
            code_length: ERROR_CODE.len(),
            message: ERROR_MESSAGE.as_ptr(),
            message_length: ERROR_MESSAGE.len(),
        };
    }
    ERROR
}

unsafe fn write_json(output: *mut NativeOutput, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap().into_boxed_slice();
    let length = bytes.len();
    let data = Box::into_raw(bytes).cast::<u8>();
    unsafe {
        *output = NativeOutput {
            kind: JSON_OUTPUT,
            json: data,
            json_length: length,
            resource: ptr::null_mut(),
            resource_type: ptr::null(),
            resource_type_length: 0,
            drop_resource: None,
        };
    }
}

unsafe extern "C" fn free_bytes(data: *mut u8, length: usize) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, length)) });
    }
}

unsafe extern "C" fn drop_counter(resource: *mut c_void) {
    if !resource.is_null() {
        drop(unsafe { Box::from_raw(resource.cast::<i64>()) });
    }
}

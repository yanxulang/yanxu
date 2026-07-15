#ifndef YANXU_NATIVE_H
#define YANXU_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YANXU_NATIVE_ABI_VERSION 1u
#define YANXU_NATIVE_OK 0
#define YANXU_NATIVE_ERROR 1
#define YANXU_NATIVE_OUTPUT_JSON 1u
#define YANXU_NATIVE_OUTPUT_RESOURCE 2u

typedef void (*YanxuNativeFreeBytesV1)(uint8_t *data, size_t length);
typedef void (*YanxuNativeDropResourceV1)(void *resource);

typedef struct YanxuNativeErrorV1 {
    const uint8_t *code;
    size_t code_length;
    const uint8_t *message;
    size_t message_length;
} YanxuNativeErrorV1;

typedef struct YanxuNativeOutputV1 {
    uint32_t kind;
    uint8_t *json;
    size_t json_length;
    void *resource;
    const uint8_t *resource_type;
    size_t resource_type_length;
    YanxuNativeDropResourceV1 drop_resource;
} YanxuNativeOutputV1;

typedef int32_t (*YanxuNativeInvokeCallbackV1)(
    void *context,
    const uint8_t *callback_name,
    size_t callback_name_length,
    const uint8_t *arguments_json,
    size_t arguments_json_length,
    YanxuNativeOutputV1 *output,
    YanxuNativeErrorV1 *error
);

typedef struct YanxuNativeCallbackV1 {
    uint32_t abi_version;
    size_t struct_size;
    void *context;
    YanxuNativeInvokeCallbackV1 invoke;
} YanxuNativeCallbackV1;

typedef int32_t (*YanxuNativeFunctionPointerV1)(
    void *function_context,
    const uint8_t *arguments_json,
    size_t arguments_json_length,
    const YanxuNativeCallbackV1 *callback,
    YanxuNativeOutputV1 *output,
    YanxuNativeErrorV1 *error
);

typedef struct YanxuNativeFunctionV1 {
    const uint8_t *name;
    size_t name_length;
    void *context;
    YanxuNativeFunctionPointerV1 call;
} YanxuNativeFunctionV1;

typedef struct YanxuNativeConstantV1 {
    const uint8_t *name;
    size_t name_length;
    const uint8_t *value_json;
    size_t value_json_length;
} YanxuNativeConstantV1;

typedef struct YanxuNativeModuleV1 {
    uint32_t abi_version;
    size_t struct_size;
    const uint8_t *name;
    size_t name_length;
    const YanxuNativeFunctionV1 *functions;
    size_t function_count;
    const YanxuNativeConstantV1 *constants;
    size_t constant_count;
    const uint8_t *const *resource_types;
    const size_t *resource_type_lengths;
    size_t resource_type_count;
    YanxuNativeFreeBytesV1 free_bytes;
    uint64_t capabilities;
} YanxuNativeModuleV1;

typedef const YanxuNativeModuleV1 *(*YanxuNativeModuleEntryV1)(void);

/* 每个动态库必须导出这个符号并返回进程存续期间稳定的描述符。 */
const YanxuNativeModuleV1 *yanxu_native_module_v1(void);

/* ABI v2 与上面的 v1 布局和入口完全独立。 */
#define YANXU_NATIVE_ABI_VERSION_V2 2u
#define YANXU_NATIVE_V2_OK 0
#define YANXU_NATIVE_V2_ERROR 1
#define YANXU_NATIVE_V2_NULL 0u
#define YANXU_NATIVE_V2_BOOL 1u
#define YANXU_NATIVE_V2_INTEGER 2u
#define YANXU_NATIVE_V2_NUMBER 3u
#define YANXU_NATIVE_V2_STRING 4u
#define YANXU_NATIVE_V2_BYTES 5u
#define YANXU_NATIVE_V2_ARRAY 6u
#define YANXU_NATIVE_V2_MAP 7u
#define YANXU_NATIVE_V2_RESOURCE 8u
#define YANXU_NATIVE_V2_CALLBACK 9u
#define YANXU_NATIVE_V2_ERROR_VALUE 10u
#define YANXU_NATIVE_V2_FLAG_TRUE 1u
#define YANXU_NATIVE_V2_FLAG_RESOURCE_HANDLE (1u << 1)

typedef uint64_t YanxuCallbackHandleV2;
typedef uint64_t YanxuResourceHandleV2;

typedef union YanxuValueDataV2 {
    int64_t integer;
    double number;
    const uint8_t *bytes;
    const struct YanxuValueV2 *items;
    struct YanxuNativeResourceV2 *resource;
    uint64_t handle;
} YanxuValueDataV2;

typedef struct YanxuValueV2 {
    uint32_t kind;
    uint32_t flags;
    uint64_t length;
    YanxuValueDataV2 value;
} YanxuValueV2;

typedef struct YanxuNativeErrorV2 {
    const uint8_t *code;
    size_t code_length;
    const uint8_t *message;
    size_t message_length;
} YanxuNativeErrorV2;

typedef void (*YanxuNativeDropResourceV2)(void *resource);

typedef struct YanxuNativeResourceV2 {
    size_t struct_size;
    void *resource;
    const uint8_t *type_name;
    size_t type_name_length;
    YanxuResourceHandleV2 parent;
    YanxuNativeDropResourceV2 drop_resource;
} YanxuNativeResourceV2;

typedef int32_t (*YanxuCallbackRetainV2)(
    void *context,
    YanxuCallbackHandleV2 callback
);
typedef int32_t (*YanxuCallbackReleaseV2)(
    void *context,
    YanxuCallbackHandleV2 callback
);
typedef int32_t (*YanxuCallbackPostV2)(
    void *context,
    YanxuCallbackHandleV2 callback,
    const YanxuValueV2 *arguments,
    size_t argument_count,
    YanxuNativeErrorV2 *error
);
typedef void (*YanxuHostWakeV2)(void *context);
typedef int32_t (*YanxuHostPumpV2)(
    void *context,
    size_t maximum_events,
    YanxuNativeErrorV2 *error
);
typedef int32_t (*YanxuHostPermissionV2)(
    void *context,
    const uint8_t *capability,
    size_t capability_length
);
typedef int32_t (*YanxuHostResourceGetV2)(
    void *context,
    YanxuResourceHandleV2 resource,
    void **raw_resource
);

typedef struct YanxuNativeHostV2 {
    uint32_t abi_version;
    size_t struct_size;
    void *context;
    YanxuCallbackRetainV2 callback_retain;
    YanxuCallbackReleaseV2 callback_release;
    YanxuCallbackPostV2 callback_post;
    YanxuHostWakeV2 wake;
    YanxuHostPumpV2 pump;
    YanxuHostPermissionV2 has_permission;
    YanxuHostResourceGetV2 resource_get;
    uint64_t event_loop_id;
    uint64_t owner_thread_token;
} YanxuNativeHostV2;

typedef int32_t (*YanxuNativeFunctionPointerV2)(
    void *function_context,
    const YanxuValueV2 *arguments,
    size_t argument_count,
    const YanxuNativeHostV2 *host,
    YanxuValueV2 *output,
    YanxuNativeErrorV2 *error
);

typedef struct YanxuNativeFunctionV2 {
    const uint8_t *name;
    size_t name_length;
    void *context;
    YanxuNativeFunctionPointerV2 call;
} YanxuNativeFunctionV2;

typedef struct YanxuNativeConstantV2 {
    const uint8_t *name;
    size_t name_length;
    const YanxuValueV2 *value;
} YanxuNativeConstantV2;

typedef void (*YanxuNativeFreeValueV2)(YanxuValueV2 *value);

typedef struct YanxuNativeModuleV2 {
    uint32_t abi_version;
    size_t struct_size;
    const uint8_t *name;
    size_t name_length;
    const YanxuNativeFunctionV2 *functions;
    size_t function_count;
    const YanxuNativeConstantV2 *constants;
    size_t constant_count;
    const uint8_t *const *resource_types;
    const size_t *resource_type_lengths;
    size_t resource_type_count;
    YanxuNativeFreeValueV2 free_value;
    uint64_t capabilities;
} YanxuNativeModuleV2;

typedef const YanxuNativeModuleV2 *(*YanxuNativeModuleEntryV2)(void);

/* 每个 ABI v2 动态库必须导出该符号。 */
const YanxuNativeModuleV2 *yanxu_native_module_v2(void);

#ifdef __cplusplus
}
#endif

#endif

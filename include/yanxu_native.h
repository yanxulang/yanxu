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

#ifdef __cplusplus
}
#endif

#endif

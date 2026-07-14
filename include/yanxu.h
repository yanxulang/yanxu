#ifndef YANXU_H
#define YANXU_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YANXU_ABI_SCHEMA 1

typedef struct YanxuEngine YanxuEngine;

/* 默认构造函数使用字节码后端、静态检查、资源预算和无宿主权限沙箱。 */
YanxuEngine *yanxu_engine_new(void);

/* 仅可信源码可使用不受限构造函数；资源预算仍然生效。 */
YanxuEngine *yanxu_engine_new_unrestricted(void);

/* 返回 schema 1 的 UTF-8 JSON。返回字符串必须由 yanxu_string_free 释放。 */
char *yanxu_engine_run(YanxuEngine *engine, const char *source);

void yanxu_engine_free(YanxuEngine *engine);
void yanxu_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif

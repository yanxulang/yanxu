# 言序原生扩展 ABI v1

原生 ABI v1 用于把 GUI、数据库、音频、图像与系统 API 等宿主能力封装为独立包。ABI 边界只使用 C 兼容布局、固定宽度数字、指针/长度对和 UTF-8 JSON，不暴露 Rust 类型布局。规范头文件是[`include/yanxu_native.h`](../include/yanxu_native.h)，可运行参考实现是[`examples/native-extension-rust`](../examples/native-extension-rust)。

## 安全门禁

言序只有在以下条件全部成立时才打开动态库：

1. 顶层应用显式声明`[权限].原生扩展 = true`；
2. 锁定制品的目标与`yanxu version --json`报告的目标完全相同；
3. 制品字节的 SHA-256 与清单/锁文件中的 64 位小写十六进制校验和一致；
4. 动态库导出`yanxu_native_module_v1`，描述符的 ABI 版本、结构大小、模块名、数组长度、指针、UTF-8 和名称唯一性全部通过校验。

WASI 目标始终返回`NATIVE_UNSUPPORTED`，不会尝试打开宿主动态库。言序不执行第三方包的构建脚本、安装钩子或 Shell 命令。

## 清单声明

```toml
[包]
格式 = 2
名 = "图像扩展"
版 = "1.0.0"
言序 = ">=1.1.5"
入口 = "src/图像.yx"

[原生]
ABI = 1

[原生.macos.aarch64]
文件 = "native/aarch64-apple-darwin/libimage.dylib"
校验和 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[原生.linux.x86_64]
文件 = "native/x86_64-unknown-linux-gnu/libimage.so"
校验和 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

解析器只选择当前目标的一个制品，并把目标、相对路径和校验和固定到锁文件。引用原生包的应用仍必须在自己的`权限`表开启`原生扩展`；依赖不能传递授权。

## 模块描述符

`YanxuNativeModuleV1`注册以下公开面：

- 函数：收取一个 UTF-8 JSON 参数值，返回 JSON 值或不透明资源；
- 常量：描述符存续期内稳定的 UTF-8 JSON 值；
- 资源类型：全局唯一类型名，返回资源时必须同时给出非空释放函数；
- 回调：宿主通过`YanxuNativeCallbackV1`把命名回调和 JSON 参数传回言序运行时；
- 错误：非`YANXU_NATIVE_OK`状态必须返回稳定代码和面向用户的 UTF-8 消息。

函数输出由模块的`free_bytes`释放；不透明资源由单独的`drop_resource`释放。言序在资源存活期内保持动态库已加载，且每个资源只释放一次。单次 JSON 输入/输出硬上限为 16 MiB，每类描述符最多 1024 项。

## 能力查询与验证

```sh
yanxu native --json
cargo test --test native_extension
```

`能力查询`只描述当前运行时支持的 ABI 面，不授予加载权限。对外发布的制品应在 Windows、Linux 和 macOS 对其声明目标分别构建和校验。

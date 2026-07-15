# 言序原生扩展 ABI v2

ABI v2 服务于需要长期资源、异步事件和非 JSON 二进制值的原生包。它与 ABI v1
完全并存：v1 动态库继续导出 `yanxu_native_module_v1`，v2 动态库导出
`yanxu_native_module_v2`，运行时不会把一种描述符按另一种布局解释。规范布局见
[`include/yanxu_native.h`](../include/yanxu_native.h)，可运行参考实现见
[`examples/native-extension-v2-rust`](../examples/native-extension-v2-rust)。

## 值与所有权

`YanxuValueV2` 使用固定的种类、标志、长度和 C union，覆盖空、布尔、64 位整数、
有限浮点数、UTF-8 文、任意字节、列、典、资源、回调和结构化错误。列元素连续排列；
典按键/值交替排列。宿主在调用期间借用参数，模块不得保存这些指针。模块返回的完整
值树由 `free_value` 恰好释放一次；宿主会在成功、模块错误、解码失败和类型违规路径
上执行同一释放规则。

默认上限限制递归深度、总元素、单/总字节和错误文字；非有限浮点、无效 UTF-8、
空指针/非零长度组合、奇数典元素或越界长度会返回稳定 `NATIVE_*` 错误。

## 持久回调

传入原生函数的言序可调用值会变成代际 `YanxuCallbackHandleV2`。需要在调用返回后
使用它时，模块必须调用 `callback_retain`；每次成功保留最终必须对应一次
`callback_release`。`callback_post` 可从原生线程投递值，但不会在该线程直接执行
言序代码：宿主先深拷贝参数，再放入容量有界的事件队列，由 VM 所有者线程的
`pump` 执行。已释放、代际过期或属于其他 VM 的句柄均被拒绝。

GUI 等高频生产者应在自身模型中合并鼠标移动、窗口尺寸和重绘状态。宿主队列满时
返回错误，不允许通过持续投递形成无界内存。`wake` 只请求唤醒平台事件循环，不是
回调执行许可；嵌套原生调用期间宿主会保存并恢复当前 VM/扩展上下文。

## 资源图

`YanxuNativeResourceV2` 声明原生指针、注册类型、可选父句柄和析构函数。宿主登记
资源后返回带代际的公开句柄；`resource_get` 只在当前扩展且句柄仍活跃时取回原始指针。
关闭父资源会先关闭子资源；重复关闭、VM 析构和错误回滚均保持析构恰好一次。动态库
直到其最后一个值、资源和回调关系释放后才卸载。

## 宿主函数表与权限

模块必须检查 `YanxuNativeHostV2.struct_size` 后再读取新增字段。当前函数表包含回调
保留/释放/投递、事件循环唤醒与泵、权限查询和资源取回。`event_loop_id`与
`owner_thread_token`供后端拒绝跨 VM/跨线程误用。

权限查询使用 UTF-8 能力名。普通原生包仍要求应用显式开启`原生扩展`。官方
`yanxu-gui`是窄化例外：仅当模块名精确匹配且应用开启`图形界面`时可装载；剪贴板、
文件对话框、通知、托盘、外部地址和全局快捷键仍分别授权，不能由 GUI 权限推导。

## 制品门禁

ABI v2 复用 v1 的普通文件、目标三元组、声明大小、SHA-256、私有内容寻址暂存和只读
装载门禁。Windows 使用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`，不会从进程当前目录搜索依赖 DLL。WASI 始终禁止
动态库。原生模块仍是进程内受信任代码，门禁不能隔离恶意系统调用。

```sh
yanxu native --json
cargo test --test native_extension_v2 -- --test-threads=1
```

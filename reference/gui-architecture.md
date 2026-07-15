# 言序 GUI 架构

言序 1.1.7 把桌面 GUI 实现为官方包`yanxu-gui`（言窗），而不是庞大的
`标准:GUI`。核心只提供可复用的 ABI、事件、资源、权限和制品边界；窗口、控件、布局
和平台适配可以独立发布、审计与替换，也不会把某个 Rust 框架写入语言规范 1。

```text
言序应用 → 言窗中文 API → 原生 ABI v2 → eframe/egui + winit → 操作系统
```

## ABI 与回调

ABI v1 的`yanxu_native_module_v1`、结构布局和 UTF-8 JSON 传输保持不变。ABI v2 使用
独立的`yanxu_native_module_v2`入口，增加递归类型值、不可变字节、结构化错误、宿主
函数表、代际回调和父子资源。参数只在调用期间借用，模块结果由模块的`free_value`
恰好释放一次。

长期事件回调必须先`retain`，销毁绑定、关闭控件、关闭父窗口或退出应用时必须
`release`。后台线程只能调用`callback_post`：宿主深拷贝参数后入有界队列，VM 所有者
线程执行`pump`才会进入言序闭包。已释放或 generation 过期的句柄返回
`GUI_CALLBACK_RELEASED`，不会复用为另一个闭包。

## 线程与事件循环

每个 VM 记录创建线程、事件循环 ID 和所有者线程令牌。窗口与控件只能从所属 UI/VM
线程操作；后台工作只能投递。普通事件保持 FIFO，高频鼠标移动、窗口移动/缩放和
重绘可按同一目标合并。容量耗尽返回`GUI_QUEUE_FULL`，退出后返回
`GUI_EVENT_LOOP_CLOSED`。同一事件循环重复或嵌套运行分别返回
`GUI_EVENT_LOOP_RUNNING`和`GUI_REENTRANT_CALL`。

定时器间隔限定为 10 毫秒到 24 小时，支持单次、周期和取消。它们与 GUI 事件走同一
队列，不能用零间隔制造忙循环。

## 资源所有权

宿主资源表为应用、窗口、布局、控件、图片、Canvas 和定时器使用代际句柄。每项记录
所属扩展、事件循环、线程、父项、子项、关闭状态与析构器。父项关闭时按子到父顺序
递归析构；显式关闭、值析构、VM 清理和错误回滚共享同一幂等路径。资源存在期间模块
动态库保持装载，事件循环返回后言窗会清空模型并释放全部保留回调。

## 后端边界

言窗 0.1.0 采用`eframe/egui + winit`：它提供真实原生窗口、Windows/macOS、Linux
Wayland/X11、每窗口 DPI、平台 IME、键盘导航与辅助功能树。公开`src/主.yx`只暴露
中文类、配置和受限字符串，不泄露 Rust 指针或 egui 类型。模型层与渲染层分开，CI
可无显示验证控件、布局、事件和资源生命周期，原生 runner 再编译并冒烟真实窗口。

## 调试

`yanxu 原生 --json`显示 ABI 上限，`yanxu 版本 --json`显示构建、格式、ABI 与权限
能力。言窗的`调试快照`返回各类存活资源计数。类型问题先运行`yanbao check`；后端
摘要或目标错误用`yanbao install`重建锁文件；线程、关闭资源和队列错误应保留稳定
错误码再定位。

更多细节见[ABI v2](native-abi-v2.md)、[Bundle](gui-bundle.md)和
[GUI 安全边界](gui-security.md)。

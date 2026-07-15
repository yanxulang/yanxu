# 从言序 1.1.6 迁移到 1.1.7

1.1.7 不改变语言规范 1 语法，也不破坏 ABI v1、旧 YXB v1、Standalone 或嵌入 API。
普通命令行项目可直接升级；只有使用 GUI、ABI v2 或新 Bundle 的项目需要新增清单项并
重新锁定、构建制品。

## 版本与锁文件

把格式 2 清单最低运行时改为`言序 = ">=1.1.7"`，用言包 0.4.0 运行`yanbao install`
重新生成锁文件。ABI v2 原生条目必须声明`ABI = 2`，并对每个真实目标分别记录文件、
SHA-256 与大小。不能复制一个平台制品后改名为其他目标。

`yanxu 版本 --json`现在报告 ABI v1/v2、格式和全部权限能力；工程握手也包含同一能力
列表。旧版工具若忽略新增 JSON 字段仍可工作。

## GUI 项目

新项目可直接执行：

```sh
yanbao init 我的窗口 --gui
yanbao check --manifest-path 我的窗口
yanbao run --manifest-path 我的窗口
yanbao build --manifest-path 我的窗口 --release --bundle
```

手工迁移时添加`yanxu-gui ^0.1`依赖、`[应用]`、`[应用.窗口]`和
`图形界面 = true`。按需单独申请剪贴板或文件对话框，不能假设 GUI 自动获得文件和
网络权限。图标必须是包内普通文件并列入资源目录。

言窗把输入交给平台 IME；应用只处理提交后的 Unicode 文本，不自行拼接组合串。中文
候选框、选择、剪切/复制/粘贴、撤销/重做与字体回退由 winit/egui 和系统字体提供。

## ABI 与运行模型

旧 v1 扩展继续导出`yanxu_native_module_v1`。需要异步事件的扩展迁移到 v2 后，应把
参数视为借用值、用模块`free_value`释放结果、成对 retain/release 长期回调，并从后台
线程只调用 post。控件、窗口和资源操作留在 VM 所有者线程。父资源关闭后所有子句柄
立即失效。

## Bundle 与调试

`--standalone`继续可用；图形分发改用`--bundle`，它携带运行时、YXB、原生库、资源、
图标、许可证和摘要。目标机器无需言序/言包或联网。交叉构建必须提供同目标 runtime；
当前机器只能实际运行本机架构产物。

常见迁移错误：

- 缺少后端：当前目标没有锁定真实原生条目，重新安装依赖或在对应原生 runner 构建；
- 摘要不符：源码/后端变化后锁文件过期，显式更新锁，不要绕过校验；
- 权限拒绝：同时检查应用申请与宿主上限；
- 线程/资源错误：不要在后台直接操作 UI，也不要保存已关闭父项的子句柄。

架构与安全细节见[GUI 架构](gui-architecture.md)、[ABI v2](native-abi-v2.md)、
[Bundle](gui-bundle.md)和[GUI 安全](gui-security.md)。

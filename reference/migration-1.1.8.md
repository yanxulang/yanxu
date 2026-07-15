# 从言序 1.1.7 迁移到 1.1.8

1.1.8 是兼容性修复版本，不改变语言规范 1、标准库 API、原生 ABI v1/v2、清单与锁文件、
YXB、Bundle 或嵌入接口。命令行项目和非 Windows 制品可直接替换运行时。

## 为什么 GUI 项目应升级

Windows MSVC 链接器默认只为可执行文件保留 1 MiB 主线程栈。言序 VM 所有者线程同时驱动
原生事件循环时，正常的控件布局、重绘和言序方法嵌套可能超过该默认值并终止进程。
1.1.8 为 x86_64 与 ARM64 Windows 的`yanxu.exe`保留 8 MiB 栈；GUI Bundle 复制同一
运行时，因此自动获得修复。该变化只修改 Windows PE 可执行文件头，不改变回调、资源或
线程语义。

## 升级步骤

1. 安装言序 1.1.8，并用`yanxu --version`确认当前运行时。
2. GUI 项目把格式 2 清单的最低版本改为`言序 = ">=1.1.8"`，再用言包重新生成锁文件。
3. 在对应 Windows 原生目标重新构建 YXB 与 Bundle；不要继续分发由 1.1.7 运行时打包的
   Windows Bundle。

无需修改`.yx`源码、ABI v2 调用方式、原生库摘要或资源声明。若项目不分发 Windows GUI，
旧清单仍可被 1.1.8 读取；重新锁定仅更新运行时要求和生成器身份。

## 验证

在 Windows x86_64 与 ARM64 原生 runner 上分别启动真实窗口，覆盖布局、重绘与关闭回调。
发行质量门禁还会直接解析`yanxu.exe`的 PE32+ 可选头，并确认
`SizeOfStackReserve >= 8 MiB`。GUI 运行模型和权限边界继续遵循
[GUI 架构](gui-architecture.md)与[GUI 安全](gui-security.md)。

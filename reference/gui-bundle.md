# 言序 GUI Bundle

GUI Bundle 是自包含的桌面分发目录。它在现有 YXB v1 上增加兼容的可选原生模块和
应用元数据字段；旧 YXB 缺少这些字段时仍按 1.1.6 语义读取。Bundle 不引入首次启动
下载，也不依赖目标机器安装言序、言包、源码或包缓存。

## 构建

```sh
yanxu 编 项目 --release --bundle
yanbao build --manifest-path 项目 --release --bundle
yanbao bundle --manifest-path 项目
```

默认嵌入当前`yanxu`。受控或交叉构建可加`--runtime <同目标运行时>`；构建器读取 PE、
ELF 或 Mach-O 头，拒绝平台或 x86-64/ARM64 架构错配。完整锁文件先精确选择当前目标
的 ABI v2 后端并核对普通文件、大小和 SHA-256，构建过程不联网补齐缺失制品。

通用内容包括带内嵌 YXB 的 standalone、可检查的`application.yxb`、内容寻址原生库、
应用资源、图标、平台元数据、许可证 NOTICE 和`bundle-manifest.json`。清单记录构建
版本/目标/模式/提交、应用标识和版本、YXB 摘要、日志位置、DLL 策略、签名计划以及
每个文件的角色、大小和 SHA-256。

## 平台布局

macOS 生成标准`.app/Contents/{MacOS,Resources,Frameworks}`、Info.plist 和 ICNS。
Info.plist 带 Bundle Identifier、显示名、版本、Retina 与可选最低系统版本；支持
Intel 与 Apple Silicon。

Windows 生成应用目录和真实 GUI 子系统 PE，不弹控制台窗口。构建器嵌入 ICO、公司/
文件/产品版本以及 PerMonitorV2 高 DPI manifest。ABI 库按绝对内容寻址路径装载，并
使用`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`，不搜索
进程当前目录；支持 x86-64 与 ARM64。

Linux 生成 AppDir、`AppRun`、Desktop Entry 和 hicolor 16–512 像素图标。winit 在
运行时按系统环境选择 Wayland，必要时回退 X11；发行机器仍需常规图形栈、字体配置与
对应 libc 系统依赖，应用本身和 GUI 后端已随目录携带。

## 原子性、验证和签名

输出在目标同级随机暂存目录组装，所有摘要验证通过后才原子改名。替换已有输出时先
改名为备份；安装失败会回滚。路径必须是规范相对路径，不能含`..`、绝对路径、链接
或特殊文件。Bundle 启动器在读取内嵌 YXB 前先定位外层标准清单，拒绝清单链接、入口
错配以及任一索引文件的大小或 SHA-256 变化；随后还会再次验证 YXB、目标、ABI、大小
与原生库摘要，并从随机私有父目录下的内容寻址只读位置装载。

`signing`字段只是签名计划，不把 SHA-256 冒充发布者身份。macOS 应依次签内嵌库、
主程序、外层 app，再公证与装订；Windows 在未签名内容验收后执行 Authenticode；
Linux 可对最终归档生成分离签名。签名会改变文件字节，签后应由平台工具验证签名并
生成对应分发清单。

日志建议位置为 macOS `~/Library/Logs/<标识>`、Windows
`%LOCALAPPDATA%\\<标识>\\Logs`、Linux`$XDG_STATE_HOME/<标识>/logs`。

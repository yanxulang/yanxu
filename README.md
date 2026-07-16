# 言序

[![CI](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml/badge.svg)](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YanXuLang/yanxu?include_prereleases)](https://github.com/YanXuLang/yanxu/releases)
[![License](https://img.shields.io/badge/license-MIT-c43b2f)](LICENSE)

言序是一门面向现代软件工程的中文编程语言。它使用中文关键字、标识符与诊断信息，同时提供静态检查、模块与包、结构化错误、字节码虚拟机、自包含应用和可嵌入运行时。1.1.12 修复 YXB 对大整数数字常量的精确往返与校验。

- [官方网站](https://yanxu.dev/)
- [语言文档](https://docs.yanxu.dev/)
- [下载发行版](https://github.com/YanXuLang/yanxu/releases)
- [问题与建议](https://github.com/YanXuLang/yanxu/issues)

## 快速开始

macOS 与 Linux：

```sh
curl -fsSL https://get.yanxu.dev | sh
```

Windows PowerShell：

```powershell
irm https://get.yanxu.dev/windows | iex
```

创建`你好.yx`：

```yanxu
法 问候（姓名：文）：文 则
    归 「你好，」加 姓名 加「！」；
终

言 问候（「言序」）；
```

运行程序：

```sh
yanxu 你好.yx
```

完整安装说明、编辑器配置与第一份项目见[快速入门](https://docs.yanxu.dev/getting-started/)。

## 使用言包管理项目

[言包](https://github.com/YanXuLang/yanbao)是官方项目与包管理工具。安装言序后，可直接安装言包并创建项目：

```sh
curl -fsSL https://get.yanxu.dev/yanbao | sh
yanbao init 我的项目 --name 示例
cd 我的项目
yanbao add http
yanbao check
yanbao test
```

官方 GitHub 包可省略`yanxulang/`组织名和`yanxu-`前缀；例如`yanbao add http`会添加`yanxulang/yanxu-http`。详见[言包文档](https://docs.yanxu.dev/tooling/package-manager/)。

创建桌面 GUI 应用：

```sh
yanbao new 我的窗口 --gui
yanbao run --manifest-path 我的窗口
yanbao bundle --manifest-path 我的窗口
```

## 语言概览

```yanxu
公 类 人 则
    公 只 域 姓名：文；

    法 初始化（姓名：文）则
        置 此.姓名 为 姓名；
    终

    法 问候（）：文 则
        归 「吾名」加 此.姓名；
    终
终

定 同伴：人 为 人（「言序」）；
言 同伴.问候（）；
```

言序提供：

- 中文关键字、标识符、全角或半角标点与源码级诊断；
- 可选类型标注、联合类型、分支收窄、继承与协议；
- 闭包、结构化错误、惰性迭代和确定性协作任务；
- 显式模块导出、格式 2 项目清单和完整依赖锁图；
- 树解释器与独立字节码 VM 的共享语言语义；
- 25 个标准模块，覆盖文字、文件、数据、网络、字节、进程和资源；
- YXB 字节码应用、自包含程序、桌面 Bundle、C ABI、Rust 嵌入和 WASI 接口；
- ABI v2 类型值、持久回调、有界宿主事件队列和父子资源生命周期。

语言语法与运行语义以[语言指南](https://docs.yanxu.dev/language/)和[版本化规范](spec/language/v1/README.md)为准。

## 工具链

| 命令 | 用途 |
| --- | --- |
| `yanxu <文卷.yx>` | 运行源码 |
| `yanxu check <文卷.yx>` | 静态类型检查 |
| `yanxu test <目录>` | 运行规格测试 |
| `yanxu fmt --write <文卷.yx>` | 格式化源码 |
| `yanxu compile <源码或项目> -o <制品>` | 构建 YXB；`--standalone`生成自包含程序，`--bundle`生成桌面应用目录 |
| `yanxu run <项目、.yx 或 .yxb>` | 统一运行源码与编译制品 |
| `yanxu doc <模块或目录>` | 生成 API 文档 |
| `yanxu lsp` | 启动 LSP 服务 |
| `yanxu dap` | 启动 DAP 服务 |
| `yanxu version --json` | 输出格式、ABI 与目标能力 |

中文命令别名继续受支持；完整参数见[命令行与 REPL](https://docs.yanxu.dev/getting-started/cli-repl/)和[工具链文档](https://docs.yanxu.dev/tooling/)。

## 架构与安全边界

言序核心由 Rust 实现，包含词法与语法分析、静态检查、树解释器、字节码编译器与 VM、包解析、应用封装、原生 ABI、宿主事件调度、LSP、DAP 和嵌入接口。GUI 作为官方`yanxu-gui`包提供，核心不内置庞大的 GUI 标准模块；言包通过版本化工程协议复用核心的清单、锁文件、YXB 和 Bundle 实现。

包清单显式声明文件、环境、网络、监听、进程、原生扩展、图形界面、剪贴板和文件对话框等独立权限。YXB 应用的有效权限始终受宿主授权上限约束；锁文件记录精确来源、修订、校验和与依赖边。原生扩展是进程内受信任代码，必须通过目标、SHA-256、ABI 版本和权限门禁。

进一步阅读：

- [运行时架构](https://docs.yanxu.dev/project/architecture/)
- [兼容政策](COMPATIBILITY.md)
- [原生 ABI v1](reference/native-abi-v1.md)
- [原生 ABI v2](reference/native-abi-v2.md)
- [GUI 架构](reference/gui-architecture.md)
- [GUI Bundle](reference/gui-bundle.md)
- [安全政策](SECURITY.md)

## 生态项目

- [言包](https://github.com/YanXuLang/yanbao)：官方项目与包管理工具
- [言窗](https://github.com/YanXuLang/yanxu-gui)：官方跨平台桌面 GUI 包
- [言序文档](https://github.com/YanXuLang/docs)：语言、工具链与生态文档
- [VS Code 扩展](https://github.com/YanXuLang/vscode-extension)：高亮、片段与运行命令
- [言枢](https://github.com/YanXuLang/yanxu-web)：言序 Web 应用框架
- [言据](https://github.com/YanXuLang/yanju)：中文数据交换格式与标准库

## 从源码构建

需要稳定版工具链的用户应优先安装发行制品。参与核心开发时：

```sh
git clone https://github.com/YanXuLang/yanxu.git
cd yanxu
cargo build --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

开发环境、测试矩阵和提交要求见[贡献指南](CONTRIBUTING.md)与[开发说明](DEVELOPMENT.md)。

## 许可证

言序按 [MIT License](LICENSE) 开源。

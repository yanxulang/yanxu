# 言序语言核心

[![CI](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml/badge.svg)](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YanXuLang/yanxu?include_prereleases)](https://github.com/YanXuLang/yanxu/releases)
[![License](https://img.shields.io/badge/license-MIT-c43b2f)](LICENSE)

这是言序编程语言的 Rust 实现仓库。1.1.6 在 1.1.5 工程能力上收紧 YXB/原生扩展安全边界、包管理原子性和可追溯发布门禁，并继续包含前端诊断、静态检查、树解释器、字节码 VM、完整包图、YXB 应用编译、嵌入 API、REPL 和完整工具链。

言序是一门现代中文解释型编程语言。它保留文言的简洁与节奏，同时提供联合类型、数据容器、结构化错误、源码级诊断、可调用父类实现的类继承、原生类型判断、显式模块边界与包清单。

```yanxu
公 类 人 则
    公 只 域 姓名：文；
    法 初始化（姓名：文）则
        置 此.姓名 为 姓名；
    终

    法 问候（）：文 则
        归 「吾名」 加 此.姓名；
    终
终

令 子：人 为 人（「言序」）；
言 子.问候（）；
```

## 安装

macOS / Linux：

```sh
curl -fsSL https://get.yanxu.dev | sh
```

Windows PowerShell：

```powershell
irm https://get.yanxu.dev/windows | iex
```

也可从[发行页](https://github.com/YanXuLang/yanxu/releases)下载 Windows、macOS 与 Linux 的 x86-64 / ARM64 构建。

安装器支持固定版本，例如`YANXU_VERSION=1.1.6 sh install.sh`；CI、离线镜像或本地制品验收还可同时指定`YANXU_ASSET_DIR`。无论来源为何，安装器都要求对应的`.sha256`文件，先在安装目录暂存并执行版本检查，只有候选程序可运行且版本与标签完全一致时才替换旧版本。

## 开发

```sh
cargo fmt --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo run -- examples/初见.yx
cargo run -- examples/元组与切片.yx
cargo run -- 查 examples/类与类型.yx
cargo run -- 字节 examples/VM入门.yx
cargo run -- 格 examples/初见.yx
cargo run -- 包 .
cargo run -- 基准 10
cargo run -- 兼容 --json
cargo run -- 标准库 --json
```

## 工具链命令

| 命令 | 用途 |
| --- | --- |
| `yanxu <文卷.yx> [-- 参数...]` | 使用参考树解释器执行，并向`环境.参数`传入程序参数 |
| `yanxu 查 <文卷.yx>` | 执行静态类型检查 |
| `yanxu 字节 <文卷.yx> [-- 参数...]` | 编译并使用栈式 VM 执行 |
| `yanxu 格 --写 <文卷.yx>` | 就地格式化 |
| `yanxu 试 <目录> [选项]` | 过滤、并发执行 `.yx` 规格测试并可输出 JSON |
| `yanxu 兼容 [目录] [--json]` | 运行 0.3–当前版本的双执行器兼容语料 |
| `yanxu 迁 [--检查\|--差异\|--写] <文卷>` | 检查并迁移已弃用源码形式 |
| `yanxu 标准库 --json` | 输出格式 1 的标准库 API 与权限审计 |
| `yanxu 文 <模块或目录>` | 生成带索引、注释与类型链接的 Markdown API |
| `yanxu 调试服务` | 启动 DAP 断点调试适配器 |
| `yanxu 语言服务` | 启动语义补全、跳转、引用、重命名与悬停 LSP |
| `yanxu 基准 [轮数]` | 校验并比较树解释器与 VM 执行耗时 |
| `yanxu compile <源码或项目> -o <制品>` | 编译不依赖原始源码的 YXB，`--standalone`生成自包含程序 |
| `yanxu run <项目、.yx 或 .yxb> [-- 参数]` | 统一执行源码项目与预编译应用 |
| `yanxu version --json` | 输出清单、锁、字节码、YXB、原生 ABI 与目标能力 |
| `yanxu package protocol '<JSON>'` | 为言包等工程工具提供版本化 JSON 协议 |

VM 是不回退到 AST 的独立执行路径，覆盖函数/闭包、对象协议、异常、模块、惰性迭代与容器；跨实现规格持续校验它和参考树解释器的共享语义。

### 包管理

核心 CLI 保留`yanxu 包`兼容入口；创建项目、增删依赖、安装与日常构建请使用官方工具[言包（yanbao）](https://github.com/YanXuLang/yanbao)。言包业务实现完全由言序源码编写，并通过版本化 JSON 工程协议调用`yanxu-package`，不复制 TOML、版本选择、锁文件或 YXB 语义。普通用户可安装言包独立 Release 中内置言序 VM 的 standalone，无需先安装言序；从源码开发言包时使用匹配的言序 1.1.6。

1.1.5 的格式 2 锁文件在构建前固定直接与传递依赖、精确版本/修订/来源/校验和、依赖边、目标与原生制品。`包:别名/导出`只能访问依赖的显式导出表，顶层项目不能越过清单导入传递依赖。Git 与索引包的源码根只在通过锁定和内容校验后进入模块加载边界；依赖清单的宿主权限不会自动传递。

### 结构化任务

`异 法`声明会返回`任务<T>`的异步函数。任务在第一次`候`时执行，结果或错误会被缓存；`取消`可取消尚未开始的任务，`并候`会在同一结构化作用域依次等待任务列，并在失败时取消余下任务。当前模型是确定性的协作式任务，不承诺线程并行。

```yanxu
异 法 求值（）：数 则
    归 42；
终

定 工作：任务<数> 为 求值（）；
言 候 工作；
```

嵌入宿主可通过`yanxu::embed::Engine`选择树解释器或字节码后端，并显式授予文件、网络外连、TCP 监听、UDP 绑定、环境和进程能力；默认嵌入配置为无宿主权限沙箱。`yanxu::ffi`提供版本化 JSON 的最小 C ABI，`yanxu::wasm::run_utf8`提供 WASI 友好的沙箱入口。直接 CLI 为兼容脚本保持不受限，包清单可用`[权限]`声明所需能力。

## 标准库

`标准:`命名空间在 1.1.5 提供 25 个模块：1.0 的`文字`、`数学`、`时间`、`文件`、`JSON`、`网络`、`测试`、`路径`、`环境`、`哈希`、`编码`、`统计`、`CSV`、`随机`、`标识`、`模板`与`校验`，1.1 新增的`Base64`、`正则`、`URL`和`日期`，1.1.2 的`套接字`，1.1.4 的`字节`，以及 1.1.5 的`进程`和`资源`。这些模块在树解释器和独立 VM 中使用同一套公开 API；`进程`受显式权限、超时和输出上限保护，`资源`在源码模式只读声明目录，在 YXB 中只读嵌入制品。

1.1.1 起，`网络.获取/发文`支持 HTTP 与 HTTPS，并采用 10 秒、4 MiB 的安全默认值；需要自定义请求时使用`网络.请求（方法，地址，正文，超时毫秒，最大字节）`。响应典包含`状态/地址/首部/正文`，网络失败可从捕获的误读取稳定`代码`和`类别`。

1.1.2 的`套接字`模块提供 TCP/UDP UTF-8 文字收发。连接、接受、发送和接收都必须显式给出毫秒超时；接收还必须给出不超过 4 MiB 的字节上限。1.1.3 将外连、TCP 监听与 UDP 绑定权限分离，DNS 结果和 HTTP 每次重定向都会复查，并限制单运行时的套接字资源。错误使用稳定`SOCKET_*`代码；完整入口见[`examples/1.1套接字.yx`](examples/1.1套接字.yx)。

1.1.4 新增不可变`字节串`与`标准:字节`，文件、TCP/UDP 和 HTTP 客户端因此可处理 NUL、图片、字体、压缩内容及其他任意二进制。`接收字节`显式返回 EOF，`精确读取`拒绝短正文；`网络.请求字节`支持受校验的自定义首部、二进制请求与响应。服务器辅助原语还包括安全随机、HMAC-SHA256、常量时间比较、HTTP 日期、文件状态和`--`分隔的命令行参数。本版本不包含 HTML、HTTP 服务端、Web 框架或异步 I/O；完整入口见[`examples/1.1.4二进制基础.yx`](examples/1.1.4二进制基础.yx)。

## 1.1.6 应用构建与原生扩展

`yanxu compile`会把入口、项目模块、锁定依赖模块、资源、权限、调试路径和内容校验和写入确定性 YXB。即使删除全部`.yx`源文件，`yanxu run app.yxb`仍可执行；`--standalone`再将当前平台的言序 VM 与 YXB 封装为不要求目标机安装言序的程序。这是预编译字节码应用，不是机器码后端。

YXB 中记录的是应用申请权限；最终有效权限始终是宿主授权上限与应用申请的交集。内容 SHA-256 只证明字节完整性，不证明发布者身份。原生扩展 ABI v1 使用 C 兼容布局和 UTF-8 JSON 传值；加载前必须同时通过目标平台、SHA-256、ABI 版本和`原生扩展`权限门禁，已验证字节从私有只读副本装载。原生代码仍是进程内受信任代码，不受语言沙箱完全约束；WASI 始终禁止动态库。参见[原生 ABI v1](reference/native-abi-v1.md)和[1.1.6 迁移指南](reference/migration-1.1.6.md)。

```yanxu
引「标准:编码」为 编码；
引「标准:统计」为 统计；
引「标准:CSV」为 CSV；
引「标准:标识」为 标识；

言 编码.解十六进制（编码.十六进制（「言序」））；
言 统计.平均（【1，2，3，4】）；
言 CSV.解析（「姓名,诗句\n子衿,\"青青子衿,悠悠我心\"」）；
言 标识.稳定UUID（「言序」）；
```

完整示例见[`examples/对象与类型判断.yx`](examples/对象与类型判断.yx)、[`examples/扩展标准库.yx`](examples/扩展标准库.yx)、[`examples/后1.0标准库.yx`](examples/后1.0标准库.yx)、[`examples/1.1标准库.yx`](examples/1.1标准库.yx)、[`examples/1.1套接字.yx`](examples/1.1套接字.yx)与[`examples/1.1.4二进制基础.yx`](examples/1.1.4二进制基础.yx)。

## 相关项目

- [官方网站](https://yanxu.dev/)
- [Fumadocs 文档](https://docs.yanxu.dev/)
- [言包包管理器](https://github.com/YanXuLang/yanbao)
- [VS Code 扩展](https://github.com/YanXuLang/vscode-extension)

言序按 [MIT License](LICENSE) 开源。

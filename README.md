# 言序语言核心

[![CI](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml/badge.svg)](https://github.com/YanXuLang/yanxu/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YanXuLang/yanxu?include_prereleases)](https://github.com/YanXuLang/yanxu/releases)
[![License](https://img.shields.io/badge/license-MIT-c43b2f)](LICENSE)

这是言序编程语言的 Rust 实现仓库，包含 1.0 规范、前端诊断、静态检查、树解释器、字节码 VM、包系统、任务、嵌入 API、REPL 和完整工具链。

言序是一门现代中文解释型编程语言。它保留文言的简洁与节奏，同时提供联合类型、数据容器、结构化错误、源码级诊断、类继承、显式模块边界与包清单。

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
curl -fsSL https://raw.githubusercontent.com/YanXuLang/yanxu/main/scripts/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/YanXuLang/yanxu/main/scripts/install.ps1 | iex
```

也可从[发行页](https://github.com/YanXuLang/yanxu/releases)下载 Windows、macOS 与 Linux 的 x86-64 / ARM64 构建。

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

## 1.0 命令

| 命令 | 用途 |
| --- | --- |
| `yanxu <文卷.yx>` | 使用参考树解释器执行 |
| `yanxu 查 <文卷.yx>` | 执行静态类型检查 |
| `yanxu 字节 <文卷.yx>` | 编译并使用栈式 VM 执行 |
| `yanxu 格 --写 <文卷.yx>` | 就地格式化 |
| `yanxu 试 <目录> [选项]` | 过滤、并发执行 `.yx` 规格测试并可输出 JSON |
| `yanxu 兼容 [目录] [--json]` | 运行 0.3–1.0 双执行器兼容语料 |
| `yanxu 迁 [--检查\|--差异\|--写] <文卷>` | 检查并迁移已弃用源码形式 |
| `yanxu 标准库 --json` | 输出格式 1 的标准库 API 与权限审计 |
| `yanxu 文 <模块或目录>` | 生成带索引、注释与类型链接的 Markdown API |
| `yanxu 调试服务` | 启动 DAP 断点调试适配器 |
| `yanxu 语言服务` | 启动语义补全、跳转、引用、重命名与悬停 LSP |
| `yanxu 基准 [轮数]` | 校验并比较树解释器与 VM 执行耗时 |

VM 是不回退到 AST 的独立执行路径，覆盖函数/闭包、对象协议、异常、模块、惰性迭代与容器；跨实现规格持续校验它和参考树解释器的共享语义。

### 包管理

核心 CLI 保留`yanxu 包`、`包 运行`、`包 锁`和`包 更新`作为运行时兼容入口；创建项目、增删依赖、安装与日常包管理请使用独立的官方工具[言包（yanbao）](https://github.com/YanXuLang/yanbao)。言包直接复用本仓库的`yanxu::package`解析器，因此`言序.toml`和`言序.lock`只有一套格式与解析语义。

### 结构化任务

`异 法`声明会返回`任务<T>`的异步函数。任务在第一次`候`时执行，结果或错误会被缓存；`取消`可取消尚未开始的任务，`并候`会在同一结构化作用域依次等待任务列，并在失败时取消余下任务。当前模型是确定性的协作式任务，不承诺线程并行。

```yanxu
异 法 求值（）：数 则
    归 42；
终

定 工作：任务<数> 为 求值（）；
言 候 工作；
```

嵌入宿主可通过`yanxu::embed::Engine`选择树解释器或字节码后端，并显式授予文件、网络、环境和进程能力；默认嵌入配置为无宿主权限沙箱。`yanxu::ffi`提供版本化 JSON 的最小 C ABI，`yanxu::wasm::run_utf8`提供 WASI 友好的沙箱入口。直接 CLI 为兼容脚本保持不受限，包清单可用`[权限]`声明所需能力。

## 标准库

`标准:`命名空间目前提供 21 个模块：1.0 的`文字`、`数学`、`时间`、`文件`、`JSON`、`网络`、`测试`、`路径`、`环境`、`哈希`、`编码`、`统计`、`CSV`、`随机`、`标识`、`模板`与`校验`，以及 1.1 新增的`Base64`、`正则`、`URL`和`日期`。这些模块在树解释器和独立 VM 中使用同一套公开 API；可移植算法由两端共享实现。

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

完整示例见[`examples/扩展标准库.yx`](examples/扩展标准库.yx)、[`examples/后1.0标准库.yx`](examples/后1.0标准库.yx)与[`examples/1.1标准库.yx`](examples/1.1标准库.yx)。

## 相关项目

- [官方网站](https://yanxu.dev/)
- [Fumadocs 文档](https://docs.yanxu.dev/)
- [言包包管理器](https://github.com/YanXuLang/yanbao)
- [VS Code 扩展](https://github.com/YanXuLang/vscode-extension)

言序按 [MIT License](LICENSE) 开源。

# 言序语言核心

[![CI](https://github.com/YanXuLang/language/actions/workflows/ci.yml/badge.svg)](https://github.com/YanXuLang/language/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YanXuLang/language?include_prereleases)](https://github.com/YanXuLang/language/releases)
[![License](https://img.shields.io/badge/license-MIT-c43b2f)](LICENSE)

这是言序编程语言的 Rust 实现仓库，包含词法器、解析器、语义解析、解释器、REPL、CLI、测试、示例和跨平台安装器。

言序是一门现代中文解释型编程语言。它保留文言的简洁与节奏，同时提供渐进式类型、数据容器、结构化错误、对象与模块。

```yanxu
类 人 则
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
curl -fsSL https://raw.githubusercontent.com/YanXuLang/language/main/scripts/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/YanXuLang/language/main/scripts/install.ps1 | iex
```

也可从[发行页](https://github.com/YanXuLang/language/releases)下载 Windows、macOS 与 Linux 的 x86-64 / ARM64 构建。

## 开发

```sh
cargo fmt --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo run -- examples/初见.yx
```

## 相关项目

- [官方网站](https://yanxulang.github.io/website/)
- [Fumadocs 文档](https://yanxulang.github.io/docs/)
- [VS Code 扩展](https://github.com/YanXuLang/vscode)
- [总控仓库](https://github.com/YanXuLang/yanxu)

言序按 [MIT License](LICENSE) 开源。

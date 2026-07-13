# 参与言序

感谢你帮助言序变得更好。项目接受错误修复、文档、测试、语言提案和工具链改进。

## 开始之前

- 小型修复可直接提交 Pull Request。
- 新语法、破坏兼容性的改动或较大的架构调整，请先创建 Discussion 或 Issue，说明动机、示例和兼容性影响。
- 请不要把多个无关改动放进同一个 Pull Request。

## 本地开发

需要 Rust 稳定版工具链。克隆项目后执行：

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

运行示例：

```sh
cargo run -- examples/初见.yx
```

文档、官网和编辑器扩展分别维护在 `YanXuLang/docs`、`YanXuLang/website` 与 `YanXuLang/vscode-extension`。跨项目改动请在对应仓库分别提交。

## 提交约定

推荐使用简短的祈使句提交标题，例如 `修复模块缓存的路径规范化`。Pull Request 应说明：

1. 改动解决什么问题；
2. 用户可见行为是否变化；
3. 如何验证；
4. 是否需要更新语法、架构或变更记录。

所有贡献按项目的 MIT 许可证发布，并须遵守[行为准则](CODE_OF_CONDUCT.md)。

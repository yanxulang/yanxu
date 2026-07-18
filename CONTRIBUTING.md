# 参与言序

感谢你帮助言序变得更好。项目接受错误修复、文档、测试、语言提案和工具链改进。

## 开始之前

- 小型修复可直接提交 Pull Request。
- 新语法、标准库或公共格式改动须先按[YXP 提案模板](proposals/README.md)创建 Discussion 或 Issue；破坏性变化还受[1.x 兼容政策](COMPATIBILITY.md)约束。
- 请不要把多个无关改动放进同一个 Pull Request。

## 本地开发

需要 Rust 1.89 或更高稳定版工具链。克隆项目后执行：

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run -- 兼容
cargo check --target wasm32-wasip1 --lib
```

运行示例：

```sh
cargo run -- examples/初见.yx
```

文档、官网和编辑器扩展分别维护在 `YanXuLang/docs`、`YanXuLang/website` 与 `YanXuLang/vscode-extension`。跨项目改动请在对应仓库分别提交。

## 版本发布

更新`Cargo.toml`中的包版本、同步`Cargo.lock`，并在`CHANGELOG.md`加入完全相同的`## X.Y.Z`章节。这些变更进入`main`后，`Auto Release`工作流会自动创建`vX.Y.Z`标签，并调用可复用`Release`工作流生成 GitHub Release、六个平台的二进制压缩包与独立 SHA-256 校验文件。

已有标签需要修复发布时，可从 Actions 手工运行`Release`并传入标签。标签版本、Cargo 版本、主分支归属或变更记录任一不一致时，发布会直接失败。

## 提交约定

推荐使用简短的祈使句提交标题，例如 `修复模块缓存的路径规范化`。Pull Request 应说明：

1. 改动解决什么问题；
2. 用户可见行为是否变化；
3. 如何验证；
4. 是否需要更新语法、架构或变更记录。

所有贡献按项目的 MIT 许可证发布，并须遵守[行为准则](CODE_OF_CONDUCT.md)。

# 1.0 嵌入示例

- `rust-host`演示持久引擎、后端、预算和权限配置。
- `c-host`演示 schema 1 JSON C ABI 的所有权边界。
- `wasi-host`演示`wasm32-wasip1`下的无宿主权限入口。

```sh
cargo run --manifest-path examples/embedding/rust-host/Cargo.toml
cargo check --manifest-path examples/embedding/wasi-host/Cargo.toml --target wasm32-wasip1
cargo doc --no-deps
```

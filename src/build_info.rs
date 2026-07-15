//! 可供 CLI、YXB 与工程协议复用的构建身份。

/// 构建时对应的完整 Git 提交；源码包不含 Git 历史时为`unknown`。
pub const COMMIT_SHA: &str = env!("YANXU_BUILD_SHA");
/// Cargo 实际编译目标三元组。
pub const TARGET: &str = env!("YANXU_BUILD_TARGET");
/// Cargo 构建模式，通常为`debug`或`release`。
pub const PROFILE: &str = env!("YANXU_BUILD_PROFILE");

pub fn identity() -> serde_json::Value {
    serde_json::json!({
        "commit_sha": COMMIT_SHA,
        "target": TARGET,
        "mode": PROFILE,
    })
}

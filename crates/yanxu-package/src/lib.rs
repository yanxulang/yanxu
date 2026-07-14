//! 言序唯一的包、锁文件、权限和依赖图语义核心。

mod package;
mod permissions;

pub use package::*;
pub use permissions::*;

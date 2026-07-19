//! 言序唯一的包、锁文件、权限和依赖图语义核心。

mod package;
mod path_policy;
mod permissions;
mod storage;

pub use package::*;
#[doc(hidden)]
pub use path_policy::{
    ModuleAuthority, PACKAGE_MODULE_OUTSIDE_ROOT_CODE, PACKAGE_MODULE_RESERVED_PATH_CODE,
    PACKAGE_PATH_COLLISION_CODE, PACKAGE_PATH_INVALID_CODE, PACKAGE_PATH_NON_PORTABLE_CODE,
    PACKAGE_PATH_RESERVED_CODE, PACKAGE_ROOT_INVALID_CODE, PackagePathDecision, PackagePathError,
    PackagePathPurpose, PackagePathReason, PortablePackagePaths, ResolvedPackageDirectoryEntry,
    ResolvedPackageFile, ResolvedPackageFileSnapshot, TrustedPackageRoots, package_path_decision,
    portable_package_path, resolve_existing_package_path, validate_portable_path_text,
};
pub use permissions::*;

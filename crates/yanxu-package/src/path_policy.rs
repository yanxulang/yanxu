//! 包内路径在校验、打包和模块加载之间共享的安全策略。
//!
//! 路径规则必须与宿主文件系统无关。否则，同一个包可能在区分大小写的
//! 平台进入锁摘要，却在另一平台被当成派生目录或锁文件跳过。

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(target_os = "wasi")]
use std::sync::Mutex;
use unicode_normalization::UnicodeNormalization;

#[cfg(not(target_os = "wasi"))]
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
#[cfg(target_os = "wasi")]
use rustix::fs::{
    AtFlags, Dir as RustixDir, FileType as RustixFileType, Mode, OFlags, fstat, openat, readlinkat,
    statat,
};

/// 模块试图进入包内保留内容时使用的稳定诊断码。
pub const PACKAGE_MODULE_RESERVED_PATH_CODE: &str = "PACKAGE_MODULE_RESERVED_PATH";
/// 包路径在受支持平台上具有不同含义时使用的稳定诊断码。
pub const PACKAGE_PATH_NON_PORTABLE_CODE: &str = "PACKAGE_PATH_NON_PORTABLE";
/// 包内相对路径不规范时使用的稳定诊断码。
pub const PACKAGE_PATH_INVALID_CODE: &str = "PACKAGE_PATH_INVALID";
/// 可信包根不存在、不是目录或无法规范化时使用的稳定诊断码。
pub const PACKAGE_ROOT_INVALID_CODE: &str = "PACKAGE_ROOT_INVALID";
/// 模块路径从一个可信包根逃逸或跨入另一个可信包根时使用的稳定诊断码。
pub const PACKAGE_MODULE_OUTSIDE_ROOT_CODE: &str = "PACKAGE_MODULE_OUTSIDE_ROOT";
/// 非模块清单字段指向保留内容时使用的稳定诊断码。
pub const PACKAGE_PATH_RESERVED_CODE: &str = "PACKAGE_PATH_RESERVED";
/// 两个路径在受支持平台上折叠为同一身份时使用的稳定诊断码。
pub const PACKAGE_PATH_COLLISION_CODE: &str = "PACKAGE_PATH_COLLISION";

const RESERVED_COMPONENTS: &[&str] = &[".git", ".yanxu", ".DS_Store", "target", "build", "vendor"];
const LOCK_NAME: &str = "言序.lock";
const TRUSTED_DIRECTORY_MAX_ENTRIES: usize = 100_000;
const TOOLING_DIRECTORY_MAX_ENTRIES: usize = 4_096;
const TOOLING_TREE_MAX_ENTRIES: usize = 100_000;
const TOOLING_TREE_MAX_DEPTH: usize = 128;

const RESERVED_MODULE_SUGGESTION: &str = "请将模块移至普通源码目录，并更新入口、导出或导入声明。";
const NON_PORTABLE_SUGGESTION: &str =
    "请使用规范保留拼写以外的、跨平台唯一且不以点或空格结尾的路径名。";

/// 路径将被用于哪一种包操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum PackagePathPurpose {
    /// 计算依赖源码树摘要。
    TreeChecksum,
    /// 写入或校验 YXP 的 `package/` 内容。
    YxpEntry,
    /// 作为可执行或可分析的言序模块读取。
    ModuleSource,
    /// 由包清单中的入口、导出、资源或原生制品字段引用。
    ManifestReference,
}

/// 路径为何不进入某个包内容集合。
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum PackagePathReason {
    /// `.git`、`.yanxu`、`.DS_Store`、`target`、`build` 或 `vendor`。
    ReservedComponent { component: String },
    /// 根锁文件或嵌套锁文件。
    LockFile { nested: bool },
}

/// 规范路径在指定包操作中的处理方式。
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum PackagePathDecision {
    Include,
    Exclude(PackagePathReason),
}

/// 可在编译器、解释器、虚拟机和工具链之间原样传递的路径诊断。
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct PackagePathError {
    pub code: &'static str,
    pub message: String,
    pub path: PathBuf,
    pub component: Option<String>,
    pub suggestion: String,
}

impl fmt::Display for PackagePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {} {}",
            self.code, self.message, self.suggestion
        )
    }
}

impl std::error::Error for PackagePathError {}

impl PackagePathError {
    /// 不重复嵌入稳定码、可交给上层结构化诊断的正文。
    pub fn diagnostic_message(&self) -> String {
        format!("{} {}", self.message, self.suggestion)
    }
}

/// 判断一个包根相对路径是否进入指定内容集合。
///
/// 规范保留组件在摘要和 YXP 场景中返回 [`PackagePathDecision::Exclude`]；
/// 在模块或清单引用场景中返回错误。大小写别名、尾随点/空格以及非 UTF-8
/// 名称在所有场景中都硬拒绝，保证行为不依赖当前宿主平台。
#[doc(hidden)]
pub fn package_path_decision(
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<PackagePathDecision, PackagePathError> {
    let components = portable_relative_components(relative)?;
    if components.is_empty() {
        return Err(invalid_path_error(relative, "包内路径不得为空"));
    }

    // 先检查全部别名，不能因为祖先恰好会被排除而隐藏不可移植的后代路径。
    for component in &components {
        validate_portable_component(relative, component)?;
    }

    for (index, component) in components.iter().enumerate() {
        if RESERVED_COMPONENTS.contains(&component.as_str()) {
            let reason = PackagePathReason::ReservedComponent {
                component: component.clone(),
            };
            return excluded_or_rejected(relative, purpose, reason, component);
        }
        if component == LOCK_NAME {
            let nested = index != 0 || components.len() != 1;
            return match purpose {
                PackagePathPurpose::TreeChecksum => {
                    Ok(PackagePathDecision::Exclude(PackagePathReason::LockFile {
                        nested,
                    }))
                }
                PackagePathPurpose::YxpEntry if !nested => Ok(PackagePathDecision::Include),
                PackagePathPurpose::YxpEntry => {
                    Ok(PackagePathDecision::Exclude(PackagePathReason::LockFile {
                        nested,
                    }))
                }
                PackagePathPurpose::ModuleSource | PackagePathPurpose::ManifestReference => {
                    Err(reserved_path_error(relative, purpose, component))
                }
            };
        }
    }
    Ok(PackagePathDecision::Include)
}

/// 生成保留原大小写、NFC 规范化并固定使用 `/` 的可序列化包路径。
#[doc(hidden)]
pub fn portable_package_path(path: &Path) -> Result<String, PackagePathError> {
    let components = portable_relative_components(path)?;
    if components.is_empty() {
        return Err(invalid_path_error(path, "包内路径不得为空"));
    }
    components
        .into_iter()
        .map(|component| {
            validate_portable_component(path, &component)?;
            Ok(component.nfc().collect::<String>())
        })
        .collect::<Result<Vec<_>, PackagePathError>>()
        .map(|components| components.join("/"))
}

/// 在交给平台 `Path` 解析前拒绝会被 Windows 当作目录分隔符的原始文本。
#[doc(hidden)]
pub fn validate_portable_path_text(raw: &str) -> Result<(), PackagePathError> {
    if raw.contains('\\') {
        return Err(non_portable_error(
            Path::new(raw),
            raw,
            "使用反斜杠目录分隔符",
        ));
    }
    Ok(())
}

/// 按可移植路径身份解析一个已经存在的包内路径。
///
/// 清单与源码保留作者写下的 Unicode 拼写，而部分文件系统会在创建文件时
/// 自动改用 NFC 或 NFD。本函数逐层枚举真实目录，以 NFC、保留大小写的身份
/// 匹配请求；同时拒绝同层大小写或规范化碰撞、符号链接和越界结果。
#[doc(hidden)]
pub fn resolve_existing_package_path(
    root: &Path,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<PathBuf, PackagePathError> {
    let decision = package_path_decision(relative, purpose)?;
    if !matches!(decision, PackagePathDecision::Include) {
        let component = match decision {
            PackagePathDecision::Exclude(PackagePathReason::ReservedComponent { component }) => {
                component
            }
            PackagePathDecision::Exclude(PackagePathReason::LockFile { .. }) => LOCK_NAME.into(),
            PackagePathDecision::Include => unreachable!(),
        };
        return Err(reserved_path_error(relative, purpose, &component));
    }
    resolve_existing_portable_relative_path_inner(root, relative, Some(purpose))
}

/// 供清单发现复用的逐组件解析；保留路径在成为更深包根前仍可被定位，
/// 但大小写别名、Unicode 碰撞和符号链接仍一律拒绝。
pub(crate) fn resolve_existing_portable_relative_path(
    root: &Path,
    relative: &Path,
) -> Result<PathBuf, PackagePathError> {
    resolve_existing_portable_relative_path_inner(root, relative, None)
}

fn resolve_existing_portable_relative_path_inner(
    root: &Path,
    relative: &Path,
    purpose: Option<PackagePathPurpose>,
) -> Result<PathBuf, PackagePathError> {
    let components = portable_relative_components(relative)?;
    if components.is_empty() {
        return fs::canonicalize(root).map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("不能规范化包根“{}”：{error}。", root.display()),
            path: root.to_path_buf(),
            component: None,
            suggestion: "请确保包根存在、是普通目录且未被替换。".into(),
        });
    }
    for component in &components {
        validate_portable_component(relative, component)?;
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| PackagePathError {
        code: PACKAGE_ROOT_INVALID_CODE,
        message: format!("不能规范化包根“{}”：{error}。", root.display()),
        path: root.to_path_buf(),
        component: None,
        suggestion: "请确保包根存在、是普通目录且未被替换。".into(),
    })?;
    if !canonical_root.is_dir() {
        return Err(PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("包根“{}”不是目录。", root.display()),
            path: root.to_path_buf(),
            component: None,
            suggestion: "请确保包根存在、是普通目录且未被替换。".into(),
        });
    }

    let mut current = canonical_root.clone();
    for (index, component) in components.iter().enumerate() {
        let requested_key = component.nfc().collect::<String>();
        let entries = fs::read_dir(&current).map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "不能枚举包路径“{}”的父目录“{}”：{error}。",
                relative.display(),
                current.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.clone()),
            suggestion: "请确保路径的全部父目录存在且可读取。".into(),
        })?;
        let mut identities = PortablePackagePaths::default();
        let mut selected = None;
        let mut folded_match = None;
        for entry in entries {
            let entry = entry.map_err(|error| PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!("不能读取包目录“{}”中的目录项：{error}。", current.display()),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请确保包目录在解析期间保持稳定且可读取。".into(),
            })?;
            let name = PathBuf::from(entry.file_name());
            let file_type = entry.file_type().map_err(|error| PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!("不能检查包目录项“{}”：{error}。", entry.path().display()),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请确保包目录在解析期间保持稳定且可读取。".into(),
            })?;
            if file_type.is_dir() {
                identities.insert_directory(&name)?;
            } else {
                identities.insert(&name)?;
            }
            let portable_name = portable_package_path(&name)?;
            if portable_case_fold(&portable_name) == portable_case_fold(&requested_key) {
                folded_match = Some(entry.path());
            }
            if portable_name == requested_key {
                selected = Some(entry.path());
            }
        }
        let Some(candidate) = selected else {
            if let Some(alias) = folded_match {
                return Err(non_portable_error(
                    relative,
                    component,
                    &format!(
                        "与实盘名称“{}”仅大小写不同",
                        alias.file_name().unwrap_or_default().to_string_lossy()
                    ),
                ));
            }
            return Err(PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!("包路径“{}”的组件“{component}”不存在。", relative.display()),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请确认清单或导入路径与包内文件一致。".into(),
            });
        };
        let metadata = fs::symlink_metadata(&candidate).map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能检查包路径“{}”：{error}。", candidate.display()),
            path: relative.to_path_buf(),
            component: Some(component.clone()),
            suggestion: "请确保包路径在解析期间保持稳定。".into(),
        })?;
        if metadata.file_type().is_symlink() {
            if let Ok(target) = fs::canonicalize(&candidate) {
                if let Ok(target_relative) = target.strip_prefix(&canonical_root) {
                    if !target_relative.as_os_str().is_empty()
                        && let Some(purpose) = purpose
                        && let Err(error) = package_path_decision(target_relative, purpose)
                    {
                        return Err(error);
                    }
                } else {
                    return Err(PackagePathError {
                        code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
                        message: format!(
                            "包路径“{}”不得为符号链接；其目标越出包根。",
                            relative.display()
                        ),
                        path: relative.to_path_buf(),
                        component: Some(component.clone()),
                        suggestion: "请移除越界符号链接并将内容保留在所属包根内。".into(),
                    });
                }
            }
            return Err(PackagePathError {
                code: if purpose == Some(PackagePathPurpose::ModuleSource) {
                    PACKAGE_MODULE_OUTSIDE_ROOT_CODE
                } else {
                    PACKAGE_PATH_INVALID_CODE
                },
                message: format!(
                    "包路径“{}”不得为符号链接或经过符号链接。",
                    relative.display()
                ),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请移除符号链接并使用包根内的真实文件或目录。".into(),
            });
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!(
                    "包路径“{}”的中间组件“{component}”不是目录。",
                    relative.display()
                ),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请修正清单或导入路径。".into(),
            });
        }
        current = candidate;
    }

    let canonical = fs::canonicalize(&current).map_err(|error| PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("不能规范化包路径“{}”：{error}。", relative.display()),
        path: relative.to_path_buf(),
        component: None,
        suggestion: "请确保包路径在解析期间保持稳定。".into(),
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(PackagePathError {
            code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
            message: format!("包路径“{}”解析后越出包根。", relative.display()),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请移除路径重定向并将内容保留在所属包根内。".into(),
        });
    }
    Ok(canonical)
}

/// 一次树遍历或归档消费中的可移植路径身份集合。
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct PortablePackagePaths {
    paths: BTreeMap<String, PortablePackagePathRecord>,
}

#[derive(Debug)]
struct PortablePackagePathRecord {
    original: PathBuf,
    terminal: bool,
    directory: bool,
}

impl PortablePackagePaths {
    pub fn insert(&mut self, path: &Path) -> Result<(), PackagePathError> {
        self.insert_kind(path, false)
    }

    pub fn insert_directory(&mut self, path: &Path) -> Result<(), PackagePathError> {
        self.insert_kind(path, true)
    }

    fn insert_kind(&mut self, path: &Path, directory: bool) -> Result<(), PackagePathError> {
        let components = portable_relative_components(path)?;
        if components.is_empty() {
            return Err(invalid_path_error(path, "包内路径不得为空"));
        }
        let component_count = components.len();
        let mut key_components = Vec::with_capacity(component_count);
        let mut original = PathBuf::new();
        for (index, component) in components.into_iter().enumerate() {
            validate_portable_component(path, &component)?;
            key_components.push(portable_case_fold(&component));
            original.push(&component);
            let key = key_components.join("/");
            let terminal = index + 1 == component_count;
            if let Some(previous) = self.paths.get_mut(&key) {
                let same_spelling = previous.original == original;
                if same_spelling && !terminal && (!previous.terminal || previous.directory) {
                    continue;
                }
                if same_spelling && terminal && !previous.terminal && directory {
                    previous.terminal = true;
                    previous.directory = true;
                    continue;
                }
                return Err(PackagePathError {
                    code: PACKAGE_PATH_COLLISION_CODE,
                    message: format!(
                        "包路径“{}”与“{}”的路径身份在 Unicode NFC 与大小写折叠后相同。",
                        previous.original.display(),
                        original.display()
                    ),
                    path: path.to_path_buf(),
                    component: None,
                    suggestion: "请重命名其中一个路径，使其全部祖先在所有受支持平台上保持唯一。"
                        .into(),
                });
            }
            self.paths.insert(
                key,
                PortablePackagePathRecord {
                    original: original.clone(),
                    terminal,
                    directory: !terminal || directory,
                },
            );
        }
        Ok(())
    }
}

pub(crate) fn portable_case_fold(component: &str) -> String {
    component
        .nfc()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .nfc()
        .collect()
}

fn excluded_or_rejected(
    path: &Path,
    purpose: PackagePathPurpose,
    reason: PackagePathReason,
    component: &str,
) -> Result<PackagePathDecision, PackagePathError> {
    match purpose {
        PackagePathPurpose::TreeChecksum | PackagePathPurpose::YxpEntry => {
            Ok(PackagePathDecision::Exclude(reason))
        }
        PackagePathPurpose::ModuleSource | PackagePathPurpose::ManifestReference => {
            Err(reserved_path_error(path, purpose, component))
        }
    }
}

fn portable_relative_components(path: &Path) -> Result<Vec<String>, PackagePathError> {
    if path.is_absolute() {
        return Err(invalid_path_error(path, "包内路径必须相对包根"));
    }
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                let component = component.to_str().ok_or_else(|| PackagePathError {
                    code: PACKAGE_PATH_NON_PORTABLE_CODE,
                    message: format!("包路径“{}”包含非 UTF-8 名称。", path.display()),
                    path: path.to_path_buf(),
                    component: None,
                    suggestion: NON_PORTABLE_SUGGESTION.into(),
                })?;
                result.push(component.to_owned());
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_path_error(
                    path,
                    "包内路径不得包含父目录、根目录或平台前缀",
                ));
            }
        }
    }
    Ok(result)
}

pub(crate) fn validate_portable_component(
    path: &Path,
    component: &str,
) -> Result<(), PackagePathError> {
    if component.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    }) {
        return Err(non_portable_error(
            path,
            component,
            "包含 Windows 不允许的符号、目录分隔符或控制字符",
        ));
    }
    if component.ends_with(['.', ' ']) {
        return Err(non_portable_error(
            path,
            component,
            "以 Windows 会忽略的点或空格结尾",
        ));
    }

    let folded_component = portable_case_fold(component);
    if RESERVED_COMPONENTS
        .iter()
        .chain(std::iter::once(&LOCK_NAME))
        .any(|reserved| component != *reserved && folded_component == portable_case_fold(reserved))
    {
        return Err(non_portable_error(
            path,
            component,
            "是保留路径名称的非规范大小写别名",
        ));
    }
    let device_stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem);
    let uppercase = device_stem
        .trim_end_matches(['.', ' '])
        .to_ascii_uppercase();
    let numbered_device = uppercase
        .strip_prefix("COM")
        .or_else(|| uppercase.strip_prefix("LPT"))
        .is_some_and(|number| {
            matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if matches!(
        uppercase.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || numbered_device
    {
        return Err(non_portable_error(
            path,
            component,
            "使用 Windows 保留设备名",
        ));
    }
    Ok(())
}

fn invalid_path_error(path: &Path, detail: &str) -> PackagePathError {
    PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("包路径“{}”不规范：{detail}。", path.display()),
        path: path.to_path_buf(),
        component: None,
        suggestion: "请改用规范的包根相对路径。".into(),
    }
}

fn non_portable_error(path: &Path, component: &str, detail: &str) -> PackagePathError {
    PackagePathError {
        code: PACKAGE_PATH_NON_PORTABLE_CODE,
        message: format!(
            "包路径“{}”的组件“{component}”不可跨平台使用：{detail}。",
            path.display()
        ),
        path: path.to_path_buf(),
        component: Some(component.into()),
        suggestion: NON_PORTABLE_SUGGESTION.into(),
    }
}

fn reserved_path_error(
    path: &Path,
    purpose: PackagePathPurpose,
    component: &str,
) -> PackagePathError {
    let module = purpose == PackagePathPurpose::ModuleSource;
    PackagePathError {
        code: if module {
            PACKAGE_MODULE_RESERVED_PATH_CODE
        } else {
            PACKAGE_PATH_RESERVED_CODE
        },
        message: if module {
            format!(
                "包内模块“{}”命中保留路径组件“{component}”；该内容不属于经过锁定与打包校验的可执行源码。",
                path.display()
            )
        } else {
            format!(
                "包清单路径“{}”命中保留路径组件“{component}”；该内容不属于可发布包内容。",
                path.display()
            )
        },
        path: path.to_path_buf(),
        component: Some(component.into()),
        suggestion: RESERVED_MODULE_SUGGESTION.into(),
    }
}

/// 模块是否位于已完成锁定与内容校验的包中。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ModuleAuthority {
    External,
    VerifiedPackageContent,
}

/// 安全解析完成后持有最终普通文件句柄的内部令牌。
///
/// 调用方必须从该句柄读取，不能根据 [`Self::path`] 再次打开文件。路径只用于
/// 模块身份、诊断和相对导入基准；即使祖先目录随后被同名替换，句柄仍绑定
/// 解析阶段选中的对象。
#[derive(Debug)]
#[doc(hidden)]
pub struct ResolvedPackageFile {
    path: PathBuf,
    file: fs::File,
}

/// 工具目录发现阶段绑定的普通模块文件身份。
///
/// 令牌只保存稳定根能力、相对路径与平台文件身份，不长期占用每个源码文件的
/// 描述符。读取前必须调用 [`Self::open`]；若目录项在发现后被同名替换，打开
/// 会失败而不会读取替换内容。
#[derive(Debug)]
#[doc(hidden)]
pub struct ResolvedPackageFileSnapshot {
    path: PathBuf,
    portable_key: String,
    roots: Arc<TrustedPackageRoots>,
    identity: ResolvedFileIdentity,
}

/// 从已打开目录能力取得的一项稳定、可移植目录快照。
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ResolvedPackageDirectoryEntry {
    pub name: String,
    pub is_directory: bool,
}

#[cfg(not(target_os = "wasi"))]
#[derive(Debug, Clone)]
struct CapabilityPackageDirectoryEntry {
    name: PathBuf,
    is_directory: bool,
    is_file: bool,
    is_symlink: bool,
}

/// WASI 受信包目录能力。环境路径只在建立根能力时使用；此后全部操作都相对
/// 已打开的目录描述符执行。
#[cfg(target_os = "wasi")]
#[derive(Debug, Clone)]
pub(crate) struct WasiPackageDirectory {
    directory: Arc<Mutex<RustixDir>>,
    identity: (u64, u64),
}

#[cfg(target_os = "wasi")]
#[derive(Debug)]
pub(crate) enum WasiPackageEntry {
    Directory(WasiPackageDirectory),
    File(fs::File),
}

#[cfg(target_os = "wasi")]
#[derive(Debug, Clone)]
pub(crate) struct WasiPackageDirectoryEntry {
    name: PathBuf,
    file_type: RustixFileType,
}

#[cfg(target_os = "wasi")]
impl WasiPackageDirectoryEntry {
    pub(crate) fn name(&self) -> &Path {
        &self.name
    }
}

#[cfg(target_os = "wasi")]
impl WasiPackageDirectory {
    fn open_ambient(path: &Path, follow_final_symlink: bool) -> io::Result<Self> {
        let mut flags = OFlags::RDONLY | OFlags::DIRECTORY;
        if !follow_final_symlink {
            flags |= OFlags::NOFOLLOW;
        }
        openat(rustix::fs::CWD, path, flags, Mode::empty())
            .map_err(io::Error::from)
            .and_then(Self::from_opened_directory)
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    pub(crate) fn open_dir_nofollow(&self, entry: &WasiPackageDirectoryEntry) -> io::Result<Self> {
        if entry.file_type != RustixFileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包目录项的枚举类型不是目录",
            ));
        }
        let directory = self.lock_directory()?;
        self.verify_binding(&directory)?;
        let descriptor = directory.fd().map_err(io::Error::from)?;
        Self::require_not_symlink(descriptor, &entry.name)?;
        let before =
            statat(descriptor, &entry.name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        let before_identity = Self::required_identity(
            &before,
            RustixFileType::Directory,
            "包目录不是目录、是链接或身份不可验证",
        )?;
        let descriptor = openat(
            descriptor,
            &entry.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let opened = Self::from_opened_directory(descriptor)?;
        let after = statat(
            directory.fd().map_err(io::Error::from)?,
            &entry.name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let after_identity = Self::required_identity(
            &after,
            RustixFileType::Directory,
            "包目录不是目录、是链接或身份不可验证",
        )?;
        self.verify_binding(&directory)?;
        if before_identity != opened.identity || after_identity != opened.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包目录在打开期间被替换",
            ));
        }
        Ok(opened)
    }

    pub(crate) fn open_file_nofollow(
        &self,
        entry: &WasiPackageDirectoryEntry,
    ) -> io::Result<fs::File> {
        if entry.file_type != RustixFileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包文件的枚举类型不是普通文件",
            ));
        }
        let directory = self.lock_directory()?;
        self.verify_binding(&directory)?;
        let descriptor = directory.fd().map_err(io::Error::from)?;
        Self::require_not_symlink(descriptor, &entry.name)?;
        let before =
            statat(descriptor, &entry.name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        let before_identity = Self::required_identity(
            &before,
            RustixFileType::RegularFile,
            "包文件不是普通文件、是链接或身份不可验证",
        )?;
        let descriptor = openat(
            descriptor,
            &entry.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let metadata = fstat(&descriptor).map_err(io::Error::from)?;
        let opened_identity = Self::required_identity(
            &metadata,
            RustixFileType::RegularFile,
            "包文件不是普通文件、是链接或身份不可验证",
        )?;
        let after = statat(
            directory.fd().map_err(io::Error::from)?,
            &entry.name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let after_identity = Self::required_identity(
            &after,
            RustixFileType::RegularFile,
            "包文件不是普通文件、是链接或身份不可验证",
        )?;
        self.verify_binding(&directory)?;
        if before_identity != opened_identity || after_identity != opened_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包文件在打开期间被替换",
            ));
        }
        Ok(descriptor.into())
    }

    pub(crate) fn open_entry_nofollow(
        &self,
        entry: &WasiPackageDirectoryEntry,
    ) -> io::Result<WasiPackageEntry> {
        match entry.file_type {
            RustixFileType::Directory => self
                .open_dir_nofollow(entry)
                .map(WasiPackageEntry::Directory),
            RustixFileType::RegularFile => {
                self.open_file_nofollow(entry).map(WasiPackageEntry::File)
            }
            RustixFileType::Symlink => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包目录项不得为符号链接",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包目录项不得为未知类型或特殊文件",
            )),
        }
    }

    pub(crate) fn entries(&self, max_entries: usize) -> io::Result<Vec<WasiPackageDirectoryEntry>> {
        let mut directory = self.lock_directory()?;
        self.verify_binding(&directory)?;
        directory.rewind();
        let mut names = Vec::new();
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(io::Error::from)?;
            let name = entry.file_name().to_str().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "包目录项名称不是 UTF-8")
            })?;
            if name == "." || name == ".." {
                continue;
            }
            if names.len() >= max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("包目录项不得超过 {max_entries} 个"),
                ));
            }
            let mut file_type = entry.file_type();
            if file_type == RustixFileType::Unknown {
                let metadata = statat(
                    directory.fd().map_err(io::Error::from)?,
                    Path::new(name),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(io::Error::from)?;
                file_type = RustixFileType::from_raw_mode(metadata.st_mode);
                if file_type == RustixFileType::Unknown
                    || metadata.st_dev == 0
                    || metadata.st_ino == 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "WASI 宿主不能可靠分类包目录项",
                    ));
                }
            }
            names.push(WasiPackageDirectoryEntry {
                name: PathBuf::from(name),
                file_type,
            });
        }
        self.verify_binding(&directory)?;
        names.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(names)
    }

    fn from_opened_directory(descriptor: rustix::fd::OwnedFd) -> io::Result<Self> {
        let metadata = fstat(&descriptor).map_err(io::Error::from)?;
        let identity = Self::directory_identity(&metadata)?;
        let directory = RustixDir::new(descriptor).map_err(io::Error::from)?;
        let result = Self {
            directory: Arc::new(Mutex::new(directory)),
            identity,
        };
        {
            let directory = result.lock_directory()?;
            result.verify_binding(&directory)?;
        }
        Ok(result)
    }

    fn stable_identity(&self) -> io::Result<(u64, u64)> {
        let directory = self.lock_directory()?;
        self.verify_binding(&directory)?;
        Ok(self.identity)
    }

    fn directory_identity(metadata: &rustix::fs::Stat) -> io::Result<(u64, u64)> {
        Self::required_identity(
            metadata,
            RustixFileType::Directory,
            "可信包根不是目录或身份不可验证",
        )
    }

    fn required_identity(
        metadata: &rustix::fs::Stat,
        expected_type: RustixFileType,
        message: &str,
    ) -> io::Result<(u64, u64)> {
        if RustixFileType::from_raw_mode(metadata.st_mode) != expected_type {
            return Err(io::Error::new(io::ErrorKind::InvalidData, message));
        }
        let device = metadata.st_dev;
        let inode = metadata.st_ino;
        if device == 0 || inode == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WASI 宿主未提供非零设备号与索引号",
            ));
        }
        Ok((device, inode))
    }

    fn verify_binding(&self, directory: &RustixDir) -> io::Result<()> {
        let descriptor_identity =
            Self::directory_identity(&directory.stat().map_err(io::Error::from)?)?;
        let relative_identity = Self::directory_identity(
            &statat(
                directory.fd().map_err(io::Error::from)?,
                Path::new("."),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?,
        )?;
        if descriptor_identity != self.identity || relative_identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WASI 宿主目录描述符绑定发生漂移",
            ));
        }
        Ok(())
    }

    fn require_not_symlink(directory: rustix::fd::BorrowedFd<'_>, name: &Path) -> io::Result<()> {
        match readlinkat(directory, name, Vec::new()) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "包目录项不得为符号链接",
            )),
            Err(error) if error == rustix::io::Errno::INVAL => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    fn lock_directory(&self) -> io::Result<std::sync::MutexGuard<'_, RustixDir>> {
        self.directory
            .lock()
            .map_err(|_| io::Error::other("WASI 包目录句柄锁已中毒"))
    }
}

impl ResolvedPackageFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    pub(crate) fn new(path: PathBuf, file: fs::File) -> Self {
        Self { path, file }
    }

    #[doc(hidden)]
    pub fn into_file(self) -> fs::File {
        self.file
    }
}

#[cfg(all(unix, not(target_os = "wasi")))]
type ResolvedFileIdentity = (u64, u64);
#[cfg(windows)]
type ResolvedFileIdentity = (u64, [u8; 16]);
#[cfg(target_os = "wasi")]
type ResolvedFileIdentity = (u64, u64);
#[cfg(not(any(unix, windows, target_os = "wasi")))]
type ResolvedFileIdentity = ();

#[cfg(all(unix, not(target_os = "wasi")))]
fn resolved_file_identity(file: &fs::File) -> io::Result<ResolvedFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.dev() == 0 || metadata.ino() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "宿主未提供可验证的普通文件身份",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn resolved_file_identity(file: &fs::File) -> io::Result<ResolvedFileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = MaybeUninit::<FILE_ID_INFO>::zeroed();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

#[cfg(target_os = "wasi")]
fn resolved_file_identity(file: &fs::File) -> io::Result<ResolvedFileIdentity> {
    let metadata = fstat(file).map_err(io::Error::from)?;
    WasiPackageDirectory::required_identity(
        &metadata,
        RustixFileType::RegularFile,
        "模块源码必须是身份可验证的普通文件",
    )
}

#[cfg(not(any(unix, windows, target_os = "wasi")))]
fn resolved_file_identity(_file: &fs::File) -> io::Result<ResolvedFileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "当前宿主不能提供稳定普通文件身份",
    ))
}

impl ResolvedPackageFileSnapshot {
    fn new(
        path: PathBuf,
        portable_key: String,
        roots: Arc<TrustedPackageRoots>,
        file: &fs::File,
    ) -> Result<Self, PackagePathError> {
        let identity = resolved_file_identity(file).map_err(|error| {
            invalid_path_error(&path, &format!("不能记录工具模块文件身份：{error}"))
        })?;
        Ok(Self {
            path,
            portable_key,
            roots,
            identity,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 复制发现阶段已经打开的根集合，供后续导入继续使用同一批目录能力。
    #[doc(hidden)]
    pub fn opened_roots(&self) -> TrustedPackageRoots {
        self.roots.as_ref().clone()
    }

    /// 从发现阶段的同一根能力重新打开文件，并拒绝任何对象身份漂移。
    #[doc(hidden)]
    pub fn open(self) -> Result<ResolvedPackageFile, PackagePathError> {
        let resolved = self
            .roots
            .resolve_existing_module_file(&self.path)?
            .ok_or_else(|| invalid_path_error(&self.path, "工具模块不属于发现阶段的根能力"))?;
        let identity = resolved_file_identity(&resolved.file).map_err(|error| {
            invalid_path_error(&self.path, &format!("不能复验工具模块文件身份：{error}"))
        })?;
        if identity != self.identity {
            return Err(invalid_path_error(
                &self.path,
                "模块文件在目录发现后被同名替换",
            ));
        }
        Ok(resolved)
    }
}

impl ModuleAuthority {
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::VerifiedPackageContent)
    }
}

/// 一次依赖解析所得的规范包根集合。
///
/// 根按组件深度从深到浅排列。一个依赖根位于应用的 `vendor/` 内时，模块会
/// 相对该依赖根判断，而不会因应用根下的 `vendor` 组件被误拒。
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct TrustedPackageRoots {
    roots: Vec<TrustedPackageRoot>,
}

#[derive(Debug, Clone)]
struct TrustedPackageRoot {
    canonical: PathBuf,
    aliases: Vec<PathBuf>,
    #[cfg(not(target_os = "wasi"))]
    directory: Arc<cap_std::fs::Dir>,
    #[cfg(target_os = "wasi")]
    directory: WasiPackageDirectory,
}

#[derive(Clone, Copy)]
struct TrustedRootMatch<'a> {
    prefix: &'a Path,
    identity: &'a Path,
    #[cfg(not(target_os = "wasi"))]
    directory: &'a cap_std::fs::Dir,
    #[cfg(target_os = "wasi")]
    directory: &'a WasiPackageDirectory,
}

impl TrustedPackageRoots {
    pub fn new() -> Self {
        Self::default()
    }

    /// 规范化、校验并加入一个可信包根；同一规范根只保留一次。
    pub fn insert(&mut self, root: impl AsRef<Path>) -> Result<(), PackagePathError> {
        let root = root.as_ref();
        let (absolute, lexical) = ambient_root_paths(root)?;
        #[cfg(not(target_os = "wasi"))]
        let directory = cap_std::fs::Dir::open_ambient_dir(&absolute, cap_std::ambient_authority())
            .map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能打开可信包根“{}”：{error}。", root.display()),
                path: root.to_path_buf(),
                component: None,
                suggestion: "请确保依赖解析得到的包根存在且可读取。".into(),
            })?;
        #[cfg(target_os = "wasi")]
        let directory = WasiPackageDirectory::open_ambient(&absolute, true).map_err(|error| {
            PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能打开可信包根“{}”：{error}。", root.display()),
                path: root.to_path_buf(),
                component: None,
                suggestion: "请确保依赖解析得到的包根存在且可读取。".into(),
            }
        })?;
        let canonical = fs::canonicalize(&absolute).map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("不能规范化可信包根“{}”：{error}。", root.display()),
            path: root.to_path_buf(),
            component: None,
            suggestion: "请确保依赖解析得到的包根存在且为真实目录。".into(),
        })?;
        #[cfg(not(target_os = "wasi"))]
        {
            let canonical_directory =
                cap_std::fs::Dir::open_ambient_dir(&canonical, cap_std::ambient_authority())
                    .map_err(|error| PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!("不能复验可信包根“{}”：{error}。", root.display()),
                        path: root.to_path_buf(),
                        component: None,
                        suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                    })?;
            let opened = directory.dir_metadata().map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能检查可信包根“{}”：{error}。", root.display()),
                path: root.to_path_buf(),
                component: None,
                suggestion: "请确保依赖解析得到的包根存在且为真实目录。".into(),
            })?;
            let stable = same_opened_directory_identity(&directory, &canonical_directory).map_err(
                |error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("不能复验可信包根“{}”的身份：{error}。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                },
            )?;
            if !opened.is_dir() || !stable {
                return Err(PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("可信包根“{}”不是稳定的真实目录。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                });
            }
        }
        #[cfg(target_os = "wasi")]
        {
            let canonical_directory = WasiPackageDirectory::open_ambient(&canonical, false)
                .map_err(|error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("不能复验可信包根“{}”：{error}。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                })?;
            let opened_identity =
                directory
                    .stable_identity()
                    .map_err(|error| PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!("不能识别可信包根“{}”：{error}。", root.display()),
                        path: root.to_path_buf(),
                        component: None,
                        suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                    })?;
            let canonical_identity =
                canonical_directory
                    .stable_identity()
                    .map_err(|error| PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!("不能复验可信包根“{}”的身份：{error}。", root.display()),
                        path: root.to_path_buf(),
                        component: None,
                        suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                    })?;
            if opened_identity != canonical_identity {
                return Err(PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("可信包根“{}”在解析期间改变了身份。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                });
            }
        }
        if let Some(existing) = self
            .roots
            .iter_mut()
            .find(|existing| existing.canonical == canonical)
        {
            #[cfg(not(target_os = "wasi"))]
            if !same_opened_directory_identity(&directory, existing.directory.as_ref()).map_err(
                |error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("不能复验既有可信包根“{}”：{error}。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请确保依赖解析期间包根没有被替换。".into(),
                },
            )? {
                return Err(PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("可信包根“{}”已被同名目录替换。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请重新执行依赖解析并建立新的可信根集合。".into(),
                });
            }
            #[cfg(target_os = "wasi")]
            if directory
                .stable_identity()
                .map_err(|error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("不能识别重新打开的可信包根“{}”：{error}。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                })?
                != existing
                    .directory
                    .stable_identity()
                    .map_err(|error| PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!("不能复验既有可信包根“{}”：{error}。", root.display()),
                        path: root.to_path_buf(),
                        component: None,
                        suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                    })?
            {
                return Err(PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!("可信包根“{}”已被同名目录替换。", root.display()),
                    path: root.to_path_buf(),
                    component: None,
                    suggestion: "请重新执行依赖解析并建立新的可信根集合。".into(),
                });
            }
            if lexical != canonical && !existing.aliases.contains(&lexical) {
                existing.aliases.push(lexical);
            }
        } else {
            let aliases = (lexical != canonical)
                .then_some(lexical)
                .into_iter()
                .collect();
            self.roots.push(TrustedPackageRoot {
                canonical,
                aliases,
                #[cfg(not(target_os = "wasi"))]
                directory: Arc::new(directory),
                #[cfg(target_os = "wasi")]
                directory,
            });
        }
        Ok(())
    }

    /// 仅当别名当前仍指向既有可信根时记录其词法前缀。
    #[doc(hidden)]
    pub fn insert_alias(
        &mut self,
        alias: impl AsRef<Path>,
        expected_root: impl AsRef<Path>,
    ) -> Result<(), PackagePathError> {
        let alias = alias.as_ref();
        let expected_root =
            fs::canonicalize(expected_root.as_ref()).map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "不能复验可信包根“{}”：{error}。",
                    expected_root.as_ref().display()
                ),
                path: expected_root.as_ref().to_path_buf(),
                component: None,
                suggestion: "请确保发现的包根没有被替换。".into(),
            })?;
        let mut candidate = Self::default();
        candidate.insert(alias)?;
        let candidate = candidate
            .roots
            .pop()
            .expect("successful root insertion records one root");
        if candidate.canonical != expected_root {
            return Err(PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "包根别名“{}”不再指向预期目录“{}”。",
                    alias.display(),
                    expected_root.display()
                ),
                path: alias.to_path_buf(),
                component: None,
                suggestion: "请确保包发现期间目录没有被重命名或替换。".into(),
            });
        }
        let existing = self
            .roots
            .iter_mut()
            .find(|root| root.canonical == expected_root)
            .ok_or_else(|| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "预期可信包根“{}”尚未加入授权集合。",
                    expected_root.display()
                ),
                path: expected_root.clone(),
                component: None,
                suggestion: "请先加入规范包根，再记录其词法别名。".into(),
            })?;
        #[cfg(not(target_os = "wasi"))]
        if !same_opened_directory_identity(
            candidate.directory.as_ref(),
            existing.directory.as_ref(),
        )
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("不能复验包根别名“{}”的身份：{error}。", alias.display()),
            path: alias.to_path_buf(),
            component: None,
            suggestion: "请确保包发现期间目录没有被重命名或替换。".into(),
        })? {
            return Err(PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "包根别名“{}”与预期目录“{}”的身份不同。",
                    alias.display(),
                    expected_root.display()
                ),
                path: alias.to_path_buf(),
                component: None,
                suggestion: "请确保包发现期间目录没有被重命名或替换。".into(),
            });
        }
        #[cfg(target_os = "wasi")]
        if candidate
            .directory
            .stable_identity()
            .map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能识别包根别名“{}”：{error}。", alias.display()),
                path: alias.to_path_buf(),
                component: None,
                suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
            })?
            != existing
                .directory
                .stable_identity()
                .map_err(|error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!(
                        "不能复验预期可信包根“{}”：{error}。",
                        expected_root.display()
                    ),
                    path: expected_root.clone(),
                    component: None,
                    suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                })?
        {
            return Err(PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "包根别名“{}”与预期目录“{}”的身份不同。",
                    alias.display(),
                    expected_root.display()
                ),
                path: alias.to_path_buf(),
                component: None,
                suggestion: "请确保包发现期间目录没有被重命名或替换。".into(),
            });
        }
        for alias in candidate.aliases {
            if !existing.aliases.contains(&alias) {
                existing.aliases.push(alias);
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn roots(&self) -> impl Iterator<Item = &Path> {
        self.roots.iter().map(|root| root.canonical.as_path())
    }

    /// 合并另一组已经打开并验证过的根能力，不再根据路径重新打开目录。
    #[doc(hidden)]
    pub fn extend_opened(&mut self, other: &Self) -> Result<(), PackagePathError> {
        for candidate in &other.roots {
            if let Some(existing) = self
                .roots
                .iter_mut()
                .find(|existing| existing.canonical == candidate.canonical)
            {
                #[cfg(not(target_os = "wasi"))]
                let same = same_opened_directory_identity(
                    existing.directory.as_ref(),
                    candidate.directory.as_ref(),
                )
                .map_err(|error| PackagePathError {
                    code: PACKAGE_ROOT_INVALID_CODE,
                    message: format!(
                        "不能合并可信包根“{}”的目录能力：{error}。",
                        candidate.canonical.display()
                    ),
                    path: candidate.canonical.clone(),
                    component: None,
                    suggestion: "请重新执行依赖解析并建立单一内容 generation。".into(),
                })?;
                #[cfg(target_os = "wasi")]
                let same = existing
                    .directory
                    .stable_identity()
                    .and_then(|existing| {
                        candidate
                            .directory
                            .stable_identity()
                            .map(|candidate| existing == candidate)
                    })
                    .map_err(|error| PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!(
                            "不能合并可信包根“{}”的目录能力：{error}。",
                            candidate.canonical.display()
                        ),
                        path: candidate.canonical.clone(),
                        component: None,
                        suggestion: "请使用能够提供稳定目录身份的 WASI 宿主。".into(),
                    })?;
                if !same {
                    return Err(PackagePathError {
                        code: PACKAGE_ROOT_INVALID_CODE,
                        message: format!(
                            "可信包根“{}”对应两个不同的目录 generation。",
                            candidate.canonical.display()
                        ),
                        path: candidate.canonical.clone(),
                        component: None,
                        suggestion: "请终止当前操作并从新的依赖解析会话重试。".into(),
                    });
                }
                for alias in &candidate.aliases {
                    if !existing.aliases.contains(alias) {
                        existing.aliases.push(alias.clone());
                    }
                }
                continue;
            }
            self.roots.push(candidate.clone());
        }
        self.roots.sort_by(|left, right| {
            right
                .canonical
                .components()
                .count()
                .cmp(&left.canonical.components().count())
                .then_with(|| left.canonical.cmp(&right.canonical))
        });
        Ok(())
    }

    /// 重新按当前路径打开根目录，并与保存的目录身份比较。
    #[doc(hidden)]
    pub fn revalidate_exact_root(&self, root: &Path) -> Result<bool, PackagePathError> {
        let Some(expected) = self.exact_root_identity(root).map(Path::to_path_buf) else {
            return Ok(false);
        };
        let mut probe = self.clone();
        if probe.insert(root).is_err() {
            return Ok(false);
        }
        Ok(probe.len() == self.len()
            && probe
                .exact_root_identity(root)
                .is_some_and(|current| current == expected))
    }

    pub(crate) fn exact_root_identity(&self, root: &Path) -> Option<&Path> {
        let (_, root) = ambient_root_paths(root).ok()?;
        self.roots
            .iter()
            .find(|candidate| {
                candidate.canonical == root || candidate.aliases.iter().any(|alias| alias == &root)
            })
            .map(|root| root.canonical.as_path())
    }

    #[cfg(not(target_os = "wasi"))]
    pub(crate) fn clone_exact_root_directory(
        &self,
        root: &Path,
    ) -> io::Result<Option<cap_std::fs::Dir>> {
        let (_, root) = ambient_root_paths(root).map_err(io::Error::other)?;
        let Some(root) = self.roots.iter().find(|candidate| {
            candidate.canonical == root || candidate.aliases.iter().any(|alias| alias == &root)
        }) else {
            return Ok(None);
        };
        root.directory.try_clone().map(Some)
    }

    #[cfg(target_os = "wasi")]
    pub(crate) fn clone_exact_root_directory(
        &self,
        root: &Path,
    ) -> io::Result<Option<WasiPackageDirectory>> {
        let (_, root) = ambient_root_paths(root).map_err(io::Error::other)?;
        let Some(root) = self.roots.iter().find(|candidate| {
            candidate.canonical == root || candidate.aliases.iter().any(|alias| alias == &root)
        }) else {
            return Ok(None);
        };
        root.directory.try_clone().map(Some)
    }

    /// 返回包含路径的最深可信包根。
    pub fn matching_root(&self, path: &Path) -> Option<&Path> {
        let path = lexical_absolute(path).ok()?;
        self.matching(&path).map(|matched| matched.prefix)
    }

    /// 返回包含路径的最深可信包根在打开时保存的规范身份，不根据环境路径重新解析。
    pub(crate) fn matching_root_identity(&self, path: &Path) -> Option<&Path> {
        let path = lexical_absolute(path).ok()?;
        self.matching(&path).map(|matched| matched.identity)
    }

    /// 若请求落在可信包根内，按可移植身份解析真实模块路径。
    /// 包外路径返回 `None`，由调用方沿用普通文件系统解析语义。
    /// 各平台都会通过保存的根能力绑定并复验最终文件或目录；返回路径只用于
    /// 身份与诊断，读取文件必须改用 [`Self::resolve_existing_module_file`]，枚举
    /// 目录必须改用 [`Self::list_existing_directory`]。
    #[doc(hidden)]
    pub fn resolve_existing_module_path(
        &self,
        requested_or_joined: &Path,
    ) -> Result<Option<PathBuf>, PackagePathError> {
        self.resolve_existing_path(requested_or_joined, PackagePathPurpose::ModuleSource)
            .map(|resolved| resolved.map(|(path, _)| path))
    }

    /// 在可信包根内逐组件绑定现有文件或目录，并返回实际可移植拼写和类型。
    /// 返回的路径只可用于身份与诊断；读取和枚举仍须使用保存的根能力。
    #[doc(hidden)]
    pub fn resolve_existing_path(
        &self,
        requested_or_joined: &Path,
        purpose: PackagePathPurpose,
    ) -> Result<Option<(PathBuf, bool)>, PackagePathError> {
        if self.roots.is_empty() {
            return Ok(None);
        }
        let requested = lexical_absolute(requested_or_joined)?;
        let Some(root) = self.matching(&requested) else {
            return Ok(None);
        };
        let relative = requested
            .strip_prefix(root.prefix)
            .expect("matching root is a path prefix");
        #[cfg(not(target_os = "wasi"))]
        {
            resolve_capability_package_path_from_root(root, relative, purpose).map(Some)
        }
        #[cfg(target_os = "wasi")]
        {
            resolve_wasi_package_path_from_root(root, relative, purpose).map(Some)
        }
    }

    /// 若模块位于可信包根内，逐组件解析并返回在解析阶段打开的最终句柄。
    /// 包外路径返回 `None`，由调用方建立同样绑定对象身份的外部文件令牌。
    #[doc(hidden)]
    pub fn resolve_existing_module_file(
        &self,
        requested_or_joined: &Path,
    ) -> Result<Option<ResolvedPackageFile>, PackagePathError> {
        self.resolve_existing_file(requested_or_joined, PackagePathPurpose::ModuleSource)
    }

    /// 在可信包根内按指定用途解析并打开一个普通文件。
    #[doc(hidden)]
    pub fn resolve_existing_file(
        &self,
        requested_or_joined: &Path,
        purpose: PackagePathPurpose,
    ) -> Result<Option<ResolvedPackageFile>, PackagePathError> {
        if self.roots.is_empty() {
            return Ok(None);
        }
        let requested = lexical_absolute(requested_or_joined)?;
        let Some(root) = self.matching(&requested) else {
            return Ok(None);
        };
        let relative = requested
            .strip_prefix(root.prefix)
            .expect("matching root is a path prefix");
        resolve_existing_file_from_root(root, relative, purpose).map(Some)
    }

    /// 相对可信根安全打开目录并返回一次目录项快照。
    #[doc(hidden)]
    pub fn list_existing_directory(
        &self,
        requested_or_joined: &Path,
        purpose: PackagePathPurpose,
    ) -> Result<Option<Vec<ResolvedPackageDirectoryEntry>>, PackagePathError> {
        if self.roots.is_empty() {
            return Ok(None);
        }
        let requested = lexical_absolute(requested_or_joined)?;
        let Some(root) = self.matching(&requested) else {
            return Ok(None);
        };
        let relative = requested
            .strip_prefix(root.prefix)
            .expect("matching root is a path prefix");
        list_existing_directory_from_root(root, relative, purpose).map(Some)
    }

    /// 记录一个模块文件的根能力、规范路径和平台对象身份，但不长期保留文件句柄。
    #[doc(hidden)]
    pub fn snapshot_existing_module_file(
        &self,
        requested_or_joined: &Path,
    ) -> Result<Option<ResolvedPackageFileSnapshot>, PackagePathError> {
        let Some(resolved) = self.resolve_existing_module_file(requested_or_joined)? else {
            return Ok(None);
        };
        let path = resolved.path().to_path_buf();
        let requested = lexical_absolute(&path)?;
        let root = self
            .matching(&requested)
            .ok_or_else(|| invalid_path_error(&path, "工具模块不属于已经打开的可信根"))?;
        let relative = requested
            .strip_prefix(root.prefix)
            .expect("matching root is a path prefix");
        let portable_key = portable_package_path(relative)?;
        ResolvedPackageFileSnapshot::new(path, portable_key, Arc::new(self.clone()), &resolved.file)
            .map(Some)
    }

    /// 从同一已打开根目录递归发现模块，并为每个普通文件记录可复验身份。
    #[doc(hidden)]
    pub fn snapshot_module_directory(
        &self,
        requested_or_joined: &Path,
    ) -> Result<Option<Vec<ResolvedPackageFileSnapshot>>, PackagePathError> {
        if self.roots.is_empty() {
            return Ok(None);
        }
        let requested = lexical_absolute(requested_or_joined)?;
        let Some(root) = self.matching(&requested) else {
            return Ok(None);
        };
        let relative = requested
            .strip_prefix(root.prefix)
            .expect("matching root is a path prefix");
        let mut walker = ToolingModuleSnapshotWalker::new(root.identity, Arc::new(self.clone()));
        #[cfg(not(target_os = "wasi"))]
        {
            let (directory, actual_relative) = resolve_capability_package_directory_from_root(
                root,
                relative,
                PackagePathPurpose::YxpEntry,
            )?;
            walker.snapshot_capability_directory(&directory, &actual_relative, 0)?;
        }
        #[cfg(target_os = "wasi")]
        {
            let (directory, actual_relative) = resolve_wasi_package_directory_from_root(
                root,
                relative,
                PackagePathPurpose::YxpEntry,
            )?;
            walker.snapshot_wasi_directory(&directory, &actual_relative, 0)?;
        }
        Ok(Some(walker.finish()))
    }

    fn matching(&self, path: &Path) -> Option<TrustedRootMatch<'_>> {
        self.roots
            .iter()
            .flat_map(|root| {
                std::iter::once(root.canonical.as_path())
                    .chain(root.aliases.iter().map(PathBuf::as_path))
                    .filter(move |prefix| path.starts_with(prefix))
                    .map(move |prefix| TrustedRootMatch {
                        prefix,
                        identity: &root.canonical,
                        #[cfg(not(target_os = "wasi"))]
                        directory: &root.directory,
                        #[cfg(target_os = "wasi")]
                        directory: &root.directory,
                    })
            })
            .max_by(|left, right| {
                left.prefix
                    .components()
                    .count()
                    .cmp(&right.prefix.components().count())
                    .then_with(|| right.prefix.cmp(left.prefix))
            })
    }

    /// 在读取文件或命中模块缓存前授权一个模块路径。
    ///
    /// `requested_or_joined` 是解析导入后、规范化文件系统路径前的连接路径；
    /// `canonical` 是调用方通过 `canonicalize` 得到的最终路径。两者都检查，
    /// 防止显式进入保留目录以及通过别名或符号链接指向保留目录。
    pub fn authorize_module(
        &self,
        requested_or_joined: &Path,
        canonical: &Path,
    ) -> Result<ModuleAuthority, PackagePathError> {
        if self.roots.is_empty() {
            return Ok(ModuleAuthority::External);
        }
        let requested = lexical_absolute(requested_or_joined)?;
        if !canonical.is_absolute() {
            return Err(invalid_path_error(
                canonical,
                "模块的规范路径必须是绝对路径",
            ));
        }

        let requested_root = self.matching(&requested);
        let canonical_root = self.matching(canonical);

        if let Some(root) = requested_root {
            let relative = requested
                .strip_prefix(root.prefix)
                .expect("matching root is a path prefix");
            package_path_decision(relative, PackagePathPurpose::ModuleSource)?;
        }
        if let Some(root) = canonical_root {
            let relative = canonical
                .strip_prefix(root.prefix)
                .expect("matching root is a path prefix");
            package_path_decision(relative, PackagePathPurpose::ModuleSource)?;
        }

        match (requested_root, canonical_root) {
            (Some(requested_root), Some(canonical_root))
                if requested_root.identity != canonical_root.identity =>
            {
                Err(PackagePathError {
                    code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
                    message: format!(
                        "模块路径“{}”从可信包根“{}”跨入了另一包根“{}”。",
                        requested_or_joined.display(),
                        requested_root.identity.display(),
                        canonical_root.identity.display()
                    ),
                    path: requested_or_joined.to_path_buf(),
                    component: None,
                    suggestion: "请移除跨包符号链接，并通过包依赖与导出访问模块。".into(),
                })
            }
            (Some(root), None) => Err(PackagePathError {
                code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
                message: format!(
                    "模块路径“{}”从可信包根“{}”逃逸到“{}”。",
                    requested_or_joined.display(),
                    root.identity.display(),
                    canonical.display()
                ),
                path: requested_or_joined.to_path_buf(),
                component: None,
                suggestion: "请移除越界路径或符号链接，并将模块保留在所属包根内。".into(),
            }),
            (_, Some(_)) => Ok(ModuleAuthority::VerifiedPackageContent),
            (None, None) => Ok(ModuleAuthority::External),
        }
    }

    /// 授权一次模块导入，并防止普通文件导入跨越包身份边界。
    ///
    /// 只有已经通过依赖图与导出表解析的 `包:` 导入才应把
    /// `allow_cross_package` 设为 `true`。相对或绝对文件导入必须保持来源模块与
    /// 目标模块属于同一个最深可信包根；这样应用不能直接读取 `vendor` 中依赖的
    /// 私有模块，也不能从依赖中用 `../` 逃逸到应用源码。
    pub fn authorize_import(
        &self,
        current_base: &Path,
        requested_or_joined: &Path,
        canonical: &Path,
        allow_cross_package: bool,
    ) -> Result<ModuleAuthority, PackagePathError> {
        self.validate_requested_import(current_base, requested_or_joined, allow_cross_package)?;
        let authority = self.authorize_module(requested_or_joined, canonical)?;
        if allow_cross_package || self.roots.is_empty() {
            return Ok(authority);
        }
        #[cfg(not(target_os = "wasi"))]
        let current = fs::canonicalize(current_base).map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!(
                "不能规范化当前模块目录“{}”：{error}。",
                current_base.display()
            ),
            path: current_base.to_path_buf(),
            component: None,
            suggestion: "请确保当前模块目录存在且未被替换。".into(),
        })?;
        #[cfg(target_os = "wasi")]
        let current = lexical_absolute(current_base)?;
        let source_root = self.matching(&current);
        let target_root = self.matching(canonical);
        if source_root.map(|root| root.identity) != target_root.map(|root| root.identity) {
            return Err(PackagePathError {
                code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
                message: format!(
                    "普通模块导入“{}”跨越了包根边界：来源“{}”，目标“{}”。",
                    requested_or_joined.display(),
                    source_root
                        .map_or_else(|| "包外".into(), |root| root.identity.display().to_string()),
                    target_root
                        .map_or_else(|| "包外".into(), |root| root.identity.display().to_string())
                ),
                path: requested_or_joined.to_path_buf(),
                component: None,
                suggestion: "请通过声明的包依赖与公开导出（包:别名/导出）访问跨包模块。".into(),
            });
        }
        Ok(authority)
    }

    /// 在任何文件系统探测前校验连接后的词法路径。
    pub fn validate_requested_import(
        &self,
        current_base: &Path,
        requested_or_joined: &Path,
        allow_cross_package: bool,
    ) -> Result<(), PackagePathError> {
        if self.roots.is_empty() {
            return Ok(());
        }
        let current = lexical_absolute(current_base)?;
        let requested = lexical_absolute(requested_or_joined)?;
        let source_root = self.matching(&current);
        let target_root = self.matching(&requested);
        if let Some(root) = target_root {
            let relative = requested
                .strip_prefix(root.prefix)
                .expect("matching root is a path prefix");
            package_path_decision(relative, PackagePathPurpose::ModuleSource)?;
        }
        if !allow_cross_package
            && source_root.map(|root| root.identity) != target_root.map(|root| root.identity)
        {
            return Err(PackagePathError {
                code: PACKAGE_MODULE_OUTSIDE_ROOT_CODE,
                message: format!(
                    "普通模块导入“{}”跨越了包根边界：来源“{}”，目标“{}”。",
                    requested_or_joined.display(),
                    source_root
                        .map_or_else(|| "包外".into(), |root| root.identity.display().to_string()),
                    target_root
                        .map_or_else(|| "包外".into(), |root| root.identity.display().to_string())
                ),
                path: requested_or_joined.to_path_buf(),
                component: None,
                suggestion: "请通过声明的包依赖与公开导出（包:别名/导出）访问跨包模块。".into(),
            });
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn validate_requested_portability(
        &self,
        requested_or_joined: &Path,
    ) -> Result<(), PackagePathError> {
        if self.roots.is_empty() {
            return Ok(());
        }
        let requested = lexical_absolute(requested_or_joined)?;
        if let Some(root) = self.matching(&requested) {
            let relative = requested
                .strip_prefix(root.prefix)
                .expect("matching root is a path prefix");
            package_path_decision(relative, PackagePathPurpose::YxpEntry)?;
        }
        Ok(())
    }
}

fn require_included_path(
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<(), PackagePathError> {
    match package_path_decision(relative, purpose)? {
        PackagePathDecision::Include => Ok(()),
        PackagePathDecision::Exclude(PackagePathReason::ReservedComponent { component }) => {
            Err(reserved_path_error(relative, purpose, &component))
        }
        PackagePathDecision::Exclude(PackagePathReason::LockFile { .. }) => {
            Err(reserved_path_error(relative, purpose, LOCK_NAME))
        }
    }
}

#[cfg(not(target_os = "wasi"))]
fn select_capability_package_component(
    directory: &cap_std::fs::Dir,
    relative: &Path,
    component: &str,
) -> Result<CapabilityPackageDirectoryEntry, PackagePathError> {
    let requested_key = component.nfc().collect::<String>();
    let entries = directory.entries().map_err(|error| PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!(
            "不能从可信目录句柄枚举包路径“{}”的组件“{component}”：{error}。",
            relative.display()
        ),
        path: relative.to_path_buf(),
        component: Some(component.into()),
        suggestion: "请确保包目录在解析期间保持稳定且可读取。".into(),
    })?;
    let mut identities = PortablePackagePaths::default();
    let mut selected = None;
    let mut folded_match = None;
    for (index, entry) in entries.enumerate() {
        if index >= TRUSTED_DIRECTORY_MAX_ENTRIES {
            return Err(PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!(
                    "包路径“{}”所在目录不得超过 {TRUSTED_DIRECTORY_MAX_ENTRIES} 项。",
                    relative.display()
                ),
                path: relative.to_path_buf(),
                component: Some(component.into()),
                suggestion: "请拆分过宽的包目录后重试。".into(),
            });
        }
        let entry = entry.map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能读取包目录项：{error}。"),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请确保包目录在解析期间保持稳定且可读取。".into(),
        })?;
        let name = PathBuf::from(entry.file_name());
        let file_type = entry.file_type().map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能检查包目录项“{}”：{error}。", name.display()),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请确保包目录项保持稳定。".into(),
        })?;
        if file_type.is_dir() {
            identities.insert_directory(&name)?;
        } else {
            identities.insert(&name)?;
        }
        let portable_name = portable_package_path(&name)?;
        if portable_case_fold(&portable_name) == portable_case_fold(&requested_key) {
            folded_match = Some(name.clone());
        }
        if portable_name == requested_key {
            selected = Some(CapabilityPackageDirectoryEntry {
                name,
                is_directory: file_type.is_dir(),
                is_file: file_type.is_file(),
                is_symlink: file_type.is_symlink(),
            });
        }
    }
    if let Some(selected) = selected {
        return Ok(selected);
    }
    if let Some(alias) = folded_match {
        return Err(non_portable_error(
            relative,
            component,
            &format!("与实盘名称“{}”仅大小写不同", alias.display()),
        ));
    }
    Err(PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("包路径“{}”的组件“{component}”不存在。", relative.display()),
        path: relative.to_path_buf(),
        component: Some(component.into()),
        suggestion: "请确认清单或导入路径与包内文件一致。".into(),
    })
}

#[cfg(not(target_os = "wasi"))]
fn open_capability_package_directory(
    directory: &cap_std::fs::Dir,
    entry: &CapabilityPackageDirectoryEntry,
    relative: &Path,
    component: &str,
    resolved_relative: &Path,
) -> Result<cap_std::fs::Dir, PackagePathError> {
    if entry.is_symlink || !entry.is_directory {
        return Err(PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "包路径“{}”的组件“{component}”必须是真实目录。",
                relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请移除链接或特殊文件并重新执行。".into(),
        });
    }
    let child = directory
        .open_dir_nofollow(&entry.name)
        .map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "不能安全打开包目录“{}”：{error}。",
                resolved_relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请确保包目录没有被替换为链接或特殊文件。".into(),
        })?;
    let opened = child.dir_metadata().map_err(|error| PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!(
            "不能检查已打开的包目录“{}”：{error}。",
            resolved_relative.display()
        ),
        path: relative.to_path_buf(),
        component: Some(component.into()),
        suggestion: "请确保包目录保持可读取。".into(),
    })?;
    if !opened.is_dir() || opened.file_type().is_symlink() || cap_metadata_is_reparse(&opened) {
        return Err(PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "包路径“{}”的目录组件不是稳定的真实目录。",
                relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请移除链接或特殊文件并重新执行。".into(),
        });
    }
    Ok(child)
}

#[cfg(not(target_os = "wasi"))]
fn open_capability_package_file(
    directory: &cap_std::fs::Dir,
    entry: &CapabilityPackageDirectoryEntry,
    relative: &Path,
    component: &str,
) -> Result<fs::File, PackagePathError> {
    if entry.is_symlink || !entry.is_file {
        return Err(PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "包路径“{}”必须是普通文件，不得为链接或特殊文件。",
                relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请将该路径替换为真实普通文件。".into(),
        });
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory
        .open_with(&entry.name, &options)
        .map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能安全打开包文件“{}”：{error}。", relative.display()),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请确保文件没有被替换为链接或特殊文件。".into(),
        })?;
    let opened = file.metadata().map_err(|error| PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("不能检查已打开的包文件“{}”：{error}。", relative.display()),
        path: relative.to_path_buf(),
        component: Some(component.into()),
        suggestion: "请确保文件保持可读取。".into(),
    })?;
    if !opened.is_file() || opened.file_type().is_symlink() || cap_metadata_is_reparse(&opened) {
        return Err(PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "包路径“{}”必须是普通文件，不得为链接或特殊文件。",
                relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请将该路径替换为真实普通文件。".into(),
        });
    }
    Ok(file.into_std())
}

#[cfg(target_os = "wasi")]
fn select_wasi_package_component(
    directory: &WasiPackageDirectory,
    relative: &Path,
    component: &str,
) -> Result<WasiPackageDirectoryEntry, PackagePathError> {
    let requested_key = component.nfc().collect::<String>();
    let entries = directory
        .entries(TRUSTED_DIRECTORY_MAX_ENTRIES)
        .map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!(
                "不能从可信目录句柄枚举包路径“{}”的组件“{component}”：{error}。",
                relative.display()
            ),
            path: relative.to_path_buf(),
            component: Some(component.into()),
            suggestion: "请确保包目录在解析期间保持稳定且可读取。".into(),
        })?;
    let mut identities = PortablePackagePaths::default();
    let mut selected = None;
    let mut folded_match = None;
    for entry in entries {
        identities.insert(entry.name())?;
        let portable_name = portable_package_path(entry.name())?;
        if portable_case_fold(&portable_name) == portable_case_fold(&requested_key) {
            folded_match = Some(entry.name.clone());
        }
        if portable_name == requested_key {
            selected = Some(entry);
        }
    }
    if let Some(selected) = selected {
        return Ok(selected);
    }
    if let Some(alias) = folded_match {
        return Err(non_portable_error(
            relative,
            component,
            &format!("与实盘名称“{}”仅大小写不同", alias.display()),
        ));
    }
    Err(PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("包路径“{}”的组件“{component}”不存在。", relative.display()),
        path: relative.to_path_buf(),
        component: Some(component.into()),
        suggestion: "请确认清单或导入路径与包内文件一致。".into(),
    })
}

#[cfg(target_os = "wasi")]
fn resolve_wasi_package_path_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<(PathBuf, bool), PackagePathError> {
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("不能复制可信包根目录句柄：{error}。"),
            path: root.identity.to_path_buf(),
            component: None,
            suggestion: "请确保包根保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        let entry = select_wasi_package_component(&directory, relative, component)?;
        resolved_relative.push(entry.name());
        if index + 1 < components.len() {
            directory = directory
                .open_dir_nofollow(&entry)
                .map_err(|error| PackagePathError {
                    code: PACKAGE_PATH_INVALID_CODE,
                    message: format!(
                        "不能安全打开包目录“{}”：{error}。",
                        resolved_relative.display()
                    ),
                    path: relative.to_path_buf(),
                    component: Some(component.clone()),
                    suggestion: "请确保目录没有被替换为链接或特殊文件。".into(),
                })?;
            continue;
        }
        let is_directory =
            match directory
                .open_entry_nofollow(&entry)
                .map_err(|error| PackagePathError {
                    code: PACKAGE_PATH_INVALID_CODE,
                    message: format!("不能安全绑定包路径“{}”：{error}。", relative.display()),
                    path: relative.to_path_buf(),
                    component: Some(component.clone()),
                    suggestion: "请确保路径没有被替换为链接或特殊文件。".into(),
                })? {
                WasiPackageEntry::Directory(_) => true,
                WasiPackageEntry::File(_) => false,
            };
        return Ok((root.identity.join(resolved_relative), is_directory));
    }
    Err(invalid_path_error(relative, "包内路径不得为空"))
}

#[cfg(target_os = "wasi")]
fn resolve_wasi_package_directory_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<(WasiPackageDirectory, PathBuf), PackagePathError> {
    if relative.as_os_str().is_empty() {
        return root
            .directory
            .try_clone()
            .map(|directory| (directory, PathBuf::new()))
            .map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能复制可信包根目录句柄：{error}。"),
                path: root.identity.to_path_buf(),
                component: None,
                suggestion: "请确保包根保持可读取。".into(),
            });
    }
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!("不能复制可信包根目录句柄：{error}。"),
            path: root.identity.to_path_buf(),
            component: None,
            suggestion: "请确保包根保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();
    for component in components {
        let entry = select_wasi_package_component(&directory, relative, &component)?;
        resolved_relative.push(entry.name());
        directory = directory
            .open_dir_nofollow(&entry)
            .map_err(|error| PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!(
                    "不能安全打开包目录“{}”：{error}。",
                    resolved_relative.display()
                ),
                path: relative.to_path_buf(),
                component: Some(component),
                suggestion: "请确保目录没有被替换为链接或特殊文件。".into(),
            })?;
    }
    Ok((directory, resolved_relative))
}

#[cfg(not(target_os = "wasi"))]
fn resolve_capability_package_path_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<(PathBuf, bool), PackagePathError> {
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!(
                "不能复制可信包根句柄“{}”：{error}。",
                root.identity.display()
            ),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请确保包根在解析期间保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        let entry = select_capability_package_component(&directory, relative, component)?;
        resolved_relative.push(&entry.name);
        if index + 1 < components.len() {
            directory = open_capability_package_directory(
                &directory,
                &entry,
                relative,
                component,
                &resolved_relative,
            )?;
            continue;
        }
        if entry.is_directory {
            open_capability_package_directory(
                &directory,
                &entry,
                relative,
                component,
                &resolved_relative,
            )?;
        } else {
            open_capability_package_file(&directory, &entry, relative, component)?;
        }
        return Ok((root.identity.join(resolved_relative), entry.is_directory));
    }
    Err(invalid_path_error(relative, "包内路径不得为空"))
}

#[cfg(not(target_os = "wasi"))]
fn resolve_capability_package_directory_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<(cap_std::fs::Dir, PathBuf), PackagePathError> {
    if relative.as_os_str().is_empty() {
        return root
            .directory
            .try_clone()
            .map(|directory| (directory, PathBuf::new()))
            .map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!(
                    "不能复制可信包根句柄“{}”：{error}。",
                    root.identity.display()
                ),
                path: root.identity.to_path_buf(),
                component: None,
                suggestion: "请确保包根保持可读取。".into(),
            });
    }
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!(
                "不能复制可信包根句柄“{}”：{error}。",
                root.identity.display()
            ),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请确保包根在解析期间保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();
    for component in components {
        let entry = select_capability_package_component(&directory, relative, &component)?;
        resolved_relative.push(&entry.name);
        directory = open_capability_package_directory(
            &directory,
            &entry,
            relative,
            &component,
            &resolved_relative,
        )?;
    }
    Ok((directory, resolved_relative))
}

#[cfg(not(target_os = "wasi"))]
fn list_existing_directory_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<Vec<ResolvedPackageDirectoryEntry>, PackagePathError> {
    let (directory, actual_relative) =
        resolve_capability_package_directory_from_root(root, relative, purpose)?;
    let resolved = root.identity.join(&actual_relative);

    let entries = directory.entries().map_err(|error| PackagePathError {
        code: PACKAGE_PATH_INVALID_CODE,
        message: format!("不能枚举包目录“{}”：{error}。", resolved.display()),
        path: relative.to_path_buf(),
        component: None,
        suggestion: "请确保目录保持可读取。".into(),
    })?;
    let mut portable_paths = PortablePackagePaths::default();
    let mut result = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= 4_096 {
            return Err(invalid_path_error(relative, "单个资源目录不得超过 4096 项"));
        }
        let entry = entry.map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能读取包目录项：{error}。"),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请确保目录保持稳定且可读取。".into(),
        })?;
        let name = PathBuf::from(entry.file_name());
        let entry_relative = actual_relative.join(&name);
        match package_path_decision(&entry_relative, purpose)? {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => continue,
        }
        let file_type = entry.file_type().map_err(|error| PackagePathError {
            code: PACKAGE_PATH_INVALID_CODE,
            message: format!("不能检查包目录项“{}”：{error}。", name.display()),
            path: entry_relative.clone(),
            component: None,
            suggestion: "请确保目录项保持稳定。".into(),
        })?;
        if file_type.is_dir() {
            portable_paths.insert_directory(&entry_relative)?;
        } else {
            portable_paths.insert(&entry_relative)?;
        }
        if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
            return Err(invalid_path_error(
                &entry_relative,
                "资源目录不得包含链接或特殊文件",
            ));
        }
        if file_type.is_dir() {
            let child = directory.open_dir_nofollow(&name).map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能安全打开目录项：{error}"))
            })?;
            let metadata = child.dir_metadata().map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能检查目录项：{error}"))
            })?;
            if !metadata.is_dir() || cap_metadata_is_reparse(&metadata) {
                return Err(invalid_path_error(
                    &entry_relative,
                    "资源目录项不得为链接、重解析点或特殊文件",
                ));
            }
        } else {
            let mut options = cap_std::fs::OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No).nonblock(true);
            let file = directory.open_with(&name, &options).map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能安全打开资源目录项：{error}"))
            })?;
            let metadata = file.metadata().map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能检查资源目录项：{error}"))
            })?;
            if !metadata.is_file() || cap_metadata_is_reparse(&metadata) {
                return Err(invalid_path_error(
                    &entry_relative,
                    "资源目录项不得为链接、重解析点或特殊文件",
                ));
            }
        }
        result.push(ResolvedPackageDirectoryEntry {
            name: portable_package_path(&name)?,
            is_directory: file_type.is_dir(),
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

#[cfg(target_os = "wasi")]
fn list_existing_directory_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<Vec<ResolvedPackageDirectoryEntry>, PackagePathError> {
    let (directory, actual_relative) =
        resolve_wasi_package_directory_from_root(root, relative, purpose)?;
    let mut result = Vec::new();
    let mut portable_paths = PortablePackagePaths::default();
    for entry in directory.entries(4_096).map_err(|error| {
        invalid_path_error(relative, &format!("不能从稳定句柄枚举资源目录：{error}"))
    })? {
        if result.len() >= 4_096 {
            return Err(invalid_path_error(relative, "单个资源目录不得超过 4096 项"));
        }
        let entry_relative = actual_relative.join(entry.name());
        match package_path_decision(&entry_relative, purpose)? {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => continue,
        }
        let is_directory = match directory.open_entry_nofollow(&entry).map_err(|error| {
            invalid_path_error(&entry_relative, &format!("不能安全打开资源目录项：{error}"))
        })? {
            WasiPackageEntry::Directory(_child) => {
                portable_paths.insert_directory(&entry_relative)?;
                true
            }
            WasiPackageEntry::File(_file) => {
                portable_paths.insert(&entry_relative)?;
                false
            }
        };
        result.push(ResolvedPackageDirectoryEntry {
            name: portable_package_path(entry.name())?,
            is_directory,
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

struct ToolingModuleSnapshotWalker {
    root_identity: PathBuf,
    scanned_entries: usize,
    portable_paths: PortablePackagePaths,
    roots: Arc<TrustedPackageRoots>,
    files: Vec<ResolvedPackageFileSnapshot>,
}

impl ToolingModuleSnapshotWalker {
    fn new(root_identity: &Path, roots: Arc<TrustedPackageRoots>) -> Self {
        Self {
            root_identity: root_identity.to_path_buf(),
            scanned_entries: 0,
            portable_paths: PortablePackagePaths::default(),
            roots,
            files: Vec::new(),
        }
    }

    fn record_entry(&mut self, relative: &Path) -> Result<(), PackagePathError> {
        self.scanned_entries = self
            .scanned_entries
            .checked_add(1)
            .filter(|count| *count <= TOOLING_TREE_MAX_ENTRIES)
            .ok_or_else(|| {
                invalid_path_error(
                    relative,
                    &format!("工具目录项不得超过 {TOOLING_TREE_MAX_ENTRIES} 个"),
                )
            })?;
        Ok(())
    }

    fn enter_directory(&self, relative: &Path, depth: usize) -> Result<(), PackagePathError> {
        if depth > TOOLING_TREE_MAX_DEPTH {
            return Err(invalid_path_error(
                relative,
                &format!("工具模块目录深度不得超过 {TOOLING_TREE_MAX_DEPTH} 层"),
            ));
        }
        Ok(())
    }

    fn record_directory_entry(
        &mut self,
        relative: &Path,
        index: usize,
    ) -> Result<(), PackagePathError> {
        if index >= TOOLING_DIRECTORY_MAX_ENTRIES {
            return Err(invalid_path_error(
                relative,
                &format!("单个工具目录不得超过 {TOOLING_DIRECTORY_MAX_ENTRIES} 项"),
            ));
        }
        self.record_entry(relative)
    }

    fn finish(mut self) -> Vec<ResolvedPackageFileSnapshot> {
        self.files
            .sort_by(|left, right| left.portable_key.cmp(&right.portable_key));
        self.files
    }

    #[cfg(not(target_os = "wasi"))]
    fn snapshot_capability_directory(
        &mut self,
        directory: &cap_std::fs::Dir,
        relative: &Path,
        depth: usize,
    ) -> Result<(), PackagePathError> {
        self.enter_directory(relative, depth)?;
        let entries = directory.entries().map_err(|error| {
            invalid_path_error(relative, &format!("不能从稳定句柄枚举工具目录：{error}"))
        })?;
        let mut discovered = Vec::new();
        for (index, entry) in entries.enumerate() {
            self.record_directory_entry(relative, index)?;
            let entry = entry.map_err(|error| {
                invalid_path_error(relative, &format!("不能读取工具目录项：{error}"))
            })?;
            let name = PathBuf::from(entry.file_name());
            let entry_relative = relative.join(&name);
            match package_path_decision(&entry_relative, PackagePathPurpose::YxpEntry)? {
                PackagePathDecision::Include => {}
                PackagePathDecision::Exclude(_) => continue,
            }
            let file_type = entry.file_type().map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能检查工具目录项：{error}"))
            })?;
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                return Err(invalid_path_error(
                    &entry_relative,
                    "工具目录不得包含符号链接、Windows 重解析点或特殊文件",
                ));
            }
            if file_type.is_dir() {
                self.portable_paths.insert_directory(&entry_relative)?;
            } else {
                self.portable_paths.insert(&entry_relative)?;
            }
            let portable_name = portable_package_path(&name)?;
            discovered.push((
                portable_name,
                CapabilityPackageDirectoryEntry {
                    name,
                    is_directory: file_type.is_dir(),
                    is_file: file_type.is_file(),
                    is_symlink: file_type.is_symlink(),
                },
                entry_relative,
            ));
        }
        discovered.sort_by(|left, right| left.0.cmp(&right.0));

        for (portable_name, entry, entry_relative) in discovered {
            if entry.is_directory {
                let child = open_capability_package_directory(
                    directory,
                    &entry,
                    &entry_relative,
                    &portable_name,
                    &entry_relative,
                )?;
                self.snapshot_capability_directory(&child, &entry_relative, depth + 1)?;
                continue;
            }
            let file =
                open_capability_package_file(directory, &entry, &entry_relative, &portable_name)?;
            if entry
                .name
                .extension()
                .is_some_and(|extension| extension == "yx")
            {
                self.files.push(ResolvedPackageFileSnapshot::new(
                    self.root_identity.join(&entry_relative),
                    portable_package_path(&entry_relative)?,
                    self.roots.clone(),
                    &file,
                )?);
            }
        }
        Ok(())
    }

    #[cfg(target_os = "wasi")]
    fn snapshot_wasi_directory(
        &mut self,
        directory: &WasiPackageDirectory,
        relative: &Path,
        depth: usize,
    ) -> Result<(), PackagePathError> {
        self.enter_directory(relative, depth)?;
        let entries = directory
            .entries(TOOLING_DIRECTORY_MAX_ENTRIES)
            .map_err(|error| {
                invalid_path_error(relative, &format!("不能从稳定句柄枚举工具目录：{error}"))
            })?;
        for (index, entry) in entries.into_iter().enumerate() {
            self.record_directory_entry(relative, index)?;
            let entry_relative = relative.join(entry.name());
            match package_path_decision(&entry_relative, PackagePathPurpose::YxpEntry)? {
                PackagePathDecision::Include => {}
                PackagePathDecision::Exclude(_) => continue,
            }
            match directory.open_entry_nofollow(&entry).map_err(|error| {
                invalid_path_error(&entry_relative, &format!("不能安全打开工具目录项：{error}"))
            })? {
                WasiPackageEntry::Directory(child) => {
                    self.portable_paths.insert_directory(&entry_relative)?;
                    self.snapshot_wasi_directory(&child, &entry_relative, depth + 1)?;
                }
                WasiPackageEntry::File(file) => {
                    self.portable_paths.insert(&entry_relative)?;
                    if entry
                        .name()
                        .extension()
                        .is_some_and(|extension| extension == "yx")
                    {
                        self.files.push(ResolvedPackageFileSnapshot::new(
                            self.root_identity.join(&entry_relative),
                            portable_package_path(&entry_relative)?,
                            self.roots.clone(),
                            &file,
                        )?);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "wasi"))]
fn resolve_existing_file_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<ResolvedPackageFile, PackagePathError> {
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!(
                "不能复制可信包根句柄“{}”：{error}。",
                root.identity.display()
            ),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请确保包根在解析期间保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();

    for (index, component) in components.iter().enumerate() {
        let entry = select_capability_package_component(&directory, relative, component)?;
        resolved_relative.push(&entry.name);

        if index + 1 < components.len() {
            directory = open_capability_package_directory(
                &directory,
                &entry,
                relative,
                component,
                &resolved_relative,
            )?;
            continue;
        }
        return Ok(ResolvedPackageFile::new(
            root.identity.join(resolved_relative),
            open_capability_package_file(&directory, &entry, relative, component)?,
        ));
    }

    Err(invalid_path_error(relative, "包内文件路径不得为空"))
}

#[cfg(target_os = "wasi")]
fn resolve_existing_file_from_root(
    root: TrustedRootMatch<'_>,
    relative: &Path,
    purpose: PackagePathPurpose,
) -> Result<ResolvedPackageFile, PackagePathError> {
    require_included_path(relative, purpose)?;
    let components = portable_relative_components(relative)?;
    let mut directory = root
        .directory
        .try_clone()
        .map_err(|error| PackagePathError {
            code: PACKAGE_ROOT_INVALID_CODE,
            message: format!(
                "不能复制可信包根句柄“{}”：{error}。",
                root.identity.display()
            ),
            path: relative.to_path_buf(),
            component: None,
            suggestion: "请确保包根在解析期间保持可读取。".into(),
        })?;
    let mut resolved_relative = PathBuf::new();

    for (index, component) in components.iter().enumerate() {
        let entry = select_wasi_package_component(&directory, relative, component)?;
        resolved_relative.push(entry.name());
        if index + 1 < components.len() {
            directory = directory
                .open_dir_nofollow(&entry)
                .map_err(|error| PackagePathError {
                    code: PACKAGE_PATH_INVALID_CODE,
                    message: format!(
                        "不能安全打开包目录“{}”：{error}。",
                        resolved_relative.display()
                    ),
                    path: relative.to_path_buf(),
                    component: Some(component.clone()),
                    suggestion: "请确保包目录没有被替换为链接或特殊文件。".into(),
                })?;
            continue;
        }
        let file = directory
            .open_file_nofollow(&entry)
            .map_err(|error| PackagePathError {
                code: PACKAGE_PATH_INVALID_CODE,
                message: format!("不能安全打开包文件“{}”：{error}。", relative.display()),
                path: relative.to_path_buf(),
                component: Some(component.clone()),
                suggestion: "请确保文件没有被替换为链接或特殊文件。".into(),
            })?;
        return Ok(ResolvedPackageFile::new(
            root.identity.join(resolved_relative),
            file,
        ));
    }

    Err(invalid_path_error(relative, "包内文件路径不得为空"))
}

#[cfg(windows)]
fn cap_metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(not(windows), not(target_os = "wasi")))]
fn cap_metadata_is_reparse(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

#[cfg(all(unix, not(target_os = "wasi")))]
pub(crate) fn same_opened_directory_identity(
    left: &cap_std::fs::Dir,
    right: &cap_std::fs::Dir,
) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = left.try_clone()?.into_std_file().metadata()?;
    let right = right.try_clone()?.into_std_file().metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
pub(crate) fn same_opened_directory_identity(
    left: &cap_std::fs::Dir,
    right: &cap_std::fs::Dir,
) -> io::Result<bool> {
    fn identity(directory: &cap_std::fs::Dir) -> io::Result<(u64, [u8; 16])> {
        use std::mem::MaybeUninit;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };

        let file = directory.try_clone()?.into_std_file();
        let mut information = MaybeUninit::<FILE_ID_INFO>::zeroed();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                information.as_mut_ptr().cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let information = unsafe { information.assume_init() };
        Ok((
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        ))
    }

    Ok(identity(left)? == identity(right)?)
}

#[cfg(not(any(unix, windows, target_os = "wasi")))]
pub(crate) fn same_opened_directory_identity(
    left: &cap_std::fs::Dir,
    right: &cap_std::fs::Dir,
) -> io::Result<bool> {
    let left = left.dir_metadata()?;
    let right = right.dir_metadata()?;
    Ok(left.is_dir()
        && right.is_dir()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok())
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, PackagePathError> {
    if !path.is_absolute() {
        return Err(invalid_path_error(path, "连接后的模块路径必须是绝对路径"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(invalid_path_error(path, "模块路径越过了文件系统根目录"));
                }
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn ambient_root_paths(root: &Path) -> Result<(PathBuf, PathBuf), PackagePathError> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| PackagePathError {
                code: PACKAGE_ROOT_INVALID_CODE,
                message: format!("不能定位当前目录以解析可信包根：{error}。"),
                path: root.to_path_buf(),
                component: None,
                suggestion: "请确保依赖解析得到的包根存在且为真实目录。".into(),
            })?
            .join(root)
    };
    let lexical = lexical_absolute(&absolute)?;
    Ok((absolute, lexical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(name: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(target_os = "wasi"))]
        let path = std::env::temp_dir().join(format!(
            "yanxu-path-policy-{}-{name}-{sequence}",
            std::process::id()
        ));
        #[cfg(target_os = "wasi")]
        let path = Path::new("/tmp").join(format!("yanxu-path-policy-{name}-{sequence}"));
        fs::remove_dir_all(&path).ok();
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn reserved_components_are_excluded_at_every_depth() {
        for component in RESERVED_COMPONENTS {
            for path in [
                PathBuf::from(component),
                Path::new("src").join(component).join("模块.yx"),
            ] {
                assert!(matches!(
                    package_path_decision(&path, PackagePathPurpose::TreeChecksum),
                    Ok(PackagePathDecision::Exclude(
                        PackagePathReason::ReservedComponent { .. }
                    ))
                ));
                assert!(matches!(
                    package_path_decision(&path, PackagePathPurpose::YxpEntry),
                    Ok(PackagePathDecision::Exclude(
                        PackagePathReason::ReservedComponent { .. }
                    ))
                ));
                let error =
                    package_path_decision(&path, PackagePathPurpose::ModuleSource).unwrap_err();
                assert_eq!(error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
                assert_eq!(error.component.as_deref(), Some(*component));
            }
        }
    }

    #[test]
    fn lock_file_has_purpose_specific_root_and_nested_rules() {
        assert!(matches!(
            package_path_decision(Path::new(LOCK_NAME), PackagePathPurpose::TreeChecksum),
            Ok(PackagePathDecision::Exclude(PackagePathReason::LockFile {
                nested: false
            }))
        ));
        assert_eq!(
            package_path_decision(Path::new(LOCK_NAME), PackagePathPurpose::YxpEntry),
            Ok(PackagePathDecision::Include)
        );
        assert!(matches!(
            package_path_decision(
                Path::new("src").join(LOCK_NAME).as_path(),
                PackagePathPurpose::YxpEntry
            ),
            Ok(PackagePathDecision::Exclude(PackagePathReason::LockFile {
                nested: true
            }))
        ));
        let error = package_path_decision(
            Path::new("src").join(LOCK_NAME).as_path(),
            PackagePathPurpose::ModuleSource,
        )
        .unwrap_err();
        assert_eq!(error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
    }

    #[test]
    fn aliases_are_rejected_identically_on_every_host() {
        for path in [
            "Build/模块.yx",
            "TARGET/模块.yx",
            ".GIT/config",
            "src/言序.LOCK",
            "vendor./模块.yx",
            "ordinary /模块.yx",
            "src/坏:名.yx",
            "src/坏*名.yx",
            "src/CON.yx",
            "src/CON .txt",
            "src/CONIN$.txt",
            "src/conout$.yx",
            "src/com1.txt",
            "src/COM1 .log",
            "src/COM¹.txt",
            "src/lpt²",
            ".Dſ_Store/cache",
        ] {
            for purpose in [
                PackagePathPurpose::TreeChecksum,
                PackagePathPurpose::YxpEntry,
                PackagePathPurpose::ModuleSource,
                PackagePathPurpose::ManifestReference,
            ] {
                let error = package_path_decision(Path::new(path), purpose).unwrap_err();
                assert_eq!(error.code, PACKAGE_PATH_NON_PORTABLE_CODE, "{path}");
            }
        }
    }

    #[test]
    fn normal_source_is_included_and_invalid_relative_paths_are_rejected() {
        assert_eq!(
            package_path_decision(Path::new("src/模块.yx"), PackagePathPurpose::ModuleSource),
            Ok(PackagePathDecision::Include)
        );
        for path in [
            Path::new(""),
            Path::new("../模块.yx"),
            Path::new("/模块.yx"),
        ] {
            assert_eq!(
                package_path_decision(path, PackagePathPurpose::ModuleSource)
                    .unwrap_err()
                    .code,
                PACKAGE_PATH_INVALID_CODE
            );
        }
    }

    #[test]
    fn deepest_dependency_root_allows_verified_vendor_package_only() {
        let app = temporary_directory("deepest-root");
        let dependency = app.join("vendor/依赖");
        let dependency_source = dependency.join("src");
        fs::create_dir_all(&dependency_source).unwrap();
        fs::create_dir_all(app.join("vendor/noise")).unwrap();
        fs::write(dependency_source.join("模块.yx"), "令 值 = 1").unwrap();
        fs::write(app.join("vendor/noise/模块.yx"), "令 值 = 2").unwrap();

        let mut roots = TrustedPackageRoots::default();
        roots.insert(&app).unwrap();
        roots.insert(&dependency).unwrap();
        roots.insert(&dependency).unwrap();
        assert_eq!(roots.len(), 2);

        let dependency_module = fs::canonicalize(dependency_source.join("模块.yx")).unwrap();
        assert_eq!(
            roots.matching_root(&dependency_module),
            Some(fs::canonicalize(&dependency).unwrap().as_path())
        );
        assert_eq!(
            roots
                .authorize_module(&dependency_module, &dependency_module)
                .unwrap(),
            ModuleAuthority::VerifiedPackageContent
        );

        let noise = fs::canonicalize(app.join("vendor/noise/模块.yx")).unwrap();
        let error = roots.authorize_module(&noise, &noise).unwrap_err();
        assert_eq!(error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);
        assert_eq!(error.component.as_deref(), Some("vendor"));

        fs::remove_dir_all(app).unwrap();
    }

    #[test]
    fn lexical_parent_segments_are_resolved_before_reserved_checks() {
        let app = temporary_directory("lexical-parent");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(app.join("build")).unwrap();
        fs::write(app.join("build/隐藏.yx"), "令 值 = 1").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&app).unwrap();

        let requested = app.join("src/../build/隐藏.yx");
        let canonical = fs::canonicalize(app.join("build/隐藏.yx")).unwrap();
        let error = roots.authorize_module(&requested, &canonical).unwrap_err();
        assert_eq!(error.code, PACKAGE_MODULE_RESERVED_PATH_CODE);

        fs::remove_dir_all(app).unwrap();
    }

    #[test]
    fn ordinary_import_cannot_cross_into_a_nested_dependency_root() {
        let app = temporary_directory("cross-root-import");
        let dependency = app.join("vendor/依赖");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(dependency.join("src")).unwrap();
        fs::write(dependency.join("src/私有.yx"), "令 值 = 1").unwrap();

        let mut roots = TrustedPackageRoots::default();
        roots.insert(&app).unwrap();
        roots.insert(&dependency).unwrap();
        let target = fs::canonicalize(dependency.join("src/私有.yx")).unwrap();
        let error = roots
            .authorize_import(
                &app.join("src"),
                &dependency.join("src/私有.yx"),
                &target,
                false,
            )
            .unwrap_err();
        assert_eq!(error.code, PACKAGE_MODULE_OUTSIDE_ROOT_CODE);
        assert_eq!(
            roots
                .authorize_import(
                    &app.join("src"),
                    &dependency.join("src/私有.yx"),
                    &target,
                    true,
                )
                .unwrap(),
            ModuleAuthority::VerifiedPackageContent
        );

        fs::remove_dir_all(app).unwrap();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn duplicate_root_and_alias_insertion_reject_same_name_replacement() {
        let root = temporary_directory("duplicate-root-replacement");
        let backup = root.with_extension("original");
        fs::write(root.join("old.yx"), "言 1；\n").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();

        fs::rename(&root, &backup).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("new.yx"), "言 2；\n").unwrap();

        let duplicate_error = roots.insert(&root).unwrap_err();
        assert_eq!(duplicate_error.code, PACKAGE_ROOT_INVALID_CODE);
        assert!(duplicate_error.message.contains("同名目录替换"));
        let alias_error = roots.insert_alias(&root, &root).unwrap_err();
        assert_eq!(alias_error.code, PACKAGE_ROOT_INVALID_CODE);
        assert!(alias_error.message.contains("身份不同"));

        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn trusted_root_file_and_directory_tokens_survive_root_replacement() {
        use std::io::Read as _;

        let root = temporary_directory("root-token-replacement");
        let backup = root.with_extension("original");
        fs::remove_dir_all(&backup).ok();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/old.yx"), "言「可信根」；\n").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let root_identity = roots.roots().next().unwrap().to_path_buf();
        let resolved = roots
            .resolve_existing_file(
                &root.join("src/old.yx"),
                PackagePathPurpose::ManifestReference,
            )
            .unwrap()
            .unwrap();

        fs::rename(&root, &backup).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/new.yx"), "言「替换根」；\n").unwrap();

        let listed =
            roots.list_existing_directory(&root.join("src"), PackagePathPurpose::ManifestReference);
        #[cfg(target_os = "wasi")]
        if std::env::var_os("YANXU_EXPECT_WASI_BINDING_DRIFT").is_some() {
            let error = listed.unwrap_err();
            assert_eq!(error.code, PACKAGE_PATH_INVALID_CODE);
            assert!(error.message.contains("WASI 宿主目录描述符绑定发生漂移"));
            let path_error = roots
                .resolve_existing_module_path(&root.join("src/old.yx"))
                .unwrap_err();
            assert!(
                path_error
                    .message
                    .contains("WASI 宿主目录描述符绑定发生漂移")
            );
            let mut source = String::new();
            resolved.into_file().read_to_string(&mut source).unwrap();
            assert_eq!(source, "言「可信根」；\n");
            fs::remove_dir_all(root).ok();
            fs::remove_dir_all(backup).ok();
            return;
        }
        let entries = listed.unwrap().unwrap();
        assert_eq!(
            entries,
            vec![ResolvedPackageDirectoryEntry {
                name: "old.yx".into(),
                is_directory: false,
            }]
        );
        let mut source = String::new();
        resolved.into_file().read_to_string(&mut source).unwrap();
        assert_eq!(source, "言「可信根」；\n");

        assert_eq!(
            roots
                .resolve_existing_module_path(&root.join("src/old.yx"))
                .unwrap()
                .unwrap(),
            root_identity.join("src/old.yx")
        );

        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn trusted_file_tokens_survive_ancestor_and_equal_length_file_replacement() {
        use std::io::Read as _;

        let root = temporary_directory("file-token-replacement");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("stable")).unwrap();
        fs::write(root.join("src/module.yx"), "言「可信」；\n").unwrap();
        fs::write(root.join("stable/module.yx"), "言「原文」；\n").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let ancestor = roots
            .resolve_existing_file(
                &root.join("src/module.yx"),
                PackagePathPurpose::ManifestReference,
            )
            .unwrap()
            .unwrap();
        let final_file = roots
            .resolve_existing_file(
                &root.join("stable/module.yx"),
                PackagePathPurpose::ManifestReference,
            )
            .unwrap()
            .unwrap();

        fs::rename(root.join("src"), root.join("src-original")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/module.yx"), "言「替换」；\n").unwrap();
        fs::rename(
            root.join("stable/module.yx"),
            root.join("stable/original.yx"),
        )
        .unwrap();
        fs::write(root.join("stable/module.yx"), "言「改写」；\n").unwrap();

        let mut ancestor_source = String::new();
        ancestor
            .into_file()
            .read_to_string(&mut ancestor_source)
            .unwrap();
        assert_eq!(ancestor_source, "言「可信」；\n");
        let mut final_source = String::new();
        final_file
            .into_file()
            .read_to_string(&mut final_source)
            .unwrap();
        assert_eq!(final_source, "言「原文」；\n");

        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn trusted_file_and_directory_operations_reject_links_and_non_files() {
        let root = temporary_directory("link-special-rejection");
        fs::write(root.join("target.yx"), "言 1；\n").unwrap();
        fs::create_dir_all(root.join("directory")).unwrap();
        let link = root.join("link.yx");
        #[cfg(all(unix, not(target_os = "wasi")))]
        std::os::unix::fs::symlink("target.yx", &link).unwrap();
        #[cfg(target_os = "wasi")]
        rustix::fs::symlinkat(Path::new("target.yx"), rustix::fs::CWD, &link).unwrap();

        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        assert!(
            roots
                .resolve_existing_file(&link, PackagePathPurpose::ManifestReference)
                .is_err()
        );
        assert!(
            roots
                .resolve_existing_file(
                    &root.join("directory"),
                    PackagePathPurpose::ManifestReference,
                )
                .is_err()
        );
        assert!(
            roots
                .list_existing_directory(&root, PackagePathPurpose::ManifestReference)
                .is_err()
        );

        fs::remove_dir_all(root).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn trusted_root_accepts_stable_final_and_ancestor_aliases() {
        use std::io::Read as _;

        let base = temporary_directory("stable-root-aliases");
        let real_root = base.join("real/package");
        fs::create_dir_all(real_root.join("docs")).unwrap();
        fs::write(real_root.join("module.yx"), "言「别名根」；\n").unwrap();
        let ancestor_alias = base.join("alias-parent");
        let final_alias = base.join("final-root");
        #[cfg(all(unix, not(target_os = "wasi")))]
        {
            std::os::unix::fs::symlink("real", &ancestor_alias).unwrap();
            std::os::unix::fs::symlink("real/package", &final_alias).unwrap();
        }
        #[cfg(target_os = "wasi")]
        {
            rustix::fs::symlinkat(Path::new("real"), rustix::fs::CWD, &ancestor_alias).unwrap();
            rustix::fs::symlinkat(Path::new("real/package"), rustix::fs::CWD, &final_alias)
                .unwrap();
        }

        let mut roots = TrustedPackageRoots::default();
        roots.insert(ancestor_alias.join("package")).unwrap();
        roots.insert(&final_alias).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(
            roots
                .resolve_existing_module_path(&final_alias.join("docs"))
                .unwrap()
                .unwrap(),
            fs::canonicalize(real_root.join("docs")).unwrap()
        );
        let resolved = roots
            .resolve_existing_file(
                &final_alias.join("module.yx"),
                PackagePathPurpose::ManifestReference,
            )
            .unwrap()
            .unwrap();
        let mut source = String::new();
        resolved.into_file().read_to_string(&mut source).unwrap();
        assert_eq!(source, "言「别名根」；\n");

        fs::remove_dir_all(base).ok();
    }

    #[cfg(target_os = "wasi")]
    #[test]
    fn wasi_directory_enumeration_stops_at_the_configured_limit() {
        let root = temporary_directory("bounded-directory-enumeration");
        for name in ["one.yx", "two.yx", "three.yx"] {
            fs::write(root.join(name), "言 1；\n").unwrap();
        }
        let directory = WasiPackageDirectory::open_ambient(&root, true).unwrap();
        let error = directory.entries(2).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "包目录项不得超过 2 个");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn portable_path_set_rejects_case_and_unicode_normalization_collisions() {
        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("src/Foo.yx")).unwrap();
        let error = paths.insert(Path::new("src/foo.yx")).unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_COLLISION_CODE);

        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("src/é.yx")).unwrap();
        let error = paths.insert(Path::new("src/e\u{301}.yx")).unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_COLLISION_CODE);

        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("src/Foo/甲.yx")).unwrap();
        let error = paths.insert(Path::new("src/foo/乙.yx")).unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_COLLISION_CODE);

        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("Package/言序.toml")).unwrap();
        let error = paths.insert(Path::new("package/额外.yx")).unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_COLLISION_CODE);

        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("src/Σ/甲.yx")).unwrap();
        let error = paths.insert(Path::new("src/ς/乙.yx")).unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_COLLISION_CODE);

        assert_eq!(
            portable_package_path(Path::new("src/e\u{301}.yx")).unwrap(),
            "src/é.yx"
        );
    }

    #[test]
    fn existing_path_resolution_matches_unicode_identity_but_preserves_case() {
        let root = temporary_directory("unicode-existing-path");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/é.yx"), "言 1；\n").unwrap();
        fs::write(root.join("src/Case.yx"), "言 2；\n").unwrap();

        let resolved = resolve_existing_package_path(
            &root,
            Path::new("src/e\u{301}.yx"),
            PackagePathPurpose::ModuleSource,
        )
        .unwrap();
        assert_eq!(resolved, fs::canonicalize(root.join("src/é.yx")).unwrap());

        let error = resolve_existing_package_path(
            &root,
            Path::new("src/case.yx"),
            PackagePathPurpose::ModuleSource,
        )
        .unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_NON_PORTABLE_CODE);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovered_module_snapshot_rejects_same_name_file_replacement() {
        use std::io::Read as _;

        let root = temporary_directory("tooling-file-replacement");
        let module = root.join("模块.yx");
        let original = root.join("原模块.yx");
        fs::write(&module, "言「发现时」；\n").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let mut files = roots.snapshot_module_directory(&root).unwrap().unwrap();
        assert_eq!(files.len(), 1);

        fs::rename(&module, &original).unwrap();
        fs::write(&module, "言「替换后」；\n").unwrap();
        let error = files.remove(0).open().unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_INVALID_CODE);
        assert!(error.message.contains("同名替换"), "{error}");

        let snapshot = roots
            .snapshot_existing_module_file(&module)
            .unwrap()
            .unwrap();
        let mut source = String::new();
        snapshot
            .open()
            .unwrap()
            .into_file()
            .read_to_string(&mut source)
            .unwrap();
        assert_eq!(source, "言「替换后」；\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn discovered_module_snapshot_keeps_the_opened_root_identity() {
        use std::io::Read as _;

        let root = temporary_directory("tooling-root-replacement");
        let backup = root.with_extension("original");
        fs::write(root.join("模块.yx"), "言「原根」；\n").unwrap();
        let mut roots = TrustedPackageRoots::default();
        roots.insert(&root).unwrap();
        let mut files = roots.snapshot_module_directory(&root).unwrap().unwrap();

        fs::rename(&root, &backup).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("模块.yx"), "言「替换根」；\n").unwrap();

        let mut source = String::new();
        files
            .remove(0)
            .open()
            .unwrap()
            .into_file()
            .read_to_string(&mut source)
            .unwrap();
        assert_eq!(source, "言「原根」；\n");
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[test]
    fn tooling_snapshot_budgets_accept_the_boundary_and_reject_one_more() {
        let roots = Arc::new(TrustedPackageRoots::default());
        let mut directory = ToolingModuleSnapshotWalker::new(Path::new("/工具根"), roots.clone());
        assert!(
            directory
                .enter_directory(Path::new("深目录"), TOOLING_TREE_MAX_DEPTH)
                .is_ok()
        );
        let depth = directory
            .enter_directory(Path::new("过深目录"), TOOLING_TREE_MAX_DEPTH + 1)
            .unwrap_err();
        assert!(depth.message.contains("目录深度"), "{depth}");
        for index in 0..TOOLING_DIRECTORY_MAX_ENTRIES {
            directory
                .record_directory_entry(Path::new("宽目录"), index)
                .unwrap();
        }
        let width = directory
            .record_directory_entry(Path::new("宽目录"), TOOLING_DIRECTORY_MAX_ENTRIES)
            .unwrap_err();
        assert!(width.message.contains("单个工具目录"), "{width}");

        let mut tree = ToolingModuleSnapshotWalker::new(Path::new("/工具根"), roots);
        for _ in 0..TOOLING_TREE_MAX_ENTRIES {
            tree.record_entry(Path::new("工具树")).unwrap();
        }
        let total = tree.record_entry(Path::new("工具树")).unwrap_err();
        assert!(total.message.contains("工具目录项"), "{total}");
    }

    #[test]
    fn raw_backslash_is_rejected_before_platform_path_parsing() {
        let error = validate_portable_path_text(r"src\模块.yx").unwrap_err();
        assert_eq!(error.code, PACKAGE_PATH_NON_PORTABLE_CODE);
    }
}

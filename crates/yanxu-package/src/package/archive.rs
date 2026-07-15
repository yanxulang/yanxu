//! Registry 制品的限额解压与展开后结构验证。

use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct ArchiveLimits {
    pub(super) compressed_bytes: u64,
    pub(super) file_bytes: u64,
    pub(super) expanded_bytes: u64,
    pub(super) entries: usize,
    pub(super) path_bytes: usize,
}

pub(super) const ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    compressed_bytes: ARCHIVE_MAX_COMPRESSED_BYTES,
    file_bytes: ARCHIVE_MAX_FILE_BYTES,
    expanded_bytes: ARCHIVE_MAX_EXPANDED_BYTES,
    entries: ARCHIVE_MAX_ENTRIES,
    path_bytes: ARCHIVE_MAX_PATH_BYTES,
};

pub(super) fn extract_archive_safely(
    archive: &Path,
    destination: &Path,
) -> Result<(), ManifestError> {
    extract_archive_with_limits(archive, destination, ARCHIVE_LIMITS)
}

pub(super) fn extract_archive_with_limits(
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let compressed_bytes = fs::metadata(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能检查制品大小：{error}")))?
        .len();
    if compressed_bytes > limits.compressed_bytes {
        return Err(manifest_error(
            archive,
            None,
            format!(
                "索引制品压缩后为 {compressed_bytes} 字节，超过 {} 字节上限",
                limits.compressed_bytes
            ),
        ));
    }
    let file = fs::File::open(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能打开索引制品：{error}")))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(|error| {
        manifest_error(archive, None, format!("索引制品不是有效 tar.gz：{error}"))
    })?;
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    for entry in entries {
        entry_count = entry_count.saturating_add(1);
        if entry_count > limits.entries {
            return Err(manifest_error(
                archive,
                None,
                format!("索引制品条目超过 {} 项上限", limits.entries),
            ));
        }
        let mut entry = entry.map_err(|error| {
            manifest_error(archive, None, format!("不能读取索引制品条目：{error}"))
        })?;
        let relative = entry
            .path()
            .map_err(|error| manifest_error(archive, None, format!("索引制品路径无效：{error}")))?
            .into_owned();
        validate_archive_relative_path(&relative, limits.path_bytes)
            .map_err(|message| manifest_error(archive, None, message))?;
        let destination_path = destination.join(&relative);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&destination_path).map_err(|error| {
                manifest_error(
                    &destination_path,
                    None,
                    format!("不能创建制品目录：{error}"),
                )
            })?;
            continue;
        }
        if !entry_type.is_file() {
            return Err(manifest_error(
                archive,
                None,
                format!(
                    "索引制品含不允许的特殊条目“{}”（符号链接、硬链接、设备文件与管道均被拒绝）",
                    relative.display()
                ),
            ));
        }
        let file_bytes = entry.size();
        if file_bytes > limits.file_bytes {
            return Err(manifest_error(
                archive,
                None,
                format!(
                    "索引制品文件“{}”为 {file_bytes} 字节，超过 {} 字节上限",
                    relative.display(),
                    limits.file_bytes
                ),
            ));
        }
        expanded_bytes = expanded_bytes
            .checked_add(file_bytes)
            .ok_or_else(|| manifest_error(archive, None, "索引制品展开大小溢出"))?;
        if expanded_bytes > limits.expanded_bytes {
            return Err(manifest_error(
                archive,
                None,
                format!("索引制品展开后超过 {} 字节上限", limits.expanded_bytes),
            ));
        }
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                manifest_error(parent, None, format!("不能创建制品目录：{error}"))
            })?;
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination_path)
            .map_err(|error| {
                manifest_error(
                    &destination_path,
                    None,
                    format!("不能安全创建制品文件：{error}"),
                )
            })?;
        let copied = io::copy(&mut entry, &mut output).map_err(|error| {
            manifest_error(
                &destination_path,
                None,
                format!("不能展开制品文件：{error}"),
            )
        })?;
        if copied != file_bytes {
            return Err(manifest_error(
                archive,
                None,
                format!(
                    "索引制品文件“{}”声明 {file_bytes} 字节，实际展开 {copied} 字节",
                    relative.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_archive_relative_path(path: &Path, max_bytes: usize) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > max_bytes
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(format!("索引制品含越界或过长路径“{}”", path.display()))
    } else {
        Ok(())
    }
}

pub(super) fn find_manifest_root(directory: &Path) -> Result<PathBuf, ManifestError> {
    let mut manifests = Vec::new();
    find_manifests(directory, &mut manifests)?;
    if manifests.len() != 1 {
        return Err(manifest_error(
            directory,
            None,
            format!(
                "索引制品应恰含一个 {MANIFEST_NAME}，实有 {} 个",
                manifests.len()
            ),
        ));
    }
    manifests
        .pop()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .ok_or_else(|| manifest_error(directory, None, "索引制品清单缺少父目录"))
}

fn find_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) -> Result<(), ManifestError> {
    for entry in fs::read_dir(directory)
        .map_err(|error| manifest_error(directory, None, format!("不能检查展开制品：{error}")))?
    {
        let entry = entry
            .map_err(|error| manifest_error(directory, None, format!("不能读取展开项：{error}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| manifest_error(&path, None, format!("不能检查展开项类型：{error}")))?;
        if file_type.is_dir() {
            find_manifests(&path, manifests)?;
        } else if file_type.is_file() && entry.file_name() == MANIFEST_NAME {
            manifests.push(path);
        } else if !file_type.is_file() {
            return Err(manifest_error(&path, None, "展开制品含特殊文件"));
        }
    }
    Ok(())
}

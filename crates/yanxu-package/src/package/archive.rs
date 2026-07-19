//! Registry 制品的限额解压与展开后结构验证。

use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct ArchiveLimits {
    pub(super) compressed_bytes: u64,
    pub(super) file_bytes: u64,
    pub(super) expanded_bytes: u64,
    pub(super) entries: usize,
    pub(super) path_bytes: usize,
    pub(super) metadata_headers: bool,
}

pub(super) const ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    compressed_bytes: ARCHIVE_MAX_COMPRESSED_BYTES,
    file_bytes: ARCHIVE_MAX_FILE_BYTES,
    expanded_bytes: ARCHIVE_MAX_EXPANDED_BYTES,
    entries: ARCHIVE_MAX_ENTRIES,
    path_bytes: ARCHIVE_MAX_PATH_BYTES,
    metadata_headers: false,
};

#[cfg(test)]
pub(super) fn extract_archive_safely(
    archive: &Path,
    destination: &Path,
) -> Result<(), ManifestError> {
    extract_archive_with_limits(archive, destination, ARCHIVE_LIMITS)
}

/// 展开调用方已经完整快照并校验过的归档字节。
///
/// registry 下载先把受压缩量上限约束的文件读入内存，再对同一份字节同时
/// 计算制品摘要并解包，避免“按路径验签、再按路径打开”之间被替换。
pub(super) fn extract_archive_bytes_safely(
    bytes: &[u8],
    archive: &Path,
    destination: &Path,
) -> Result<(), ManifestError> {
    extract_archive_bytes_with_limits(bytes, archive, destination, ARCHIVE_LIMITS)
}

pub(super) fn extract_archive_bytes_with_limits(
    bytes: &[u8],
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let compressed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    extract_archive_reader_with_limits(
        io::Cursor::new(bytes),
        compressed_bytes,
        archive,
        destination,
        limits,
    )
}

/// 展开由本地 Git 进程直接生成的未压缩 tar 快照。
///
/// Git 依赖不使用可由用户配置替换的 `tar.gz` 压缩命令；原始 tar 字节仍受
/// 输入、单文件、总展开量、条目数和路径长度的同一组硬上限约束。
pub(super) fn extract_tar_bytes_with_limits(
    bytes: &[u8],
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let archive_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if archive_bytes > limits.compressed_bytes {
        return Err(manifest_error(
            archive,
            None,
            format!(
                "归档为 {archive_bytes} 字节，超过 {} 字节输入上限",
                limits.compressed_bytes
            ),
        ));
    }
    extract_tar_reader_with_limits(io::Cursor::new(bytes), archive, destination, limits)
}

/// 只读验证既有文件是否为本生产器可安全覆盖的 YXP 制品。
///
/// 源树内允许调用方选择任意输出文件名；但再次打包时不能仅凭扩展名覆盖
/// 一个普通源码或资源文件。这里完整消费 gzip/tar，在既有消费端限额内确认
/// 所有条目均为 `package/` 下的普通文件，并且恰含根清单。
pub(super) fn validate_existing_package_archive(
    archive: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let compressed_bytes = fs::metadata(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能检查既有打包输出：{error}")))?
        .len();
    if compressed_bytes > limits.compressed_bytes {
        return Err(manifest_error(
            archive,
            None,
            format!("既有打包输出超过 {} 字节上限", limits.compressed_bytes),
        ));
    }

    let file = fs::File::open(archive)
        .map_err(|error| manifest_error(archive, None, format!("不能打开既有打包输出：{error}")))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(|error| {
        manifest_error(
            archive,
            None,
            format!("源树内既有输出不是有效 YXP：{error}"),
        )
    })?;
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut manifest_count = 0_usize;
    let mut paths = BTreeSet::new();
    for entry in entries {
        entry_count = entry_count.saturating_add(1);
        if entry_count > limits.entries {
            return Err(manifest_error(
                archive,
                None,
                format!("既有 YXP 条目超过 {} 项上限", limits.entries),
            ));
        }
        let mut entry = entry.map_err(|error| {
            manifest_error(archive, None, format!("不能读取既有 YXP 条目：{error}"))
        })?;
        let relative = entry
            .path()
            .map_err(|error| manifest_error(archive, None, format!("既有 YXP 路径无效：{error}")))?
            .into_owned();
        validate_archive_relative_path(&relative, limits.path_bytes)
            .map_err(|message| manifest_error(archive, None, message))?;
        if !paths.insert(relative.clone()) {
            return Err(manifest_error(
                archive,
                None,
                format!("源树内既有 YXP 含重复路径“{}”", relative.display()),
            ));
        }
        if !entry.header().entry_type().is_file()
            || relative
                .components()
                .next()
                .is_none_or(|component| component.as_os_str() != "package")
        {
            return Err(manifest_error(
                archive,
                None,
                "源树内既有输出不是本工具生成的 YXP，拒绝覆盖",
            ));
        }
        if relative == Path::new("package").join(MANIFEST_NAME) {
            manifest_count = manifest_count.saturating_add(1);
        } else if relative
            .file_name()
            .is_some_and(|name| name == MANIFEST_NAME)
        {
            return Err(manifest_error(
                archive,
                None,
                "源树内既有 YXP 含嵌套包清单，拒绝覆盖",
            ));
        }
        let file_bytes = entry.size();
        if file_bytes > limits.file_bytes {
            return Err(manifest_error(
                archive,
                None,
                format!("既有 YXP 单文件超过 {} 字节上限", limits.file_bytes),
            ));
        }
        expanded_bytes = expanded_bytes
            .checked_add(file_bytes)
            .filter(|total| *total <= limits.expanded_bytes)
            .ok_or_else(|| {
                manifest_error(
                    archive,
                    None,
                    format!("既有 YXP 展开后超过 {} 字节上限", limits.expanded_bytes),
                )
            })?;
        let copied = io::copy(&mut entry, &mut io::sink()).map_err(|error| {
            manifest_error(archive, None, format!("不能完整读取既有 YXP 条目：{error}"))
        })?;
        if copied != file_bytes {
            return Err(manifest_error(
                archive,
                None,
                "既有 YXP 条目声明大小与实际内容不符",
            ));
        }
    }
    if manifest_count != 1 || entry_count < 2 {
        return Err(manifest_error(
            archive,
            None,
            format!("既有 YXP 应恰含一个根清单，实有 {manifest_count} 个"),
        ));
    }
    let mut decoder = tar.into_inner();
    io::copy(&mut decoder, &mut io::sink()).map_err(|error| {
        manifest_error(archive, None, format!("既有 YXP gzip 数据不完整：{error}"))
    })?;
    Ok(())
}

#[cfg(test)]
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
    extract_archive_reader_with_limits(file, compressed_bytes, archive, destination, limits)
}

fn extract_archive_reader_with_limits<R: Read>(
    reader: R,
    compressed_bytes: u64,
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
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
    let decoder = flate2::read::GzDecoder::new(reader);
    extract_tar_reader_with_limits(decoder, archive, destination, limits)
}

fn extract_tar_reader_with_limits<R: Read>(
    reader: R,
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let mut tar = tar::Archive::new(reader);
    let entries = tar.entries().map_err(|error| {
        manifest_error(archive, None, format!("索引制品不是有效 tar.gz：{error}"))
    })?;
    let entries = entries.raw(!limits.metadata_headers);
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
        if limits.metadata_headers
            && (entry_type.is_pax_global_extensions()
                || entry_type.is_pax_local_extensions()
                || entry_type.is_gnu_longname()
                || entry_type.is_gnu_longlink())
        {
            let metadata_bytes = entry.size();
            if metadata_bytes > limits.file_bytes {
                return Err(manifest_error(
                    archive,
                    None,
                    format!(
                        "归档元数据“{}”为 {metadata_bytes} 字节，超过 {} 字节上限",
                        relative.display(),
                        limits.file_bytes
                    ),
                ));
            }
            expanded_bytes = expanded_bytes
                .checked_add(metadata_bytes)
                .filter(|total| *total <= limits.expanded_bytes)
                .ok_or_else(|| {
                    manifest_error(
                        archive,
                        None,
                        format!("归档展开后超过 {} 字节上限", limits.expanded_bytes),
                    )
                })?;
            let copied = io::copy(&mut entry, &mut io::sink()).map_err(|error| {
                manifest_error(archive, None, format!("不能读取归档扩展元数据：{error}"))
            })?;
            if copied != metadata_bytes {
                return Err(manifest_error(
                    archive,
                    None,
                    "归档扩展元数据声明大小与实际内容不符",
                ));
            }
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
        Err(format!("制品含越界或过长路径“{}”", path.display()))
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

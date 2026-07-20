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

const TAR_BLOCK_BYTES: u64 = 512;
const TAR_RECORD_BYTES: u64 = 10 * 1024;
const TAR_PATH_RECORD_OVERHEAD_BYTES: u64 = 64;
const TAR_PATH_EXTENSION_RECORDS_PER_ENTRY: u64 = 2;

/// 对 gzip 解码后的完整 tar 字节流施加预算，而不只累计逻辑文件大小。
///
/// 每个逻辑条目预留一个 tar 头、最多一个块的内容填充，以及两组 GNU/PAX
/// 长路径扩展头与载荷；额外保留一个完整 tar record，覆盖结束块和生产器填充。
/// 因此最大合法文件内容、4096 个条目和 512 字节路径仍可由本工具读取，而
/// tar 结束标记后的高压缩数据不能绕过展开预算。
fn decoded_archive_bytes_limit(limits: ArchiveLimits) -> u64 {
    let path_payload = tar_block_padded(
        u64::try_from(limits.path_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(TAR_PATH_RECORD_OVERHEAD_BYTES),
    );
    let path_extension = TAR_BLOCK_BYTES.saturating_add(path_payload);
    let per_entry_overhead = TAR_BLOCK_BYTES
        .saturating_add(TAR_BLOCK_BYTES - 1)
        .saturating_add(TAR_PATH_EXTENSION_RECORDS_PER_ENTRY.saturating_mul(path_extension));
    limits
        .expanded_bytes
        .saturating_add(
            u64::try_from(limits.entries)
                .unwrap_or(u64::MAX)
                .saturating_mul(per_entry_overhead),
        )
        .saturating_add(TAR_RECORD_BYTES)
}

fn tar_block_padded(bytes: u64) -> u64 {
    bytes
        .saturating_add(TAR_BLOCK_BYTES - 1)
        .checked_div(TAR_BLOCK_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_mul(TAR_BLOCK_BYTES)
}

struct DecodedArchiveBudget<R> {
    inner: R,
    remaining: u64,
    limit: u64,
}

impl<R> DecodedArchiveBudget<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            limit,
        }
    }
}

impl<R: Read> Read for DecodedArchiveBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("归档解码数据超过 {} 字节硬上限", self.limit),
                )),
            };
        }
        let allowed = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

fn archive_snapshot(archive: &Path, limits: ArchiveLimits) -> Result<Vec<u8>, ManifestError> {
    let absolute = absolute_normalized(archive)?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| manifest_error(archive, None, "归档路径必须包含普通文件名"))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| manifest_error(archive, None, "归档路径缺少父目录"))?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        manifest_error(archive, None, format!("不能定位归档文件父目录：{error}"))
    })?;
    read_stable_regular_file_snapshot(&canonical_parent.join(file_name), limits.compressed_bytes)
}

fn drain_archive_reader<R: Read>(
    reader: &mut R,
    archive: &Path,
    kind: &str,
) -> Result<(), ManifestError> {
    io::copy(reader, &mut io::sink())
        .map(|_| ())
        .map_err(|error| manifest_error(archive, None, format!("{kind}数据不完整：{error}")))
}

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
    extract_tar_reader_with_limits(
        io::Cursor::new(bytes),
        archive,
        destination,
        limits,
        "Git 提交 tar ",
    )
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
    validate_existing_package_archive_with_hook(archive, limits, || Ok(()))
}

fn validate_existing_package_archive_with_hook(
    archive: &Path,
    limits: ArchiveLimits,
    after_snapshot: impl FnOnce() -> Result<(), ManifestError>,
) -> Result<(), ManifestError> {
    let bytes = archive_snapshot(archive, limits)?;
    after_snapshot()?;
    let compressed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    validate_existing_package_archive_reader(
        io::Cursor::new(bytes),
        compressed_bytes,
        archive,
        limits,
    )
}

fn validate_existing_package_archive_reader<R: Read>(
    reader: R,
    compressed_bytes: u64,
    archive: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    if compressed_bytes > limits.compressed_bytes {
        return Err(manifest_error(
            archive,
            None,
            format!("既有打包输出超过 {} 字节上限", limits.compressed_bytes),
        ));
    }
    let decoder = flate2::read::MultiGzDecoder::new(reader);
    let decoded = DecodedArchiveBudget::new(decoder, decoded_archive_bytes_limit(limits));
    let mut tar = tar::Archive::new(decoded);
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
    let mut paths = PortablePackagePaths::default();
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
        reject_archive_backslash(entry.path_bytes().as_ref(), archive)?;
        let relative = entry
            .path()
            .map_err(|error| manifest_error(archive, None, format!("既有 YXP 路径无效：{error}")))?
            .into_owned();
        validate_archive_relative_path(&relative, limits.path_bytes)
            .map_err(|message| manifest_error(archive, None, message))?;
        paths
            .insert(&relative)
            .map_err(|error| package_path_manifest_error(archive, error))?;
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
        let package_relative = relative
            .strip_prefix("package")
            .map_err(|_| manifest_error(archive, None, "源树内既有 YXP 路径不属于 package 根"))?;
        match package_path_decision(package_relative, PackagePathPurpose::YxpEntry)
            .map_err(|error| package_path_manifest_error(archive, error))?
        {
            PackagePathDecision::Include => {}
            PackagePathDecision::Exclude(_) => {
                let error =
                    package_path_decision(package_relative, PackagePathPurpose::ManifestReference)
                        .expect_err("excluded YXP path must be rejected as a manifest reference");
                return Err(package_path_manifest_error(archive, error));
            }
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
    let mut decoded = tar.into_inner();
    drain_archive_reader(&mut decoded, archive, "既有 YXP gzip ")
}

#[cfg(test)]
pub(super) fn extract_archive_with_limits(
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<(), ManifestError> {
    let bytes = archive_snapshot(archive, limits)?;
    let compressed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    extract_archive_reader_with_limits(
        io::Cursor::new(bytes),
        compressed_bytes,
        archive,
        destination,
        limits,
    )
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
    let decoder = flate2::read::MultiGzDecoder::new(reader);
    let decoded = DecodedArchiveBudget::new(decoder, decoded_archive_bytes_limit(limits));
    extract_tar_reader_with_limits(decoded, archive, destination, limits, "索引制品 gzip ")
}

fn extract_tar_reader_with_limits<R: Read>(
    reader: R,
    archive: &Path,
    destination: &Path,
    limits: ArchiveLimits,
    trailing_kind: &str,
) -> Result<(), ManifestError> {
    let mut tar = tar::Archive::new(reader);
    let entries = tar.entries().map_err(|error| {
        manifest_error(archive, None, format!("索引制品不是有效 tar.gz：{error}"))
    })?;
    let entries = entries.raw(!limits.metadata_headers);
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut paths = PortablePackagePaths::default();
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
        reject_archive_backslash(entry.path_bytes().as_ref(), archive)?;
        let relative = entry
            .path()
            .map_err(|error| manifest_error(archive, None, format!("索引制品路径无效：{error}")))?
            .into_owned();
        validate_archive_relative_path(&relative, limits.path_bytes)
            .map_err(|message| manifest_error(archive, None, message))?;
        let entry_type = entry.header().entry_type();
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
        if entry_type.is_dir() {
            paths
                .insert_directory(&relative)
                .map_err(|error| package_path_manifest_error(archive, error))?;
        } else {
            paths
                .insert(&relative)
                .map_err(|error| package_path_manifest_error(archive, error))?;
        }
        let destination_path = destination.join(&relative);
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
    let mut decoded = tar.into_inner();
    drain_archive_reader(&mut decoded, archive, trailing_kind)
}

fn reject_archive_backslash(raw: &[u8], archive: &Path) -> Result<(), ManifestError> {
    if raw.contains(&b'\\') {
        let display = String::from_utf8_lossy(raw);
        return Err(package_path_manifest_error(
            archive,
            PackagePathError {
                code: PACKAGE_PATH_NON_PORTABLE_CODE,
                message: format!("制品路径“{display}”包含反斜杠目录分隔符。"),
                path: PathBuf::from(display.into_owned()),
                component: None,
                suggestion: "请重新生成仅使用正斜杠路径的制品。".into(),
            },
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(name: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(target_os = "wasi"))]
        let root = std::env::temp_dir().join(format!(
            "yanxu-archive-{name}-{}-{sequence}",
            std::process::id()
        ));
        #[cfg(target_os = "wasi")]
        let root = Path::new("/tmp").join(format!("yanxu-archive-{name}-{sequence}"));
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn valid_tar_bytes(trailing_decoded_bytes: u64) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            (
                "package/言序.toml",
                "[包]\n格式=2\n名称='归档测试'\n版本='1.0.0'\n入口='main.yx'\n".as_bytes(),
            ),
            ("package/main.yx", "言 1；\n".as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes).unwrap();
        }
        builder.finish().unwrap();
        let mut decoded = builder.into_inner().unwrap();
        let zeros = [0_u8; 8 * 1024];
        let mut remaining = trailing_decoded_bytes;
        while remaining > 0 {
            let write = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(zeros.len());
            decoded.extend_from_slice(&zeros[..write]);
            remaining -= write as u64;
        }
        decoded
    }

    fn gzip_bytes(decoded: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(decoded).unwrap();
        encoder.finish().unwrap()
    }

    fn write_valid_archive(path: &Path, trailing_decoded_bytes: u64) -> u64 {
        let decoded = valid_tar_bytes(trailing_decoded_bytes);
        fs::write(path, gzip_bytes(&decoded)).unwrap();
        decoded.len() as u64
    }

    #[test]
    fn decoded_budget_formula_covers_exact_path_and_entry_overheads() {
        let limits = ARCHIVE_LIMITS;
        assert_eq!(limits.entries, 4_096);
        assert_eq!(limits.path_bytes, 512);
        let padded_path_record = 1024_u64;
        let extension = TAR_BLOCK_BYTES + padded_path_record;
        let per_entry = TAR_BLOCK_BYTES
            + (TAR_BLOCK_BYTES - 1)
            + TAR_PATH_EXTENSION_RECORDS_PER_ENTRY * extension;
        assert_eq!(
            decoded_archive_bytes_limit(limits),
            limits.expanded_bytes
                + u64::try_from(limits.entries).unwrap() * per_entry
                + TAR_RECORD_BYTES
        );
    }

    #[test]
    fn raw_archive_backslash_is_rejected_before_path_conversion() {
        let error =
            reject_archive_backslash(b"package\\src\\main.yx", Path::new("bad.yxp")).unwrap_err();
        assert_eq!(error.code(), PACKAGE_PATH_NON_PORTABLE_CODE);
    }

    #[cfg(any(all(unix, not(target_os = "wasi")), target_os = "wasi"))]
    #[test]
    fn archive_path_rejects_a_final_symlink() {
        let root = temporary_directory("symlink");
        let archive = root.join("real.yxp");
        let link = root.join("linked.yxp");
        write_valid_archive(&archive, 0);
        #[cfg(all(unix, not(target_os = "wasi")))]
        std::os::unix::fs::symlink(Path::new("real.yxp"), &link).unwrap();
        #[cfg(target_os = "wasi")]
        rustix::fs::symlinkat(Path::new("real.yxp"), rustix::fs::CWD, &link).unwrap();

        let error = validate_existing_package_archive(&link, ARCHIVE_LIMITS).unwrap_err();
        assert!(
            error.message.contains("符号链接")
                || error.message.contains("普通文件")
                || error.message.contains("不能预先打开"),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(all(unix, not(target_os = "wasi")))]
    #[test]
    fn archive_path_fifo_is_rejected_without_blocking() {
        const CHILD_ENV: &str = "YANXU_ARCHIVE_FIFO_CHILD";
        const TEST_NAME: &str =
            "package::archive::tests::archive_path_fifo_is_rejected_without_blocking";
        if std::env::var_os(CHILD_ENV).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg(TEST_NAME)
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "FIFO 负向测试子进程失败");
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().ok();
                    child.wait().ok();
                    panic!("FIFO 负向测试超时，归档路径打开可能发生阻塞");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = temporary_directory("fifo");
        let fifo = root.join("archive.pipe");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let error = validate_existing_package_archive(&fifo, ARCHIVE_LIMITS).unwrap_err();
        assert!(
            error.message.contains("普通文件") || error.message.contains("不能预先打开"),
            "{error}"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn archive_validation_never_reopens_a_replaced_path_after_snapshot() {
        let root = temporary_directory("path-replacement");
        let archive = root.join("package.yxp");
        let original = root.join("original.yxp");
        write_valid_archive(&archive, 0);

        validate_existing_package_archive_with_hook(&archive, ARCHIVE_LIMITS, || {
            fs::rename(&archive, &original).map_err(|error| {
                manifest_error(&archive, None, format!("不能模拟归档替换：{error}"))
            })?;
            fs::write(&archive, b"replacement is not an archive").map_err(|error| {
                manifest_error(&archive, None, format!("不能写入替换归档：{error}"))
            })?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            fs::read(&archive).unwrap(),
            b"replacement is not an archive"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn highly_compressed_trailing_decoded_data_hits_the_hard_budget() {
        let root = temporary_directory("decoded-tail-budget");
        let archive = root.join("package.yxp");
        let limits = ArchiveLimits {
            compressed_bytes: 128 * 1024,
            file_bytes: 1024,
            expanded_bytes: 1024,
            entries: 4,
            path_bytes: 512,
            metadata_headers: false,
        };
        let decoded_limit = decoded_archive_bytes_limit(limits);
        let base_bytes = valid_tar_bytes(0).len() as u64;
        let trailing = decoded_limit
            .checked_add(1)
            .and_then(|limit| limit.checked_sub(base_bytes))
            .expect("test archive must fit below decoded budget before padding");
        assert_eq!(write_valid_archive(&archive, trailing), decoded_limit + 1);
        assert!(fs::metadata(&archive).unwrap().len() < limits.compressed_bytes);

        let error = validate_existing_package_archive(&archive, limits).unwrap_err();
        assert!(error.message.contains("归档解码数据超过"), "{error}");

        let destination = root.join("output");
        let error = extract_archive_with_limits(&archive, &destination, limits).unwrap_err();
        assert!(error.message.contains("归档解码数据超过"), "{error}");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn exact_decoded_budget_boundary_is_accepted() {
        let root = temporary_directory("decoded-exact-boundary");
        let archive = root.join("package.yxp");
        let limits = ArchiveLimits {
            compressed_bytes: 128 * 1024,
            file_bytes: 1024,
            expanded_bytes: 1024,
            entries: 4,
            path_bytes: 512,
            metadata_headers: false,
        };
        let decoded_limit = decoded_archive_bytes_limit(limits);
        let base_bytes = valid_tar_bytes(0).len() as u64;
        let trailing = decoded_limit
            .checked_sub(base_bytes)
            .expect("test archive must fit below decoded budget");
        assert_eq!(write_valid_archive(&archive, trailing), decoded_limit);

        validate_existing_package_archive(&archive, limits).unwrap();
        let destination = root.join("output");
        extract_archive_with_limits(&archive, &destination, limits).unwrap();
        assert!(destination.join("package/言序.toml").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_later_gzip_member_cannot_hide_decoded_tail_data() {
        let root = temporary_directory("decoded-multi-member");
        let archive = root.join("package.yxp");
        let limits = ArchiveLimits {
            compressed_bytes: 128 * 1024,
            file_bytes: 1024,
            expanded_bytes: 1024,
            entries: 4,
            path_bytes: 512,
            metadata_headers: false,
        };
        let mut encoded = gzip_bytes(&valid_tar_bytes(0));
        encoded.extend(gzip_bytes(&vec![
            0_u8;
            usize::try_from(
                decoded_archive_bytes_limit(limits) + 1
            )
            .unwrap()
        ]));
        fs::write(&archive, encoded).unwrap();
        assert!(fs::metadata(&archive).unwrap().len() < limits.compressed_bytes);

        let error = validate_existing_package_archive(&archive, limits).unwrap_err();
        assert!(error.message.contains("归档解码数据超过"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_directory_after_its_child_is_order_independent() {
        let root = temporary_directory("reverse-directory");
        let archive_path = root.join("reverse.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            fs::File::create(&archive_path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(encoder);
        let mut file = tar::Header::new_gnu();
        file.set_size(1);
        file.set_mode(0o644);
        file.set_cksum();
        builder
            .append_data(&mut file, "package/assets/x.txt", &b"x"[..])
            .unwrap();
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_size(0);
        directory.set_mode(0o755);
        directory.set_cksum();
        builder
            .append_data(&mut directory, "package/assets", io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let destination = root.join("out");
        extract_archive_with_limits(&archive_path, &destination, ARCHIVE_LIMITS).unwrap();
        assert_eq!(
            fs::read(destination.join("package/assets/x.txt")).unwrap(),
            b"x"
        );

        let mut paths = PortablePackagePaths::default();
        paths.insert(Path::new("package/assets/x.txt")).unwrap();
        paths.insert_directory(Path::new("package/assets")).unwrap();
        assert_eq!(
            paths
                .insert(Path::new("package/assets/x.txt"))
                .unwrap_err()
                .code,
            crate::path_policy::PACKAGE_PATH_COLLISION_CODE
        );
        fs::remove_dir_all(root).unwrap();
    }
}

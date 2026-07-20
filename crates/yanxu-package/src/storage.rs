//! 包清单与锁文件的跨进程互斥和耐中断替换。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(target_os = "wasi"))]
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};

const LOCK_DIRECTORY: &str = ".yanxu";
const LOCK_NAME: &str = "package.lock";
#[cfg(not(target_os = "wasi"))]
const CACHE_LOCK_BIND_ATTEMPTS: usize = 16;
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ProjectLock {
    #[cfg(not(target_os = "wasi"))]
    file: fs::File,
    #[cfg(target_os = "wasi")]
    _file: fs::File,
}

impl ProjectLock {
    pub(crate) fn acquire(root: &Path) -> io::Result<Self> {
        let directory = root.join(LOCK_DIRECTORY);
        fs::create_dir_all(&directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(LOCK_NAME))?;
        Self::acquire_opened(file)
    }

    pub(crate) fn acquire_opened(file: fs::File) -> io::Result<Self> {
        #[cfg(not(target_os = "wasi"))]
        {
            fs2::FileExt::lock_exclusive(&file)?;
            Ok(Self { file })
        }
        #[cfg(target_os = "wasi")]
        {
            Ok(Self { _file: file })
        }
    }

    /// 从已经限定的缓存根逐级 no-follow 创建并打开锁，避免路径组件把锁文件
    /// 重定向到缓存边界外。调用方仍负责验证缓存根本身的类型与身份。
    pub(crate) fn acquire_under(root: &Path, components: &[&str]) -> io::Result<Self> {
        for component in components {
            let path = Path::new(component);
            if path.components().count() != 1
                || !matches!(
                    path.components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cache lock component must be one normal path component",
                ));
            }
        }

        #[cfg(not(target_os = "wasi"))]
        {
            Self::acquire_under_with_hook(root, components, || {})
        }
        #[cfg(target_os = "wasi")]
        {
            let mut lock_root = root.to_path_buf();
            lock_root.extend(components);
            Self::acquire(&lock_root)
        }
    }

    #[cfg(not(target_os = "wasi"))]
    fn acquire_under_with_hook(
        root: &Path,
        components: &[&str],
        mut before_file_open: impl FnMut(),
    ) -> io::Result<Self> {
        for attempt in 0..CACHE_LOCK_BIND_ATTEMPTS {
            match Self::acquire_under_once(root, components, &mut before_file_open) {
                Ok(lock) => return Ok(lock),
                Err(error)
                    if attempt + 1 < CACHE_LOCK_BIND_ATTEMPTS
                        && matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::Interrupted
                        ) =>
                {
                    std::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded cache-lock binding loop always returns")
    }

    #[cfg(not(target_os = "wasi"))]
    fn acquire_under_once(
        root: &Path,
        components: &[&str],
        before_file_open: &mut impl FnMut(),
    ) -> io::Result<Self> {
        let mut directory = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
        for component in components {
            match directory.create_dir(component) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            directory = directory.open_dir_nofollow(component)?;
        }
        match directory.create_dir(LOCK_DIRECTORY) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let state = directory.open_dir_nofollow(LOCK_DIRECTORY)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        before_file_open();
        let file = state.open_with(LOCK_NAME, &options)?.into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata_is_reparse(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache lock must be a regular non-reparse file",
            ));
        }
        Self::acquire_opened(file)
    }
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        #[cfg(not(target_os = "wasi"))]
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut pending = AtomicFile::create(path)?;
    pending.file_mut().write_all(bytes)?;
    pending.commit()
}

pub(crate) struct AtomicFile {
    destination: PathBuf,
    #[cfg(unix)]
    parent: PathBuf,
    temporary: PathBuf,
    file: Option<fs::File>,
    sequence: u64,
    committed: bool,
}

impl AtomicFile {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = temporary_path(path, sequence, "tmp");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let mut pending = Self {
            destination: path.to_path_buf(),
            #[cfg(unix)]
            parent: parent.to_path_buf(),
            temporary,
            file: Some(file),
            sequence,
            committed: false,
        };
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && !metadata_is_reparse(&metadata)
        {
            pending.file_mut().set_permissions(metadata.permissions())?;
        }

        Ok(pending)
    }

    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        self.file.as_mut().expect("pending file remains open")
    }

    pub(crate) fn commit(mut self) -> io::Result<()> {
        let file = self.file.take().expect("pending file remains open");
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        let parent = fs::File::open(&self.parent)?;
        replace(&self.temporary, &self.destination, self.sequence)?;
        self.committed = true;
        #[cfg(unix)]
        parent.sync_all()?;
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

fn temporary_path(path: &Path, sequence: u64, suffix: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "yanxu".into());
    parent.join(format!(
        ".{file_name}.{suffix}-{}-{sequence}",
        std::process::id()
    ))
}

#[cfg(not(windows))]
fn replace(temporary: &Path, destination: &Path, _sequence: u64) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace(temporary: &Path, destination: &Path, _sequence: u64) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
    };

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an interior NUL",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }

    let temporary = wide(temporary)?;
    let destination = wide(destination)?;
    // ReplaceFileW 以一个系统调用把同卷临时文件换入既有目标，整个过程中
    // 目标路径始终指向完整旧文件或完整新文件。目标尚不存在时使用不带
    // REPLACE_EXISTING 的 MoveFileExW；若并发创建了目标，该调用会安全失败。
    if unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            temporary.as_ptr(),
            ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } != 0
    {
        return Ok(());
    }
    let replace_error = io::Error::last_os_error();
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        return Ok(());
    }
    let move_error = io::Error::last_os_error();
    Err(io::Error::new(
        move_error.kind(),
        format!("atomic replacement failed: {replace_error}; atomic move failed: {move_error}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("yanxu-storage-{name}-{unique}"))
    }

    #[test]
    fn atomically_writes_a_file_in_the_current_directory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!(".yanxu-atomic-relative-{unique}"));
        atomic_write(&path, b"complete\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete\n");
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cache_lock_rebinds_after_its_open_directory_is_removed() {
        let root = temp("lock-rebind");
        fs::create_dir_all(&root).unwrap();
        let lock_root = root.join(".locks").join("checksum");
        let mut removed = false;
        let lock = ProjectLock::acquire_under_with_hook(&root, &[".locks", "checksum"], || {
            if !removed {
                fs::remove_dir_all(&lock_root).unwrap();
                removed = true;
            }
        })
        .unwrap();
        assert!(removed);
        assert!(lock_root.join(".yanxu/package.lock").is_file());
        drop(lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_and_failed_replacements_preserve_existing_destinations() {
        let root = temp("preserve-destination");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("artifact");
        fs::write(&destination, b"old complete bytes\n").unwrap();

        {
            let mut pending = AtomicFile::create(&destination).unwrap();
            pending
                .file_mut()
                .write_all(b"uncommitted bytes\n")
                .unwrap();
        }
        assert_eq!(fs::read(&destination).unwrap(), b"old complete bytes\n");

        let directory = root.join("directory-destination");
        fs::create_dir_all(&directory).unwrap();
        let mut pending = AtomicFile::create(&directory).unwrap();
        pending
            .file_mut()
            .write_all(b"replacement bytes\n")
            .unwrap();
        assert!(pending.commit().is_err());
        assert!(directory.is_dir());
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_replacement_is_always_a_complete_file() {
        let root = temp("complete-replacement");
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("artifact");
        fs::write(&destination, b"old complete bytes\n").unwrap();
        let mut pending = AtomicFile::create(&destination).unwrap();
        pending
            .file_mut()
            .write_all(b"new complete bytes\n")
            .unwrap();
        pending.commit().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new complete bytes\n");
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            !name.contains(".tmp-") && !name.contains(".backup-")
        }));
        fs::remove_dir_all(root).unwrap();
    }
}

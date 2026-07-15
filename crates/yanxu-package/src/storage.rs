//! 包清单与锁文件的跨进程互斥和耐中断替换。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const LOCK_DIRECTORY: &str = ".yanxu";
const LOCK_NAME: &str = "package.lock";
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
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        #[cfg(not(target_os = "wasi"))]
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = temporary_path(path, sequence, "tmp");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Ok(metadata) = fs::metadata(path) {
            file.set_permissions(metadata.permissions())?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace(&temporary, path, sequence)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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

fn replace(temporary: &Path, destination: &Path, sequence: u64) -> io::Result<()> {
    #[cfg(not(windows))]
    let _ = sequence;
    match fs::rename(temporary, destination) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(initial) if destination.exists() => {
            let backup = temporary_path(destination, sequence, "backup");
            fs::rename(destination, &backup)?;
            if let Err(error) = fs::rename(temporary, destination) {
                let _ = fs::rename(&backup, destination);
                return Err(io::Error::new(
                    error.kind(),
                    format!("replacement failed: {error}; initial attempt: {initial}"),
                ));
            }
            let _ = fs::remove_file(backup);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

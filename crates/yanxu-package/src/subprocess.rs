#[cfg(not(target_os = "wasi"))]
use std::fs;
#[cfg(not(target_os = "wasi"))]
use std::io::{self, Read};
use std::path::Path;
#[cfg(not(target_os = "wasi"))]
use std::path::PathBuf;
#[cfg(not(target_os = "wasi"))]
use std::process::{Child, Stdio};
use std::process::{Command, ExitStatus};
#[cfg(not(target_os = "wasi"))]
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(not(target_os = "wasi"))]
use std::sync::atomic::Ordering;
#[cfg(not(target_os = "wasi"))]
use std::thread;
use std::time::Duration;
#[cfg(not(target_os = "wasi"))]
use std::time::Instant;

#[cfg(not(target_os = "wasi"))]
use cap_fs_ext::DirExt as _;

#[cfg(not(target_os = "wasi"))]
const POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(not(target_os = "wasi"))]
const DISK_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
#[cfg_attr(target_os = "wasi", allow(dead_code))]
pub(crate) struct DiskBudget<'a> {
    pub(crate) root: &'a Path,
    pub(crate) max_bytes: u64,
    pub(crate) max_entries: usize,
    pub(crate) max_depth: usize,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(target_os = "wasi", allow(dead_code))]
pub(crate) struct CommandBudget<'a> {
    pub(crate) timeout: Duration,
    pub(crate) stdout_bytes: usize,
    pub(crate) stderr_bytes: usize,
    pub(crate) disk: Option<DiskBudget<'a>>,
    pub(crate) cancellation: Option<&'a AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "wasi", allow(dead_code))]
pub(crate) enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
#[cfg_attr(target_os = "wasi", allow(dead_code))]
pub(crate) enum CommandFailure {
    Spawn,
    Containment,
    Wait,
    ReaderSpawn(OutputStream),
    Read(OutputStream),
    ReaderPanicked(OutputStream),
    Timeout(Duration),
    Cancelled,
    OutputLimit {
        stream: OutputStream,
        max_bytes: usize,
    },
    DiskBytes(u64),
    DiskEntries(usize),
    DiskDepth(usize),
    DiskSpecial,
    DiskRead,
    #[cfg(target_os = "wasi")]
    Unsupported,
}

#[cfg(not(target_os = "wasi"))]
enum ReaderResult {
    Complete(Vec<u8>),
    Limit,
    Failed,
}

#[cfg(not(target_os = "wasi"))]
struct CommandControl<'a> {
    deadline: Instant,
    timeout: Duration,
    cancellation: Option<&'a AtomicBool>,
}

#[cfg(not(target_os = "wasi"))]
impl CommandControl<'_> {
    fn check(&self) -> Result<(), CommandFailure> {
        if self
            .cancellation
            .is_some_and(|cancellation| cancellation.load(Ordering::Acquire))
        {
            return Err(CommandFailure::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(CommandFailure::Timeout(self.timeout));
        }
        Ok(())
    }
}

pub(crate) fn run(
    command: &mut Command,
    budget: CommandBudget<'_>,
) -> Result<CommandOutput, CommandFailure> {
    #[cfg(target_os = "wasi")]
    {
        let _ = (command, budget);
        Err(CommandFailure::Unsupported)
    }

    #[cfg(not(target_os = "wasi"))]
    {
        run_supported(command, budget)
    }
}

#[cfg(not(target_os = "wasi"))]
fn run_supported(
    command: &mut Command,
    budget: CommandBudget<'_>,
) -> Result<CommandOutput, CommandFailure> {
    let started = Instant::now();
    let deadline = started.checked_add(budget.timeout).unwrap_or(started);
    let control = CommandControl {
        deadline,
        timeout: budget.timeout,
        cancellation: budget.cancellation,
    };
    control.check()?;
    let disk_monitor = budget
        .disk
        .map(|disk| DiskMonitor::open(disk, &control))
        .transpose()?;
    control.check()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare_containment(command);
    let mut child = command.spawn().map_err(|_| CommandFailure::Spawn)?;
    let containment = match ChildContainment::attach(&mut child) {
        Ok(containment) => containment,
        Err(()) => {
            terminate_uncontained_child(&mut child);
            let _ = child.wait();
            return Err(CommandFailure::Containment);
        }
    };
    let mut child = ContainedChild::new(child, containment);
    control.check()?;
    let stdout = child.child.stdout.take().ok_or(CommandFailure::Spawn)?;
    let stderr = child.child.stderr.take().ok_or(CommandFailure::Spawn)?;
    let stdout_limit = Arc::new(AtomicBool::new(false));
    let stderr_limit = Arc::new(AtomicBool::new(false));
    let stdout_failed = Arc::new(AtomicBool::new(false));
    let stderr_failed = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_reader(
        stdout,
        OutputStream::Stdout,
        budget.stdout_bytes,
        stdout_limit.clone(),
        stdout_failed.clone(),
    )?;
    let stderr_reader = match spawn_reader(
        stderr,
        OutputStream::Stderr,
        budget.stderr_bytes,
        stderr_limit.clone(),
        stderr_failed.clone(),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            child.terminate_and_reap();
            let _ = join_reader(stdout_reader, OutputStream::Stdout);
            return Err(error);
        }
    };
    let monitoring_started = Instant::now();
    let mut next_disk_check = monitoring_started
        .checked_add(DISK_POLL_INTERVAL)
        .unwrap_or(monitoring_started);

    let outcome = loop {
        if let Err(error) = control.check() {
            break Err(error);
        }
        if stdout_limit.load(Ordering::Acquire) {
            break Err(CommandFailure::OutputLimit {
                stream: OutputStream::Stdout,
                max_bytes: budget.stdout_bytes,
            });
        }
        if stderr_limit.load(Ordering::Acquire) {
            break Err(CommandFailure::OutputLimit {
                stream: OutputStream::Stderr,
                max_bytes: budget.stderr_bytes,
            });
        }
        if stdout_failed.load(Ordering::Acquire) {
            break Err(CommandFailure::Read(OutputStream::Stdout));
        }
        if stderr_failed.load(Ordering::Acquire) {
            break Err(CommandFailure::Read(OutputStream::Stderr));
        }
        match child.child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(_) => break Err(CommandFailure::Wait),
        }
        let now = Instant::now();
        if now >= next_disk_check {
            if let Some(monitor) = &disk_monitor
                && let Err(error) = monitor.check(&control)
            {
                break Err(error);
            }
            next_disk_check = now.checked_add(DISK_POLL_INTERVAL).unwrap_or(now);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    };

    child.terminate_and_reap();
    let stdout_joined = join_reader(stdout_reader, OutputStream::Stdout);
    let stderr_joined = join_reader(stderr_reader, OutputStream::Stderr);

    if stdout_limit.load(Ordering::Acquire) || matches!(stdout_joined, Ok(ReaderResult::Limit)) {
        return Err(CommandFailure::OutputLimit {
            stream: OutputStream::Stdout,
            max_bytes: budget.stdout_bytes,
        });
    }
    if stderr_limit.load(Ordering::Acquire) || matches!(stderr_joined, Ok(ReaderResult::Limit)) {
        return Err(CommandFailure::OutputLimit {
            stream: OutputStream::Stderr,
            max_bytes: budget.stderr_bytes,
        });
    }
    let status = outcome?;
    let stdout = match stdout_joined? {
        ReaderResult::Complete(stdout) => stdout,
        ReaderResult::Failed => return Err(CommandFailure::Read(OutputStream::Stdout)),
        ReaderResult::Limit => unreachable!("output limit handled above"),
    };
    match stderr_joined? {
        ReaderResult::Complete(_) => {}
        ReaderResult::Failed => return Err(CommandFailure::Read(OutputStream::Stderr)),
        ReaderResult::Limit => unreachable!("output limit handled above"),
    }
    if let Some(monitor) = &disk_monitor {
        monitor.check(&control)?;
    }
    Ok(CommandOutput { status, stdout })
}

#[cfg(not(target_os = "wasi"))]
fn spawn_reader(
    reader: impl Read + Send + 'static,
    stream: OutputStream,
    max_bytes: usize,
    limit_reached: Arc<AtomicBool>,
    read_failed: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<ReaderResult>, CommandFailure> {
    let name = match stream {
        OutputStream::Stdout => "yanxu-subprocess-stdout",
        OutputStream::Stderr => "yanxu-subprocess-stderr",
    };
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_bounded(reader, max_bytes, &limit_reached, &read_failed)
            }));
            match result {
                Ok(result) => result,
                Err(payload) => {
                    read_failed.store(true, Ordering::Release);
                    std::panic::resume_unwind(payload)
                }
            }
        })
        .map_err(|_| CommandFailure::ReaderSpawn(stream))
}

#[cfg(not(target_os = "wasi"))]
fn read_bounded(
    mut reader: impl Read,
    max_bytes: usize,
    limit_reached: &AtomicBool,
    read_failed: &AtomicBool,
) -> ReaderResult {
    let mut retained = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let length = match reader.read(&mut buffer) {
            Ok(0) => {
                return if limit_reached.load(Ordering::Acquire) {
                    ReaderResult::Limit
                } else {
                    ReaderResult::Complete(retained)
                };
            }
            Ok(length) => length,
            Err(_) => {
                read_failed.store(true, Ordering::Release);
                return ReaderResult::Failed;
            }
        };
        if retained.len().saturating_add(length) > max_bytes {
            limit_reached.store(true, Ordering::Release);
            return ReaderResult::Limit;
        }
        retained.extend_from_slice(&buffer[..length]);
    }
}

#[cfg(not(target_os = "wasi"))]
fn join_reader(
    reader: thread::JoinHandle<ReaderResult>,
    stream: OutputStream,
) -> Result<ReaderResult, CommandFailure> {
    reader
        .join()
        .map_err(|_| CommandFailure::ReaderPanicked(stream))
}

#[cfg(not(target_os = "wasi"))]
struct DiskMonitor {
    display_root: PathBuf,
    root: cap_std::fs::Dir,
    max_bytes: u64,
    max_entries: usize,
    max_depth: usize,
}

#[cfg(not(target_os = "wasi"))]
impl DiskMonitor {
    fn open(budget: DiskBudget<'_>, control: &CommandControl<'_>) -> Result<Self, CommandFailure> {
        let root = cap_std::fs::Dir::open_ambient_dir(budget.root, cap_std::ambient_authority())
            .map_err(|_| CommandFailure::DiskRead)?;
        let monitor = Self {
            display_root: budget.root.to_path_buf(),
            root,
            max_bytes: budget.max_bytes,
            max_entries: budget.max_entries,
            max_depth: budget.max_depth,
        };
        monitor.check(control)?;
        Ok(monitor)
    }

    fn verify_binding(&self) -> Result<(), CommandFailure> {
        let path_metadata =
            fs::symlink_metadata(&self.display_root).map_err(|_| CommandFailure::DiskRead)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || crate::package::standard_metadata_is_reparse(&path_metadata)
        {
            return Err(CommandFailure::DiskSpecial);
        }
        let current =
            cap_std::fs::Dir::open_ambient_dir(&self.display_root, cap_std::ambient_authority())
                .map_err(|_| CommandFailure::DiskRead)?;
        let metadata = current
            .dir_metadata()
            .map_err(|_| CommandFailure::DiskRead)?;
        if !metadata.is_dir() || crate::package::cap_metadata_is_reparse(&metadata) {
            return Err(CommandFailure::DiskSpecial);
        }
        match crate::path_policy::same_opened_directory_identity(&self.root, &current) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CommandFailure::DiskSpecial),
            Err(_) => Err(CommandFailure::DiskRead),
        }
    }

    fn check(&self, control: &CommandControl<'_>) -> Result<(), CommandFailure> {
        control.check()?;
        self.verify_binding()?;
        let root = self
            .root
            .try_clone()
            .map_err(|_| CommandFailure::DiskRead)?;
        let mut pending = vec![(root, 0_usize)];
        let mut bytes = 0_u64;
        let mut entries = 0_usize;
        while let Some((directory, depth)) = pending.pop() {
            let children = directory.entries().map_err(|_| CommandFailure::DiskRead)?;
            for child in children {
                let child = child.map_err(|_| CommandFailure::DiskRead)?;
                entries = entries.saturating_add(1);
                if entries.is_multiple_of(256) {
                    control.check()?;
                }
                if entries > self.max_entries {
                    return Err(CommandFailure::DiskEntries(self.max_entries));
                }
                let name = child.file_name();
                let metadata = match directory.symlink_metadata(&name) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(CommandFailure::DiskRead),
                };
                if metadata.file_type().is_symlink()
                    || crate::package::cap_metadata_is_reparse(&metadata)
                {
                    return Err(CommandFailure::DiskSpecial);
                }
                if metadata.is_dir() {
                    let child_depth = depth.saturating_add(1);
                    if child_depth > self.max_depth {
                        return Err(CommandFailure::DiskDepth(self.max_depth));
                    }
                    let child = match directory.open_dir_nofollow(&name) {
                        Ok(child) => child,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(_) => return Err(CommandFailure::DiskRead),
                    };
                    let opened = child.dir_metadata().map_err(|_| CommandFailure::DiskRead)?;
                    if !opened.is_dir() || crate::package::cap_metadata_is_reparse(&opened) {
                        return Err(CommandFailure::DiskSpecial);
                    }
                    pending.push((child, child_depth));
                } else if metadata.is_file() {
                    bytes = bytes
                        .checked_add(measured_file_bytes(&metadata))
                        .ok_or(CommandFailure::DiskBytes(self.max_bytes))?;
                    if bytes > self.max_bytes {
                        return Err(CommandFailure::DiskBytes(self.max_bytes));
                    }
                } else {
                    return Err(CommandFailure::DiskSpecial);
                }
            }
        }
        control.check()?;
        self.verify_binding()
    }
}

#[cfg(all(unix, not(target_os = "wasi")))]
fn measured_file_bytes(metadata: &cap_std::fs::Metadata) -> u64 {
    use cap_std::fs::MetadataExt as _;

    metadata.len().max(metadata.blocks().saturating_mul(512))
}

#[cfg(all(not(unix), not(target_os = "wasi")))]
fn measured_file_bytes(metadata: &cap_std::fs::Metadata) -> u64 {
    metadata.len()
}

#[cfg(not(target_os = "wasi"))]
struct ContainedChild {
    child: Child,
    containment: ChildContainment,
    reaped: bool,
}

#[cfg(not(target_os = "wasi"))]
impl ContainedChild {
    fn new(child: Child, containment: ChildContainment) -> Self {
        Self {
            child,
            containment,
            reaped: false,
        }
    }

    fn terminate_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        self.containment.terminate(&mut self.child);
        let _ = self.child.wait();
        self.reaped = true;
    }
}

#[cfg(not(target_os = "wasi"))]
impl Drop for ContainedChild {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

#[cfg(all(unix, not(target_os = "wasi")))]
fn prepare_containment(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(windows)]
fn prepare_containment(command: &mut Command) {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    command.creation_flags(CREATE_SUSPENDED);
}

#[cfg(all(not(any(unix, windows)), not(target_os = "wasi")))]
fn prepare_containment(_command: &mut Command) {}

#[cfg(all(unix, not(target_os = "wasi")))]
fn terminate_uncontained_child(child: &mut Child) {
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        // `prepare_containment` establishes this group before exec.  Kill the
        // group as well as its leader if watchdog creation fails after spawn.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(all(unix, not(target_os = "wasi")))]
fn open_descriptor_limit() -> libc::c_int {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0
        && limit.rlim_cur != libc::RLIM_INFINITY
    {
        return limit.rlim_cur.min(libc::c_int::MAX as _) as libc::c_int;
    }
    65_536
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(target_os = "wasi")
))]
fn close_watchdog_descriptors(keep: libc::c_int, max_descriptor: libc::c_int) {
    let keep = keep as libc::c_uint;
    let lower_closed = keep == 0
        || unsafe {
            libc::syscall(
                libc::SYS_close_range,
                0 as libc::c_uint,
                keep - 1,
                0 as libc::c_uint,
            )
        } == 0;
    let upper_closed = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            keep + 1,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        )
    } == 0;
    if lower_closed && upper_closed {
        return;
    }
    for descriptor in 0..max_descriptor {
        if descriptor != keep as libc::c_int {
            unsafe {
                libc::close(descriptor);
            }
        }
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "wasi"))
))]
fn close_watchdog_descriptors(keep: libc::c_int, max_descriptor: libc::c_int) {
    for descriptor in 0..max_descriptor {
        if descriptor != keep {
            unsafe {
                libc::close(descriptor);
            }
        }
    }
}

#[cfg(all(not(unix), not(target_os = "wasi")))]
fn terminate_uncontained_child(child: &mut Child) {
    // Windows children have not been resumed yet.  Other supported targets do
    // not provide a stronger containment primitive at this point.
    let _ = child.kill();
}

#[cfg(all(unix, not(target_os = "wasi")))]
struct ChildContainment {
    group: libc::pid_t,
    monitor: Option<libc::pid_t>,
    parent_guard: Option<libc::c_int>,
}

#[cfg(all(unix, not(target_os = "wasi")))]
impl ChildContainment {
    fn attach(child: &mut Child) -> Result<Self, ()> {
        use std::os::fd::IntoRawFd as _;
        use std::os::unix::net::UnixStream;

        let group = libc::pid_t::try_from(child.id()).map_err(|_| ())?;
        let parent = unsafe { libc::getpid() };
        let max_descriptor = open_descriptor_limit();
        let (read_guard, write_guard) = UnixStream::pair().map_err(|_| ())?;
        let pipe = [read_guard.into_raw_fd(), write_guard.into_raw_fd()];
        let monitor = unsafe { libc::fork() };
        if monitor == -1 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(());
        }
        if monitor == 0 {
            close_watchdog_descriptors(pipe[0], max_descriptor);
            unsafe {
                libc::setsid();
                let mut byte = 0_u8;
                let mut event = libc::pollfd {
                    fd: pipe[0],
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                };
                loop {
                    if libc::getppid() != parent {
                        break;
                    }
                    if libc::poll(&raw mut event, 1, 20) <= 0 {
                        continue;
                    }
                    let read = libc::read(pipe[0], (&raw mut byte).cast(), 1);
                    if read == 0 {
                        break;
                    }
                    if read > 0 {
                        continue;
                    }
                }
                libc::close(pipe[0]);
                libc::kill(-group, libc::SIGKILL);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[0]);
        }
        Ok(Self {
            group,
            monitor: Some(monitor),
            parent_guard: Some(pipe[1]),
        })
    }

    fn terminate(&mut self, child: &mut Child) {
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
        }
        let _ = child.kill();
        self.stop_monitor();
    }

    fn stop_monitor(&mut self) {
        if let Some(parent_guard) = self.parent_guard.take() {
            unsafe {
                libc::close(parent_guard);
            }
        }
        if let Some(monitor) = self.monitor.take() {
            unsafe {
                libc::kill(monitor, libc::SIGKILL);
            }
            loop {
                let waited = unsafe { libc::waitpid(monitor, std::ptr::null_mut(), 0) };
                if waited == monitor {
                    break;
                }
                if waited == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "wasi")))]
impl Drop for ChildContainment {
    fn drop(&mut self) {
        self.stop_monitor();
    }
}

#[cfg(windows)]
struct ChildContainment {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl ChildContainment {
    fn attach(child: &mut Child) -> Result<Self, ()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(());
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                std::mem::size_of_val(&information) as u32,
            )
        } != 0;
        let assigned =
            configured && unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } != 0;
        if !assigned || resume_process_threads(child.id()).is_err() {
            unsafe {
                windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1);
                windows_sys::Win32::Foundation::CloseHandle(job);
            }
            return Err(());
        }
        Ok(Self { job })
    }

    fn terminate(&self, child: &mut Child) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
        }
        let _ = child.kill();
    }
}

#[cfg(windows)]
impl Drop for ChildContainment {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

#[cfg(windows)]
fn resume_process_threads(process_id: u32) -> Result<(), ()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(());
    }
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    let mut found = false;
    let mut available = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while available {
        if entry.th32OwnerProcessID == process_id {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                unsafe {
                    CloseHandle(snapshot);
                }
                return Err(());
            }
            let resumed = unsafe { ResumeThread(thread) };
            unsafe {
                CloseHandle(thread);
            }
            if resumed == u32::MAX {
                unsafe {
                    CloseHandle(snapshot);
                }
                return Err(());
            }
            found = true;
        }
        available = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    found.then_some(()).ok_or(())
}

#[cfg(all(not(any(unix, windows)), not(target_os = "wasi")))]
struct ChildContainment;

#[cfg(all(not(any(unix, windows)), not(target_os = "wasi")))]
impl ChildContainment {
    fn attach(_child: &mut Child) -> Result<Self, ()> {
        Ok(Self)
    }

    fn terminate(&self, child: &mut Child) {
        let _ = child.kill();
    }
}

#[cfg(all(test, unix, not(target_os = "wasi")))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn subprocess_watchdog_closes_unrelated_inherited_descriptors() {
        let (mut probe_reader, probe_writer) = UnixStream::pair().unwrap();
        probe_reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_containment(&mut command);
        let mut child = command.spawn().unwrap();
        let containment = ChildContainment::attach(&mut child).unwrap();
        let mut child = ContainedChild::new(child, containment);

        drop(probe_writer);
        let mut byte = [0_u8; 1];
        assert_eq!(probe_reader.read(&mut byte).unwrap(), 0);
        child.terminate_and_reap();
    }
}

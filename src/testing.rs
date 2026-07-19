//! `.yx` 规格测试发现、并发执行与报告。

use crate::interpreter::Interpreter;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
static ACTIVE_TEST_EXECUTIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static PEAK_TEST_EXECUTIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
struct ActiveTestExecution;

#[cfg(test)]
impl ActiveTestExecution {
    fn begin() -> Self {
        let active = ACTIVE_TEST_EXECUTIONS.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK_TEST_EXECUTIONS.fetch_max(active, Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for ActiveTestExecution {
    fn drop(&mut self) {
        ACTIVE_TEST_EXECUTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct TestOptions {
    pub filter: Option<String>,
    pub jobs: usize,
    pub timeout: Duration,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            filter: None,
            jobs: thread::available_parallelism().map_or(1, usize::from),
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Passed,
    Failed,
    ExpectedFailure,
    UnexpectedPass,
    TimedOut,
}

impl TestStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Passed => "成",
            Self::Failed => "败",
            Self::ExpectedFailure => "预败",
            Self::UnexpectedPass => "意外成",
            Self::TimedOut => "超时",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestCaseResult {
    pub path: PathBuf,
    pub passed: bool,
    pub status: TestStatus,
    pub detail: String,
    pub duration_ms: u128,
}

pub fn discover(path: impl AsRef<Path>) -> Result<Vec<PathBuf>, String> {
    discover_with_root(path).map(|(_, files)| {
        files
            .into_iter()
            .map(|file| file.path().to_path_buf())
            .collect()
    })
}

pub(crate) fn discover_with_root(
    path: impl AsRef<Path>,
) -> Result<(PathBuf, Vec<crate::package::ResolvedPackageFileSnapshot>), String> {
    let requested = path.as_ref();
    if fs::symlink_metadata(requested).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!("测试入口不得为符号链接“{}”", requested.display()));
    }
    let requested_absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("不能定位当前目录：{error}"))?
            .join(requested)
    };
    let mut roots = testing_package_roots(&requested_absolute)?;
    if let Some(root) = roots.matching_root(&requested_absolute)
        && root != requested_absolute
    {
        roots
            .authorize_module(&requested_absolute, &requested_absolute)
            .map_err(|error| error.to_string())?;
    }
    let path = if roots
        .matching_root(&requested_absolute)
        .is_some_and(|root| root == requested_absolute)
    {
        fs::canonicalize(&requested_absolute)
            .map_err(|error| format!("不能定位“{}”：{error}", requested.display()))?
    } else {
        match roots
            .resolve_existing_module_path(&requested_absolute)
            .map_err(|error| error.to_string())?
        {
            Some(path) => path,
            None => fs::canonicalize(&requested_absolute)
                .map_err(|error| format!("不能定位“{}”：{error}", requested.display()))?,
        }
    };
    roots
        .insert_discovered(&path)
        .map_err(|error| error.to_string())?;
    let is_file = path.is_file();
    if roots.matching_root(&path).is_none() {
        let explicit_root = if is_file {
            path.parent().unwrap_or_else(|| Path::new("."))
        } else {
            &path
        };
        roots
            .insert(explicit_root)
            .map_err(|error| error.to_string())?;
    }
    if is_file {
        roots
            .authorize_module(&requested_absolute, &path)
            .map_err(|error| error.to_string())?;
        let file = roots
            .snapshot_existing_module_file(&path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("测试文卷不属于已打开的目录“{}”", path.display()))?;
        return Ok((path, vec![file]));
    }
    if roots.roots().all(|root| root != path) {
        roots
            .authorize_module(&requested_absolute, &path)
            .map_err(|error| error.to_string())?;
    }
    let files = roots
        .snapshot_module_directory(&path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("测试目录不属于已打开的根能力“{}”", path.display()))?;
    Ok((path, files))
}

pub fn run(path: impl AsRef<Path>) -> Result<Vec<TestCaseResult>, String> {
    run_with_options(path, &TestOptions::default())
}

pub fn run_with_options(
    path: impl AsRef<Path>,
    options: &TestOptions,
) -> Result<Vec<TestCaseResult>, String> {
    if options.jobs == 0 {
        return Err("并发数须大于零".into());
    }
    if options.timeout.is_zero() {
        return Err("超时须大于零".into());
    }
    let (_, mut paths) = discover_with_root(path)?;
    if let Some(filter) = options.filter.as_deref() {
        paths.retain(|path| path.path().to_string_lossy().contains(filter));
    }
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let count = paths.len();
    let queue = Arc::new(Mutex::new(VecDeque::from(paths)));
    let (sender, receiver) = mpsc::channel();
    let workers = options.jobs.min(count);
    let mut worker_handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let queue = queue.clone();
        let sender = sender.clone();
        let timeout = options.timeout;
        worker_handles.push(thread::spawn(move || {
            loop {
                let path = queue.lock().expect("test queue poisoned").pop_front();
                let Some(path) = path else {
                    break;
                };
                let _ = sender.send(run_case_with_timeout(path, timeout));
            }
        }));
    }
    drop(sender);

    let mut results = Vec::with_capacity(count);
    let mut failure = None;
    for _ in 0..count {
        match receiver.recv() {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(error)) => {
                failure.get_or_insert(error);
            }
            Err(_) => {
                failure.get_or_insert_with(|| "测试工作线程意外终止".to_string());
                break;
            }
        }
    }
    for worker in worker_handles {
        if worker.join().is_err() {
            failure.get_or_insert_with(|| "测试工作线程发生内部恐慌".to_string());
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if results.len() != count {
        return Err("测试工作线程没有返回全部结果".into());
    }
    results.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(results)
}

pub const TEST_REPORT_SCHEMA_VERSION: u32 = 1;

pub fn machine_report(results: &[TestCaseResult]) -> Value {
    let passed = results.iter().filter(|result| result.passed).count();
    let expected_failures = results
        .iter()
        .filter(|result| result.status == TestStatus::ExpectedFailure)
        .count();
    let timed_out = results
        .iter()
        .filter(|result| result.status == TestStatus::TimedOut)
        .count();
    json!({
        "schema": "https://yanxu.dev/schemas/test-report-v1.json",
        "schema_version": TEST_REPORT_SCHEMA_VERSION,
        "summary": {
            "total": results.len(),
            "passed": passed,
            "failed": results.len() - passed,
            "expectedFailures": expected_failures,
            "timedOut": timed_out
        },
        "tests": results
    })
}

fn run_case_with_timeout(
    file: crate::package::ResolvedPackageFileSnapshot,
    timeout: Duration,
) -> Result<TestCaseResult, String> {
    #[cfg(test)]
    let _active = ActiveTestExecution::begin();
    let path = file.path().to_path_buf();
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_case(file, started, timeout)
    }))
    .unwrap_or_else(|_| {
        Ok(TestCaseResult {
            path: path.clone(),
            passed: false,
            status: TestStatus::Failed,
            detail: "测试执行时发生内部恐慌".into(),
            duration_ms: 0,
        })
    });
    let elapsed = started.elapsed();
    if elapsed >= timeout {
        Ok(TestCaseResult {
            path,
            passed: false,
            status: TestStatus::TimedOut,
            detail: format!("超过 {} 毫秒", timeout.as_millis()),
            duration_ms: elapsed.as_millis(),
        })
    } else {
        result.map(|mut result| {
            result.duration_ms = elapsed.as_millis();
            result
        })
    }
}

fn run_case(
    file: crate::package::ResolvedPackageFileSnapshot,
    started: Instant,
    timeout: Duration,
) -> Result<TestCaseResult, String> {
    let canonical = file.path().to_path_buf();
    let opened_roots = file.opened_roots();
    let resolved = file.open().map_err(|error| error.to_string())?;
    let source = crate::package::read_resolved_module_source_snapshot(resolved)
        .map_err(|error| format!("不能读取“{}”：{error}", canonical.display()))?;
    let expected = expectations(&source);
    let expected_failure = expected_failure(&source);
    let mut interpreter = Interpreter::silent();
    let execution = match crate::parse_named(&source, canonical.display().to_string()) {
        Ok(statements) => {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or_else(|| "EXECUTION_TIMEOUT：读取和解析已耗尽测试时间预算".to_string())?;
            if remaining.is_zero() {
                return Err("EXECUTION_TIMEOUT：读取和解析已耗尽测试时间预算".into());
            }
            interpreter.set_time_limit(remaining);
            interpreter
                .execute_in_directory_with_opened_roots(
                    &statements,
                    canonical.parent().unwrap_or_else(|| Path::new(".")),
                    &opened_roots,
                )
                .map_err(crate::YanxuError::Runtime)
        }
        Err(error) => Err(error),
    };
    let (raw_passed, detail) = match execution {
        Ok(_) if expected.is_empty() || expected == interpreter.output() => (
            true,
            if expected.is_empty() {
                "执行成功".into()
            } else {
                format!("输出 {} 行，与期望相符", expected.len())
            },
        ),
        Ok(_) => (
            false,
            format!("期望 {:?}，实得 {:?}", expected, interpreter.output()),
        ),
        Err(error) => (false, error.to_string()),
    };

    let (passed, status, detail) = match (expected_failure, raw_passed) {
        (Some(reason), false) if reason.is_empty() || detail.contains(&reason) => (
            true,
            TestStatus::ExpectedFailure,
            format!("按期失败：{detail}"),
        ),
        (Some(reason), false) => (
            false,
            TestStatus::Failed,
            format!("预期失败须含“{reason}”，实得：{detail}"),
        ),
        (Some(_), true) => (
            false,
            TestStatus::UnexpectedPass,
            "标记为预期失败，但实际通过".into(),
        ),
        (None, true) => (true, TestStatus::Passed, detail),
        (None, false) => (false, TestStatus::Failed, detail),
    };
    Ok(TestCaseResult {
        path: canonical,
        passed,
        status,
        detail,
        duration_ms: 0,
    })
}

fn testing_package_roots(path: &Path) -> Result<crate::package::TrustedPackageRoots, String> {
    let mut roots = crate::package::TrustedPackageRoots::default();
    roots
        .insert_discovered(path)
        .map_err(|error| error.to_string())?;
    Ok(roots)
}

fn expectations(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("// 期：")
                .or_else(|| line.strip_prefix("# 期："))
                .map(str::to_owned)
        })
        .collect()
}

fn expected_failure(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("// 预败")
            .or_else(|| line.strip_prefix("# 预败"))
            .map(|reason| {
                reason
                    .trim_start_matches(['：', ':', ' '])
                    .trim()
                    .to_owned()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    static RUN_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn reads_ordered_output_expectations_and_expected_failure() {
        assert_eq!(
            expectations("# 期：甲\n言「甲」；\n// 期：乙"),
            ["甲", "乙"]
        );
        assert_eq!(
            expected_failure("# 预败：不可除以零"),
            Some("不可除以零".into())
        );
    }

    #[test]
    fn filters_runs_concurrently_and_reports_expected_failures_as_json() {
        let _run = RUN_TEST_LOCK.lock().unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-tests-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("通过.yx"), "# 期：善\n言「善」；").unwrap();
        fs::write(root.join("预败.yx"), "# 预败：不可除以零\n言 1 除 0；").unwrap();
        fs::write(root.join("忽略.yx"), "言 未知；").unwrap();

        let options = TestOptions {
            filter: Some("通过".into()),
            jobs: 2,
            timeout: Duration::from_secs(1),
        };
        let filtered = run_with_options(&root, &options).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].status, TestStatus::Passed);

        let mut options = options;
        options.filter = Some("预败".into());
        let expected = run_with_options(&root, &options).unwrap();
        assert_eq!(expected[0].status, TestStatus::ExpectedFailure);
        assert!(expected[0].passed);
        let report = machine_report(&expected);
        assert_eq!(report["schema_version"], TEST_REPORT_SCHEMA_VERSION);
        assert_eq!(report["summary"]["expectedFailures"], 1);
        assert_eq!(report["tests"][0]["status"], "expected_failure");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn discovered_test_uses_the_opened_root_after_path_replacement() {
        let _run = RUN_TEST_LOCK.lock().unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-test-snapshot-{unique}"));
        let backup = root.with_extension("original");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("用例.yx"),
            "引「辅助.yx」为 辅助；\n# 期：原根\n言 辅助.值；\n",
        )
        .unwrap();
        fs::write(root.join("辅助.yx"), "公 定 值：文 为「原根」；\n").unwrap();
        let (_, mut files) = discover_with_root(&root).unwrap();
        assert_eq!(files.len(), 2);

        fs::rename(&root, &backup).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("用例.yx"),
            "引「辅助.yx」为 辅助；\n# 期：替换根\n言 辅助.值；\n",
        )
        .unwrap();
        fs::write(root.join("辅助.yx"), "公 定 值：文 为「替换根」；\n").unwrap();

        let index = files
            .iter()
            .position(|file| file.path().ends_with("用例.yx"))
            .unwrap();
        let result = run_case_with_timeout(files.remove(index), Duration::from_secs(1)).unwrap();
        assert!(result.passed, "{result:#?}");
        assert_eq!(result.status, TestStatus::Passed);
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[cfg(all(not(windows), not(target_os = "wasi")))]
    #[test]
    fn discovered_test_does_not_trust_a_replacement_nested_package_root() {
        let _run = RUN_TEST_LOCK.lock().unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-test-nested-snapshot-{unique}"));
        let backup = root.with_extension("original");
        fs::create_dir_all(root.join("子目录")).unwrap();
        fs::write(
            root.join("子目录/用例.yx"),
            "引「辅助.yx」为 辅助；\n# 期：原根\n言 辅助.值；\n",
        )
        .unwrap();
        fs::write(root.join("子目录/辅助.yx"), "公 定 值：文 为「原根」；\n").unwrap();
        let (_, mut files) = discover_with_root(&root).unwrap();

        fs::rename(&root, &backup).unwrap();
        fs::create_dir_all(root.join("子目录")).unwrap();
        fs::write(
            root.join("子目录/言序.toml"),
            "[包]\n格式 = 2\n名称 = \"替换包\"\n版本 = \"0.1.0\"\n言序 = \">=1.1.15\"\n入口 = \"用例.yx\"\n\n[依赖]\n",
        )
        .unwrap();
        fs::write(
            root.join("子目录/用例.yx"),
            "引「辅助.yx」为 辅助；\n# 期：替换根\n言 辅助.值；\n",
        )
        .unwrap();
        fs::write(root.join("子目录/辅助.yx"), "公 定 值：文 为「替换根」；\n").unwrap();

        let index = files
            .iter()
            .position(|file| file.path().ends_with("子目录/用例.yx"))
            .unwrap();
        let result = run_case_with_timeout(files.remove(index), Duration::from_secs(1)).unwrap();
        assert!(result.passed, "{result:#?}");
        assert_eq!(result.status, TestStatus::Passed);
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(backup).ok();
    }

    #[test]
    fn repeated_timeouts_stop_every_execution_and_respect_the_worker_limit() {
        let _run = RUN_TEST_LOCK.lock().unwrap();
        assert_eq!(ACTIVE_TEST_EXECUTIONS.load(Ordering::SeqCst), 0);
        PEAK_TEST_EXECUTIONS.store(0, Ordering::SeqCst);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-timeout-tests-{unique}"));
        fs::create_dir_all(&root).unwrap();
        for index in 0..8 {
            fs::write(root.join(format!("超时-{index}.yx")), "当 真 则\n终\n").unwrap();
        }
        let options = TestOptions {
            filter: None,
            jobs: 2,
            timeout: Duration::from_millis(10),
        };

        let results = run_with_options(&root, &options).unwrap();

        assert_eq!(results.len(), 8);
        assert!(
            results
                .iter()
                .all(|result| result.status == TestStatus::TimedOut)
        );
        assert_eq!(ACTIVE_TEST_EXECUTIONS.load(Ordering::SeqCst), 0);
        let peak = PEAK_TEST_EXECUTIONS.load(Ordering::SeqCst);
        assert!(
            (1..=options.jobs).contains(&peak),
            "peak executions: {peak}"
        );
        assert_eq!(machine_report(&results)["summary"]["timedOut"], 8);
        fs::remove_dir_all(root).unwrap();
    }
}

//! `.yx` 规格测试发现、并发执行与报告。

use crate::interpreter::Interpreter;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

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
    discover_with_root(path).map(|(_, files)| files)
}

pub(crate) fn discover_with_root(
    path: impl AsRef<Path>,
) -> Result<(PathBuf, Vec<PathBuf>), String> {
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
    if path.is_file() {
        roots
            .authorize_module(&requested_absolute, &path)
            .map_err(|error| error.to_string())?;
        return Ok((path.clone(), vec![path]));
    }
    if roots.roots().all(|root| root != path) {
        roots
            .authorize_module(&requested_absolute, &path)
            .map_err(|error| error.to_string())?;
    }
    let mut files = Vec::new();
    let mut portable_paths = BTreeMap::new();
    visit(&path, &roots, &mut portable_paths, &mut files)?;
    files.sort_by_key(|file| testing_path_key(&roots, file));
    Ok((path, files))
}

fn testing_path_key(roots: &crate::package::TrustedPackageRoots, path: &Path) -> String {
    roots
        .matching_root(path)
        .and_then(|root| path.strip_prefix(root).ok())
        .and_then(|relative| crate::package::portable_package_path(relative).ok())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
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
    let mut paths = discover(path)?;
    if let Some(filter) = options.filter.as_deref() {
        paths.retain(|path| path.to_string_lossy().contains(filter));
    }
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let count = paths.len();
    let queue = Arc::new(Mutex::new(VecDeque::from(paths)));
    let (sender, receiver) = mpsc::channel();
    let workers = options.jobs.min(count);
    for _ in 0..workers {
        let queue = queue.clone();
        let sender = sender.clone();
        let timeout = options.timeout;
        thread::spawn(move || {
            loop {
                let path = queue.lock().expect("test queue poisoned").pop_front();
                let Some(path) = path else {
                    break;
                };
                let _ = sender.send(run_case_with_timeout(path, timeout));
            }
        });
    }
    drop(sender);

    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        results.push(
            receiver
                .recv()
                .map_err(|_| "测试工作线程意外终止".to_string())??,
        );
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

fn run_case_with_timeout(path: PathBuf, timeout: Duration) -> Result<TestCaseResult, String> {
    let (sender, receiver) = mpsc::channel();
    let worker_path = path.clone();
    let started = Instant::now();
    thread::spawn(move || {
        let result = std::panic::catch_unwind(|| run_case(&worker_path)).unwrap_or_else(|_| {
            Ok(TestCaseResult {
                path: worker_path,
                passed: false,
                status: TestStatus::Failed,
                detail: "测试执行时发生内部恐慌".into(),
                duration_ms: 0,
            })
        });
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result.map(|mut result| {
            result.duration_ms = started.elapsed().as_millis();
            result
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(TestCaseResult {
            path,
            passed: false,
            status: TestStatus::TimedOut,
            detail: format!("超过 {} 毫秒", timeout.as_millis()),
            duration_ms: started.elapsed().as_millis(),
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("测试线程意外终止".into()),
    }
}

fn run_case(path: &Path) -> Result<TestCaseResult, String> {
    let (canonical, source) = crate::read_module_source_file(path)?;
    let expected = expectations(&source);
    let expected_failure = expected_failure(&source);
    let mut interpreter = Interpreter::silent();
    let execution = match crate::parse_named(&source, canonical.display().to_string()) {
        Ok(statements) => interpreter
            .execute_in_directory(
                &statements,
                canonical.parent().unwrap_or_else(|| Path::new(".")),
            )
            .map_err(crate::YanxuError::Runtime),
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
        path: path.to_path_buf(),
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

fn visit(
    path: &Path,
    roots: &crate::package::TrustedPackageRoots,
    portable_paths: &mut BTreeMap<PathBuf, crate::package::PortablePackagePaths>,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries =
        fs::read_dir(path).map_err(|error| format!("不能读取目录“{}”：{error}", path.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if let Some(root) = roots.matching_root(&path) {
            let relative = path.strip_prefix(root).expect("matching package root");
            match crate::package::package_path_decision(
                relative,
                crate::package::PackagePathPurpose::YxpEntry,
            )
            .map_err(|error| error.to_string())?
            {
                crate::package::PackagePathDecision::Include => {}
                crate::package::PackagePathDecision::Exclude(_) => continue,
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            let paths = portable_paths.entry(root.to_path_buf()).or_default();
            if metadata.is_dir() {
                paths
                    .insert_directory(relative)
                    .map_err(|error| error.to_string())?;
            } else {
                paths.insert(relative).map_err(|error| error.to_string())?;
            }
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("测试目录不得包含符号链接“{}”", path.display()));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            visit(&canonical, roots, portable_paths, files)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "yx")
        {
            roots
                .authorize_module(&path, &canonical)
                .map_err(|error| error.to_string())?;
            files.push(canonical);
        }
    }
    Ok(())
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
}

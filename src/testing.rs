//! `.yx` 规格测试发现、并发执行与报告。

use crate::interpreter::Interpreter;
use crate::run_file_with;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
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
    let path = path.as_ref();
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = Vec::new();
    visit(path, &mut files)?;
    files.sort();
    Ok(files)
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
    let source = fs::read_to_string(path)
        .map_err(|error| format!("不能读取“{}”：{error}", path.display()))?;
    let expected = expectations(&source);
    let expected_failure = expected_failure(&source);
    let mut interpreter = Interpreter::silent();
    let execution = run_file_with(&mut interpreter, path);
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

fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(path).map_err(|error| format!("不能读取目录“{}”：{error}", path.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            visit(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "yx") {
            files.push(path);
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

//! 可由树解释器与字节码 VM 共用的标准库内核。
//!
//! 此处只处理 Rust 基础类型，不依赖任一运行时的 `Value`，以免两个执行器
//! 各自复制路径、编码、统计、CSV 与纯函数工具算法。运行时适配层只负责
//! 类型转换和报错。

use base64::Engine as _;
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use url::Url;

pub const API_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const BYTES_MAX_VALUE_BYTES: usize = crate::budget::MAX_BYTE_VALUE_BYTES as usize;
pub const SECURE_RANDOM_MAX_BYTES: usize = 1024 * 1024;
pub const PROCESS_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const PROCESS_MAX_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub status: i32,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn api_manifest() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(include_str!("../stdlib/api-v1.json"))
}
#[cfg(not(target_family = "wasm"))]
use std::io::Write;
#[cfg(not(target_family = "wasm"))]
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(not(target_family = "wasm"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(target_family = "wasm"))]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(not(target_family = "wasm"))]
use std::thread;
#[cfg(not(target_family = "wasm"))]
use std::time::{Duration, Instant};

#[cfg(not(target_family = "wasm"))]
pub fn process_run(
    program: &str,
    arguments: &[String],
    directory: Option<&str>,
    timeout_millis: u64,
) -> Result<ProcessOutput, String> {
    use std::process::{Command, Stdio};
    if program.trim().is_empty() {
        return Err("PROCESS_PROGRAM：程序名不可为空".into());
    }
    if !(1..=PROCESS_MAX_TIMEOUT_MILLIS).contains(&timeout_millis) {
        return Err(format!(
            "PROCESS_TIMEOUT：超时须在 1..={PROCESS_MAX_TIMEOUT_MILLIS} 毫秒之间"
        ));
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("PROCESS_SPAWN：不能启动“{program}”：{error}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || read_process_output(stdout));
    let stderr_reader = thread::spawn(move || read_process_output(stderr));
    let deadline = Instant::now() + Duration::from_millis(timeout_millis);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("PROCESS_WAIT：等候子进程失败：{error}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("PROCESS_TIMEOUT：子进程超过 {timeout_millis} 毫秒"));
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "PROCESS_READ：读取标准输出的线程异常".to_owned())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "PROCESS_READ：读取标准错误的线程异常".to_owned())??;
    Ok(ProcessOutput {
        status: status.code().unwrap_or(-1),
        success: status.success(),
        stdout: String::from_utf8(stdout)
            .map_err(|_| "PROCESS_UTF8：标准输出不是 UTF-8 文字".to_owned())?,
        stderr: String::from_utf8(stderr)
            .map_err(|_| "PROCESS_UTF8：标准错误不是 UTF-8 文字".to_owned())?,
    })
}

#[cfg(not(target_family = "wasm"))]
fn read_process_output(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let length = reader
            .read(&mut buffer)
            .map_err(|error| format!("PROCESS_READ：读取子进程输出失败：{error}"))?;
        if length == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(length) > PROCESS_MAX_OUTPUT_BYTES {
            return Err(format!(
                "PROCESS_LIMIT：单个输出流不得超过 {PROCESS_MAX_OUTPUT_BYTES} 字节"
            ));
        }
        bytes.extend_from_slice(&buffer[..length]);
    }
}

#[cfg(target_family = "wasm")]
pub fn process_run(
    _program: &str,
    _arguments: &[String],
    _directory: Option<&str>,
    _timeout_millis: u64,
) -> Result<ProcessOutput, String> {
    Err("PROCESS_UNSUPPORTED：WASI 不支持启动宿主进程".into())
}

pub fn path_join(left: &str, right: &str) -> String {
    Path::new(left).join(right).to_string_lossy().into_owned()
}

pub fn path_parent(path: &str) -> Option<String> {
    Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.to_string_lossy().into_owned())
}

pub fn path_file_name(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

pub fn path_extension(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .map(|extension| extension.to_string_lossy().into_owned())
}

pub fn path_is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
}

/// 只做词法规范化，不访问文件系统，也不解析符号链接。
pub fn path_normalize(path: &str) -> String {
    let path = Path::new(path);
    let mut prefix = None;
    let mut rooted = false;
    let mut parts: Vec<OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_owned()),
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::Normal(value) => parts.push(value.to_owned()),
            Component::ParentDir => {
                let can_pop = parts
                    .last()
                    .is_some_and(|part| part != std::ffi::OsStr::new(".."));
                if can_pop {
                    parts.pop();
                } else if !rooted {
                    parts.push(OsString::from(".."));
                }
            }
        }
    }

    let mut normalized = PathBuf::new();
    if let Some(prefix) = prefix {
        normalized.push(prefix);
    }
    if rooted {
        normalized.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in parts {
        normalized.push(part);
    }
    if normalized.as_os_str().is_empty() {
        if path.as_os_str().is_empty() {
            String::new()
        } else {
            ".".into()
        }
    } else {
        normalized.to_string_lossy().into_owned()
    }
}

pub fn create_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|error| format!("不能创建目录“{}”：{error}", path.display()))
}

pub fn remove_path(path: &Path, recursive: bool) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("不能取得“{}”状态：{error}", path.display()))?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return std::fs::remove_file(path)
            .map_err(|error| format!("不能删除文卷“{}”：{error}", path.display()));
    }
    if metadata.is_dir() {
        return if recursive {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_dir(path)
        }
        .map_err(|error| format!("不能删除目录“{}”：{error}", path.display()));
    }
    Err(format!("不可删除特殊文件“{}”", path.display()))
}

pub fn sha256(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn bytes_from_numbers(numbers: &[f64]) -> Result<Vec<u8>, String> {
    if numbers.len() > BYTES_MAX_VALUE_BYTES {
        return Err(format!("字节数列不得超过 {BYTES_MAX_VALUE_BYTES} 项"));
    }
    numbers
        .iter()
        .enumerate()
        .map(|(index, number)| {
            if number.is_finite()
                && number.fract() == 0.0
                && (0.0..=f64::from(u8::MAX)).contains(number)
            {
                Ok(*number as u8)
            } else {
                Err(format!("字节数列第 {} 项须为 0..255 的整数", index + 1))
            }
        })
        .collect()
}

pub fn bytes_find(source: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    source
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn bytes_slice(source: &[u8], start: usize, end: usize) -> Result<Vec<u8>, String> {
    if start > end || end > source.len() {
        return Err(format!(
            "字节切片范围 {start}..{end} 超出 0..{}",
            source.len()
        ));
    }
    Ok(source[start..end].to_vec())
}

pub fn bytes_concat(left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    let length = left
        .len()
        .checked_add(right.len())
        .ok_or_else(|| "字节拼接长度溢出".to_string())?;
    if length > BYTES_MAX_VALUE_BYTES {
        return Err(format!("字节拼接结果不得超过 {BYTES_MAX_VALUE_BYTES} 字节"));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    Ok(bytes)
}

pub fn secure_random_bytes(length: usize) -> Result<Vec<u8>, String> {
    if length > SECURE_RANDOM_MAX_BYTES {
        return Err(format!(
            "安全随机字节长度不得超过 {SECURE_RANDOM_MAX_BYTES}"
        ));
    }
    let mut bytes = vec![0; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("操作系统安全随机源不可用：{error}"))?;
    Ok(bytes)
}

pub fn hmac_sha256(key: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "HMAC-SHA256 密钥无效".to_string())?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

pub fn format_http_date(unix_millis: u64) -> Result<String, String> {
    const YEAR_9999_UNIX_MILLIS: u64 = 253_402_300_800_000;
    if unix_millis >= YEAR_9999_UNIX_MILLIS {
        return Err("HTTP 日期须早于公元 9999 年".into());
    }
    Ok(httpdate::fmt_http_date(
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(unix_millis),
    ))
}

pub fn parse_http_date(text: &str) -> Option<u64> {
    httpdate::parse_http_date(text)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    pub kind: &'static str,
    pub bytes: u64,
    pub readonly: bool,
    pub modified_millis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileBytesError {
    Io(String),
    Limit(String),
}

pub fn file_status(path: &Path) -> Result<FileStatus, String> {
    let metadata = std::fs::metadata(path).map_err(|error| format!("不能读取文件状态：{error}"))?;
    let kind = if metadata.is_file() {
        "文件"
    } else if metadata.is_dir() {
        "目录"
    } else {
        "其他"
    };
    let modified_millis = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok());
    Ok(FileStatus {
        kind,
        bytes: metadata.len(),
        readonly: metadata.permissions().readonly(),
        modified_millis,
    })
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, FileBytesError> {
    let file = std::fs::File::open(path)
        .map_err(|error| FileBytesError::Io(format!("不能读取文件：{error}")))?;
    let limit = BYTES_MAX_VALUE_BYTES as u64 + 1;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| FileBytesError::Io(format!("不能读取文件：{error}")))?;
    if bytes.len() > BYTES_MAX_VALUE_BYTES {
        return Err(FileBytesError::Limit(format!(
            "文件超过 {BYTES_MAX_VALUE_BYTES} 字节上限"
        )));
    }
    Ok(bytes)
}

pub fn hex_encode(text: &str) -> String {
    text.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn hex_decode(text: &str) -> Result<String, String> {
    if !text.len().is_multiple_of(2) {
        return Err("十六进制文本长度须为偶数".into());
    }
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or_else(|| "含有非十六进制字符".to_string())?;
            let low = hex_digit(pair[1]).ok_or_else(|| "含有非十六进制字符".to_string())?;
            Ok((high << 4) | low)
        })
        .collect::<Result<Vec<_>, String>>()?;
    String::from_utf8(bytes).map_err(|_| "解码结果不是有效 UTF-8 文字".into())
}

pub fn percent_encode(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("百分号编码不完整".into());
            }
            let high = hex_digit(bytes[index + 1])
                .ok_or_else(|| "百分号后须有两位十六进制数".to_string())?;
            let low = hex_digit(bytes[index + 2])
                .ok_or_else(|| "百分号后须有两位十六进制数".to_string())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "解码结果不是有效 UTF-8 文字".into())
}

pub fn base64_encode(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

pub fn base64_decode(text: &str) -> Result<String, String> {
    decode_base64(&base64::engine::general_purpose::STANDARD, text, "Base64")
}

pub fn base64_url_encode(text: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text.as_bytes())
}

pub fn base64_url_decode(text: &str) -> Result<String, String> {
    decode_base64(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        text,
        "网址 Base64",
    )
}

fn decode_base64(engine: &impl base64::Engine, text: &str, name: &str) -> Result<String, String> {
    let bytes = engine
        .decode(text)
        .map_err(|_| format!("{name}文字含非法字母、长度或填充"))?;
    String::from_utf8(bytes).map_err(|_| format!("{name}解码结果不是有效 UTF-8 文字"))
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|error| format!("正则模式不合法：{error}"))
}

pub fn regex_is_match(pattern: &str, text: &str) -> Result<bool, String> {
    Ok(compile_regex(pattern)?.is_match(text))
}

pub fn regex_first(pattern: &str, text: &str) -> Result<Option<String>, String> {
    Ok(compile_regex(pattern)?
        .find(text)
        .map(|matched| matched.as_str().to_string()))
}

pub fn regex_replace_all(pattern: &str, text: &str, replacement: &str) -> Result<String, String> {
    Ok(compile_regex(pattern)?
        .replace_all(text, replacement)
        .into_owned())
}

pub fn regex_split(pattern: &str, text: &str) -> Result<Vec<String>, String> {
    Ok(compile_regex(pattern)?
        .split(text)
        .map(str::to_string)
        .collect())
}

fn parse_url(text: &str) -> Result<Url, String> {
    Url::parse(text).map_err(|error| format!("URL 不合法：{error}"))
}

pub fn url_is_valid(text: &str) -> bool {
    Url::parse(text).is_ok()
}

pub fn url_scheme(text: &str) -> Result<String, String> {
    Ok(parse_url(text)?.scheme().to_string())
}

pub fn url_host(text: &str) -> Result<Option<String>, String> {
    Ok(parse_url(text)?.host_str().map(str::to_string))
}

pub fn url_port(text: &str) -> Result<Option<f64>, String> {
    Ok(parse_url(text)?.port().map(f64::from))
}

pub fn url_path(text: &str) -> Result<String, String> {
    Ok(parse_url(text)?.path().to_string())
}

pub fn url_query_value(text: &str, name: &str) -> Result<Option<String>, String> {
    Ok(parse_url(text)?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned()))
}

pub fn url_join(base: &str, relative: &str) -> Result<String, String> {
    parse_url(base)?
        .join(relative)
        .map(|url| url.into())
        .map_err(|error| format!("相对 URL 不合法：{error}"))
}

#[derive(Clone, Copy)]
struct IsoDate {
    year: i32,
    month: u32,
    day: u32,
}

fn parse_iso_date(text: &str) -> Result<IsoDate, String> {
    let bytes = text.as_bytes();
    let digits = [0, 1, 2, 3, 5, 6, 8, 9];
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !digits
            .into_iter()
            .all(|index| bytes[index].is_ascii_digit())
    {
        return Err("日期须为 YYYY-MM-DD 形式".into());
    }
    let year = text[0..4].parse::<i32>().unwrap();
    let month = text[5..7].parse::<u32>().unwrap();
    let day = text[8..10].parse::<u32>().unwrap();
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
    {
        return Err("日期不在 0001-01-01 至 9999-12-31 的有效公历范围".into());
    }
    Ok(IsoDate { year, month, day })
}

fn leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub fn date_is_valid(text: &str) -> bool {
    parse_iso_date(text).is_ok()
}

pub fn date_is_leap_year(year: f64) -> Result<bool, String> {
    let year = safe_integer(year, "年份")?;
    let year = i32::try_from(year)
        .ok()
        .filter(|year| (1..=9999).contains(year))
        .ok_or_else(|| "年份须在 1 至 9999 之间".to_string())?;
    Ok(leap_year(year))
}

pub fn date_add_days(text: &str, days: f64) -> Result<String, String> {
    let date = parse_iso_date(text)?;
    let days = safe_integer(days, "日期天数")?;
    let ordinal = days_from_civil(date)
        .checked_add(days)
        .ok_or_else(|| "日期运算超出支持范围".to_string())?;
    let minimum = days_from_civil(IsoDate {
        year: 1,
        month: 1,
        day: 1,
    });
    let maximum = days_from_civil(IsoDate {
        year: 9999,
        month: 12,
        day: 31,
    });
    if !(minimum..=maximum).contains(&ordinal) {
        return Err("日期运算超出 0001-01-01 至 9999-12-31".into());
    }
    let result = civil_from_days(ordinal);
    Ok(format!(
        "{:04}-{:02}-{:02}",
        result.year, result.month, result.day
    ))
}

/// 返回从开始日期到结束日期的天数；结束早于开始时为负数。
pub fn date_days_between(start: &str, end: &str) -> Result<f64, String> {
    let start = days_from_civil(parse_iso_date(start)?);
    let end = days_from_civil(parse_iso_date(end)?);
    Ok((end - start) as f64)
}

fn days_from_civil(date: IsoDate) -> i64 {
    let mut year = i64::from(date.year);
    let month = i64::from(date.month);
    let day = i64::from(date.day);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> IsoDate {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    IsoDate {
        year: year as i32,
        month: month as u32,
        day: day as u32,
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn safe_integer(value: f64, name: &str) -> Result<i64, String> {
    if value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER {
        Ok(value as i64)
    } else {
        Err(format!("{name}须为安全范围内的有限整数"))
    }
}

fn seeded_bits(seed: f64) -> Result<u64, String> {
    let seed = safe_integer(seed, "随机种子")? as u64;
    let mut mixed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    Ok(mixed ^ (mixed >> 31))
}

/// 由显式整数种子生成 `[0, 1)` 内可复现的小数。
pub fn seeded_random_unit(seed: f64) -> Result<f64, String> {
    let bits = seeded_bits(seed)? >> 11;
    Ok(bits as f64 / (1_u64 << 53) as f64)
}

/// 由显式整数种子生成半开区间 `[lower, upper)` 内的整数。
pub fn seeded_random_integer(seed: f64, lower: f64, upper: f64) -> Result<f64, String> {
    let lower = safe_integer(lower, "随机下界")?;
    let upper = safe_integer(upper, "随机上界")?;
    if lower >= upper {
        return Err("随机整数须满足下界小于上界".into());
    }
    let span = upper as i128 - lower as i128;
    if span > MAX_SAFE_INTEGER as i128 {
        return Err("随机整数区间不可超过安全整数范围".into());
    }
    let offset = seeded_bits(seed)? % span as u64;
    Ok(lower as f64 + offset as f64)
}

pub fn seeded_random_bool(seed: f64) -> Result<bool, String> {
    Ok(seeded_bits(seed)? & 1 == 1)
}

/// 从文字的 SHA-256 摘要构造 RFC 9562 版本 8、标准变体 UUID。
pub fn stable_uuid(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    matches!(bytes[14], b'1'..=b'8')
        && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

pub fn stable_short_id(text: &str, length: f64) -> Result<String, String> {
    let length = safe_integer(length, "短码长度")?;
    if !(4..=64).contains(&length) {
        return Err("短码长度须在 4 至 64 之间".into());
    }
    Ok(sha256(text)[..length as usize].into())
}

pub fn template_interpolate(template: &str, name: &str, value: &str) -> Result<String, String> {
    if name.is_empty() || name.contains(['{', '}']) {
        return Err("模板占位名不可为空或含花括号".into());
    }
    Ok(template.replace(&format!("{{{{{name}}}}}"), value))
}

pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn html_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// 校验常用 ASCII 邮件地址形式；不尝试实现完整 RFC 邮箱语法。
pub fn is_email(text: &str) -> bool {
    if text.len() > 254 || text.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._%+-".contains(&byte))
    {
        return false;
    }
    let labels: Vec<_> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2 && label.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
}

pub fn is_ipv4(text: &str) -> bool {
    let parts: Vec<_> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part == &"0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

pub fn is_hex_color(text: &str) -> bool {
    let Some(digits) = text.strip_prefix('#') else {
        return false;
    };
    matches!(digits.len(), 3 | 4 | 6 | 8) && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

pub fn stats_sum(values: &[f64]) -> Result<f64, String> {
    ensure_finite(values)?;
    Ok(values.iter().sum())
}

pub fn stats_mean(values: &[f64]) -> Result<f64, String> {
    ensure_non_empty(values)?;
    Ok(stats_sum(values)? / values.len() as f64)
}

pub fn stats_median(values: &[f64]) -> Result<f64, String> {
    ensure_non_empty(values)?;
    ensure_finite(values)?;
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        Ok((sorted[middle - 1] + sorted[middle]) / 2.0)
    } else {
        Ok(sorted[middle])
    }
}

/// 返回总体方差（除以 N），适合描述所给完整数据集。
pub fn stats_variance(values: &[f64]) -> Result<f64, String> {
    let mean = stats_mean(values)?;
    Ok(values
        .iter()
        .map(|value| {
            let distance = value - mean;
            distance * distance
        })
        .sum::<f64>()
        / values.len() as f64)
}

pub fn stats_stddev(values: &[f64]) -> Result<f64, String> {
    Ok(stats_variance(values)?.sqrt())
}

fn ensure_non_empty(values: &[f64]) -> Result<(), String> {
    if values.is_empty() {
        Err("统计数据不可为空".into())
    } else {
        Ok(())
    }
}

fn ensure_finite(values: &[f64]) -> Result<(), String> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err("统计数据须全部为有限数".into())
    }
}

pub fn csv_parse(text: &str) -> Result<Vec<Vec<String>>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }

    let characters: Vec<char> = text.chars().collect();
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut index = 0;
    let mut in_quotes = false;
    let mut after_quote = false;
    let mut record_open = false;

    while index < characters.len() {
        let character = characters[index];
        if in_quotes {
            if character == '"' {
                if characters.get(index + 1) == Some(&'"') {
                    field.push('"');
                    index += 2;
                    continue;
                }
                in_quotes = false;
                after_quote = true;
            } else {
                field.push(character);
            }
            index += 1;
            continue;
        }

        if after_quote {
            match character {
                ',' => {
                    row.push(std::mem::take(&mut field));
                    after_quote = false;
                    record_open = true;
                }
                '\n' | '\r' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    after_quote = false;
                    record_open = false;
                    if character == '\r' && characters.get(index + 1) == Some(&'\n') {
                        index += 1;
                    }
                }
                _ => return Err("CSV 引号字段结束后只可接分隔号或换行".into()),
            }
            index += 1;
            continue;
        }

        match character {
            '"' if field.is_empty() => {
                in_quotes = true;
                record_open = true;
            }
            '"' => return Err("CSV 未转义引号须位于字段开头".into()),
            ',' => {
                row.push(std::mem::take(&mut field));
                record_open = true;
            }
            '\n' | '\r' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                record_open = false;
                if character == '\r' && characters.get(index + 1) == Some(&'\n') {
                    index += 1;
                }
            }
            _ => {
                field.push(character);
                record_open = true;
            }
        }
        index += 1;
    }

    if in_quotes {
        return Err("CSV 引号字段未闭合".into());
    }
    if after_quote || record_open || !row.is_empty() || !field.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

pub fn csv_stringify(rows: &[Vec<String>]) -> String {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|field| {
                    if field.contains([',', '"', '\n', '\r']) {
                        format!("\"{}\"", field.replace('"', "\"\""))
                    } else {
                        field.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub const HTTP_DEFAULT_TIMEOUT_MILLIS: u64 = 10_000;
pub const HTTP_DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const HTTP_MAX_REDIRECTS: usize = 10;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpRequestBudget {
    timeout_millis: u64,
    requested_max_bytes: u64,
    host_limits: crate::budget::HostResourceLimits,
}

impl HttpRequestBudget {
    pub(crate) const fn new(
        timeout_millis: u64,
        requested_max_bytes: u64,
        host_limits: crate::budget::HostResourceLimits,
    ) -> Self {
        Self {
            timeout_millis,
            requested_max_bytes,
            host_limits,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkError {
    pub code: &'static str,
    pub message: String,
}

impl NetworkError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn category(&self) -> &'static str {
        "网络"
    }
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for NetworkError {}

pub const SOCKET_MAX_READ_BYTES: u64 = crate::budget::MAX_SOCKET_READ_BYTES;
pub const SOCKET_MAX_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;
pub const SOCKET_MAX_OPEN_RESOURCES: usize = 128;
pub const SOCKET_MAX_OPEN_LISTENERS: usize = 16;
#[cfg(not(target_family = "wasm"))]
const SOCKET_BIND_RESOLVE_TIMEOUT_MILLIS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketError {
    pub code: &'static str,
    pub message: String,
}

impl SocketError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn category(&self) -> &'static str {
        "套接字"
    }
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for SocketError {}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct SocketQuota {
    inner: Arc<SocketQuotaInner>,
}

#[cfg(target_family = "wasm")]
#[derive(Debug, Clone, Default)]
pub struct SocketQuota {
    _private: (),
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct SocketQuotaInner {
    max_resources: usize,
    max_listeners: usize,
    resources: AtomicUsize,
    listeners: AtomicUsize,
}

#[cfg(not(target_family = "wasm"))]
impl Clone for SocketQuota {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Default for SocketQuota {
    fn default() -> Self {
        Self::new(SOCKET_MAX_OPEN_RESOURCES, SOCKET_MAX_OPEN_LISTENERS)
    }
}

#[cfg(not(target_family = "wasm"))]
impl SocketQuota {
    pub fn new(max_resources: usize, max_listeners: usize) -> Self {
        Self {
            inner: Arc::new(SocketQuotaInner {
                max_resources,
                max_listeners,
                resources: AtomicUsize::new(0),
                listeners: AtomicUsize::new(0),
            }),
        }
    }

    fn acquire(&self, listener: bool) -> Result<SocketLease, SocketError> {
        if listener
            && self
                .inner
                .listeners
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                    (count < self.inner.max_listeners).then_some(count + 1)
                })
                .is_err()
        {
            return Err(SocketError::new(
                "SOCKET_LIMIT",
                format!(
                    "同时打开的 TCP 监听器不得超过 {} 个",
                    self.inner.max_listeners
                ),
            ));
        }
        if self
            .inner
            .resources
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < self.inner.max_resources).then_some(count + 1)
            })
            .is_err()
        {
            if listener {
                self.inner.listeners.fetch_sub(1, Ordering::SeqCst);
            }
            return Err(SocketError::new(
                "SOCKET_LIMIT",
                format!(
                    "同时打开的套接字资源不得超过 {} 个",
                    self.inner.max_resources
                ),
            ));
        }
        Ok(SocketLease {
            quota: self.clone(),
            listener,
        })
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        (
            self.inner.resources.load(Ordering::SeqCst),
            self.inner.listeners.load(Ordering::SeqCst),
        )
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct SocketLease {
    quota: SocketQuota,
    listener: bool,
}

#[cfg(not(target_family = "wasm"))]
impl Drop for SocketLease {
    fn drop(&mut self) {
        self.quota.inner.resources.fetch_sub(1, Ordering::SeqCst);
        if self.listener {
            self.quota.inner.listeners.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct TcpStreamHandle {
    stream: TcpStream,
    read_buffer: Vec<u8>,
    _lease: SocketLease,
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct TcpListenerHandle {
    listener: TcpListener,
    lease: SocketLease,
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct UdpSocketHandle {
    socket: UdpSocket,
    _lease: SocketLease,
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub enum SocketHandle {
    TcpStream(TcpStreamHandle),
    TcpListener(TcpListenerHandle),
    Udp(UdpSocketHandle),
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRead {
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[cfg(target_family = "wasm")]
#[derive(Debug)]
pub struct SocketHandle;

impl SocketHandle {
    pub fn kind_name(&self) -> &'static str {
        #[cfg(not(target_family = "wasm"))]
        {
            match self {
                Self::TcpStream(_) => "TCP流",
                Self::TcpListener(_) => "TCP监听器",
                Self::Udp(_) => "UDP套接字",
                Self::Closed => "已关闭套接字",
            }
        }
        #[cfg(target_family = "wasm")]
        {
            "不可用套接字"
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_tcp_connect(address: &str, timeout_millis: u64) -> Result<SocketHandle, SocketError> {
    socket_tcp_connect_guarded(
        address,
        timeout_millis,
        &crate::permissions::PermissionSet::unrestricted(),
        &SocketQuota::default(),
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_tcp_connect_guarded(
    address: &str,
    timeout_millis: u64,
    permissions: &crate::permissions::PermissionSet,
    quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let deadline = Instant::now() + timeout;
    permissions
        .check_network(address)
        .map_err(socket_permission_error)?;
    let addresses = resolve_socket_addresses(address, deadline)?
        .into_iter()
        .filter(|resolved| {
            permissions
                .check_resolved_network(address, *resolved)
                .is_ok()
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(SocketError::new(
            "SOCKET_PERMISSION",
            format!("套接字地址“{address}”的 DNS 结果均被网络地址策略拒绝"),
        ));
    }
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new("SOCKET_TIMEOUT", "TCP 连接已超过超时上限"));
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|error| socket_io_error("SOCKET_CONNECT", "配置 TCP 流", error))?;
                let lease = quota.acquire(false)?;
                return Ok(SocketHandle::TcpStream(TcpStreamHandle {
                    stream,
                    read_buffer: Vec::new(),
                    _lease: lease,
                }));
            }
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error.expect("地址列表非空");
    Err(socket_io_error("SOCKET_CONNECT", "连接 TCP 地址", error))
}

#[cfg(target_family = "wasm")]
pub fn socket_tcp_connect(
    _address: &str,
    _timeout_millis: u64,
) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_tcp_connect_guarded(
    _address: &str,
    _timeout_millis: u64,
    _permissions: &crate::permissions::PermissionSet,
    _quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_tcp_listen(address: &str) -> Result<SocketHandle, SocketError> {
    socket_tcp_listen_guarded(
        address,
        &crate::permissions::PermissionSet::unrestricted(),
        &SocketQuota::default(),
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_tcp_listen_guarded(
    address: &str,
    permissions: &crate::permissions::PermissionSet,
    quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    permissions
        .check_tcp_listen(address)
        .map_err(socket_permission_error)?;
    let deadline = Instant::now() + Duration::from_millis(SOCKET_BIND_RESOLVE_TIMEOUT_MILLIS);
    let addresses = resolve_socket_addresses(address, deadline)?;
    let mut last_error = None;
    for resolved in addresses {
        if permissions
            .check_tcp_listen_resolved(address, resolved)
            .is_err()
        {
            continue;
        }
        match TcpListener::bind(resolved) {
            Ok(listener) => {
                let lease = quota.acquire(true)?;
                return Ok(SocketHandle::TcpListener(TcpListenerHandle {
                    listener,
                    lease,
                }));
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(last_error) = last_error else {
        return Err(SocketError::new(
            "SOCKET_PERMISSION",
            "TCP 监听地址的 DNS 结果均被绑定策略拒绝",
        ));
    };
    Err(socket_io_error(
        "SOCKET_BIND",
        "绑定 TCP 监听地址",
        last_error,
    ))
}

#[cfg(target_family = "wasm")]
pub fn socket_tcp_listen(_address: &str) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_tcp_listen_guarded(
    _address: &str,
    _permissions: &crate::permissions::PermissionSet,
    _quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_accept(
    handle: &mut SocketHandle,
    timeout_millis: u64,
) -> Result<(SocketHandle, String), SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let SocketHandle::TcpListener(listener_handle) = handle else {
        return Err(socket_state(handle, "接受", "TCP监听器"));
    };
    listener_handle
        .listener
        .set_nonblocking(true)
        .map_err(|error| socket_io_error("SOCKET_ACCEPT", "配置 TCP 监听器", error))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener_handle.listener.accept() {
            Ok((stream, peer)) => {
                stream.set_nonblocking(false).map_err(|error| {
                    socket_io_error("SOCKET_ACCEPT", "配置已接受 TCP 流", error)
                })?;
                stream.set_nodelay(true).map_err(|error| {
                    socket_io_error("SOCKET_ACCEPT", "配置已接受 TCP 流", error)
                })?;
                let lease = listener_handle.lease.quota.acquire(false)?;
                return Ok((
                    SocketHandle::TcpStream(TcpStreamHandle {
                        stream,
                        read_buffer: Vec::new(),
                        _lease: lease,
                    }),
                    peer.to_string(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SocketError::new(
                        "SOCKET_TIMEOUT",
                        "等待 TCP 连接已超过超时上限",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => {
                return Err(socket_io_error("SOCKET_ACCEPT", "接受 TCP 连接", error));
            }
        }
    }
}

#[cfg(target_family = "wasm")]
pub fn socket_accept(
    _handle: &mut SocketHandle,
    _timeout_millis: u64,
) -> Result<(SocketHandle, String), SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_send(
    handle: &mut SocketHandle,
    text: &str,
    timeout_millis: u64,
) -> Result<u64, SocketError> {
    socket_send_bytes(handle, text.as_bytes(), timeout_millis)
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_send_bytes(
    handle: &mut SocketHandle,
    bytes: &[u8],
    timeout_millis: u64,
) -> Result<u64, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let SocketHandle::TcpStream(stream_handle) = handle else {
        return Err(socket_state(handle, "发送字节", "TCP流"));
    };
    let deadline = Instant::now() + timeout;
    let mut written = 0;
    while written < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new(
                "SOCKET_TIMEOUT",
                "写入 TCP 流已超过超时上限",
            ));
        }
        stream_handle
            .stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| socket_io_error("SOCKET_WRITE", "配置 TCP 写超时", error))?;
        let count = stream_handle
            .stream
            .write(&bytes[written..])
            .map_err(|error| socket_io_error("SOCKET_WRITE", "写入 TCP 流", error))?;
        if count == 0 {
            return Err(SocketError::new("SOCKET_WRITE", "写入 TCP 流未产生进度"));
        }
        written += count;
    }
    Ok(bytes.len() as u64)
}

#[cfg(target_family = "wasm")]
pub fn socket_send(
    _handle: &mut SocketHandle,
    _text: &str,
    _timeout_millis: u64,
) -> Result<u64, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_send_bytes(
    _handle: &mut SocketHandle,
    _bytes: &[u8],
    _timeout_millis: u64,
) -> Result<u64, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_receive_bytes(
    handle: &mut SocketHandle,
    max_bytes: u64,
    timeout_millis: u64,
) -> Result<SocketRead, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let capacity = socket_read_capacity(max_bytes)?;
    let SocketHandle::TcpStream(stream_handle) = handle else {
        return Err(socket_state(handle, "接收字节", "TCP流"));
    };
    if !stream_handle.read_buffer.is_empty() {
        let length = capacity.min(stream_handle.read_buffer.len());
        let bytes = stream_handle.read_buffer.drain(..length).collect();
        return Ok(SocketRead { bytes, eof: false });
    }
    stream_handle
        .stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| socket_io_error("SOCKET_READ", "配置 TCP 读超时", error))?;
    let mut bytes = vec![0; capacity];
    let length = stream_handle
        .stream
        .read(&mut bytes)
        .map_err(|error| socket_io_error("SOCKET_READ", "读取 TCP 流", error))?;
    bytes.truncate(length);
    Ok(SocketRead {
        bytes,
        eof: length == 0,
    })
}

#[cfg(target_family = "wasm")]
pub fn socket_receive_bytes(
    _handle: &mut SocketHandle,
    _max_bytes: u64,
    _timeout_millis: u64,
) -> Result<SocketRead, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_read_exact_bytes(
    handle: &mut SocketHandle,
    byte_count: u64,
    timeout_millis: u64,
) -> Result<Vec<u8>, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let capacity = socket_read_capacity(byte_count)?;
    let SocketHandle::TcpStream(stream_handle) = handle else {
        return Err(socket_state(handle, "精确读取", "TCP流"));
    };
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::with_capacity(capacity);
    if !stream_handle.read_buffer.is_empty() {
        let length = capacity.min(stream_handle.read_buffer.len());
        bytes.extend(stream_handle.read_buffer.drain(..length));
    }
    while bytes.len() < capacity {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new(
                "SOCKET_TIMEOUT",
                "精确读取 TCP 流已超过超时上限",
            ));
        }
        stream_handle
            .stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| socket_io_error("SOCKET_READ", "配置 TCP 读超时", error))?;
        let mut chunk = vec![0; capacity - bytes.len()];
        let length = stream_handle
            .stream
            .read(&mut chunk)
            .map_err(|error| socket_io_error("SOCKET_READ", "精确读取 TCP 流", error))?;
        if length == 0 {
            return Err(SocketError::new(
                "SOCKET_EOF",
                format!(
                    "TCP 流提前结束：需要 {capacity} 字节，只读取 {} 字节",
                    bytes.len()
                ),
            ));
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    Ok(bytes)
}

#[cfg(target_family = "wasm")]
pub fn socket_read_exact_bytes(
    _handle: &mut SocketHandle,
    _byte_count: u64,
    _timeout_millis: u64,
) -> Result<Vec<u8>, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_receive(
    handle: &mut SocketHandle,
    max_bytes: u64,
    timeout_millis: u64,
) -> Result<String, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let capacity = socket_read_capacity(max_bytes)?;
    let SocketHandle::TcpStream(stream_handle) = handle else {
        return Err(socket_state(handle, "接收", "TCP流"));
    };
    let deadline = Instant::now() + timeout;
    loop {
        if stream_handle.read_buffer.len() > capacity {
            return Err(SocketError::new(
                "SOCKET_LIMIT",
                format!("TCP 单次接收超过 {max_bytes} 字节上限"),
            ));
        }
        if !stream_handle.read_buffer.is_empty() {
            match std::str::from_utf8(&stream_handle.read_buffer) {
                Ok(text) => {
                    let text = text.to_owned();
                    stream_handle.read_buffer.clear();
                    return Ok(text);
                }
                Err(error) if error.error_len().is_some() => {
                    return Err(SocketError::new(
                        "SOCKET_UTF8",
                        "TCP 接收内容含非法 UTF-8 字节序列",
                    ));
                }
                Err(_) => {}
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new(
                "SOCKET_TIMEOUT",
                "读取 TCP 流已超过超时上限",
            ));
        }
        stream_handle
            .stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| socket_io_error("SOCKET_READ", "配置 TCP 读超时", error))?;
        let read_capacity = capacity
            .saturating_add(1)
            .saturating_sub(stream_handle.read_buffer.len())
            .max(1);
        let mut bytes = vec![0; read_capacity];
        let length = stream_handle
            .stream
            .read(&mut bytes)
            .map_err(|error| socket_io_error("SOCKET_READ", "读取 TCP 流", error))?;
        if length == 0 {
            if stream_handle.read_buffer.is_empty() {
                return Ok(String::new());
            }
            return Err(SocketError::new(
                "SOCKET_UTF8",
                "TCP 流在未完成的 UTF-8 字符后结束",
            ));
        }
        stream_handle
            .read_buffer
            .extend_from_slice(&bytes[..length]);
    }
}

#[cfg(target_family = "wasm")]
pub fn socket_receive(
    _handle: &mut SocketHandle,
    _max_bytes: u64,
    _timeout_millis: u64,
) -> Result<String, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_bind(address: &str) -> Result<SocketHandle, SocketError> {
    socket_udp_bind_guarded(
        address,
        &crate::permissions::PermissionSet::unrestricted(),
        &SocketQuota::default(),
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_bind_guarded(
    address: &str,
    permissions: &crate::permissions::PermissionSet,
    quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    permissions
        .check_udp_bind(address)
        .map_err(socket_permission_error)?;
    let deadline = Instant::now() + Duration::from_millis(SOCKET_BIND_RESOLVE_TIMEOUT_MILLIS);
    let addresses = resolve_socket_addresses(address, deadline)?;
    let mut last_error = None;
    for resolved in addresses {
        if permissions
            .check_udp_bind_resolved(address, resolved)
            .is_err()
        {
            continue;
        }
        match UdpSocket::bind(resolved) {
            Ok(socket) => {
                let lease = quota.acquire(false)?;
                return Ok(SocketHandle::Udp(UdpSocketHandle {
                    socket,
                    _lease: lease,
                }));
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(last_error) = last_error else {
        return Err(SocketError::new(
            "SOCKET_PERMISSION",
            "UDP 绑定地址的 DNS 结果均被绑定策略拒绝",
        ));
    };
    Err(socket_io_error("SOCKET_BIND", "绑定 UDP 地址", last_error))
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_bind(_address: &str) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_bind_guarded(
    _address: &str,
    _permissions: &crate::permissions::PermissionSet,
    _quota: &SocketQuota,
) -> Result<SocketHandle, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_send_to(
    handle: &mut SocketHandle,
    text: &str,
    address: &str,
    timeout_millis: u64,
) -> Result<u64, SocketError> {
    socket_udp_send_bytes_to_guarded(
        handle,
        text.as_bytes(),
        address,
        timeout_millis,
        &crate::permissions::PermissionSet::unrestricted(),
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_send_to_guarded(
    handle: &mut SocketHandle,
    text: &str,
    address: &str,
    timeout_millis: u64,
    permissions: &crate::permissions::PermissionSet,
) -> Result<u64, SocketError> {
    socket_udp_send_bytes_to_guarded(
        handle,
        text.as_bytes(),
        address,
        timeout_millis,
        permissions,
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_send_bytes_to_guarded(
    handle: &mut SocketHandle,
    bytes: &[u8],
    address: &str,
    timeout_millis: u64,
    permissions: &crate::permissions::PermissionSet,
) -> Result<u64, SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let deadline = Instant::now() + timeout;
    permissions
        .check_network(address)
        .map_err(socket_permission_error)?;
    let addresses = resolve_socket_addresses(address, deadline)?
        .into_iter()
        .filter(|resolved| {
            permissions
                .check_resolved_network(address, *resolved)
                .is_ok()
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(SocketError::new(
            "SOCKET_PERMISSION",
            format!("UDP 目标“{address}”的 DNS 结果均被网络地址策略拒绝"),
        ));
    }
    let SocketHandle::Udp(socket_handle) = handle else {
        return Err(socket_state(handle, "UDP发送至", "UDP套接字"));
    };
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new(
                "SOCKET_TIMEOUT",
                "发送 UDP 数据报已超过超时上限",
            ));
        }
        socket_handle
            .socket
            .set_write_timeout(Some(remaining))
            .map_err(|error| socket_io_error("SOCKET_WRITE", "配置 UDP 写超时", error))?;
        match socket_handle.socket.send_to(bytes, address) {
            Ok(written) => return Ok(written as u64),
            Err(error) => last_error = Some(error),
        }
    }
    Err(socket_io_error(
        "SOCKET_WRITE",
        "发送 UDP 数据报",
        last_error.expect("地址列表非空"),
    ))
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_send_to(
    _handle: &mut SocketHandle,
    _text: &str,
    _address: &str,
    _timeout_millis: u64,
) -> Result<u64, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_send_to_guarded(
    _handle: &mut SocketHandle,
    _text: &str,
    _address: &str,
    _timeout_millis: u64,
    _permissions: &crate::permissions::PermissionSet,
) -> Result<u64, SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_send_bytes_to_guarded(
    _handle: &mut SocketHandle,
    _bytes: &[u8],
    _address: &str,
    _timeout_millis: u64,
    _permissions: &crate::permissions::PermissionSet,
) -> Result<u64, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_receive_from(
    handle: &mut SocketHandle,
    max_bytes: u64,
    timeout_millis: u64,
) -> Result<(String, String), SocketError> {
    let (bytes, peer) = socket_udp_receive_bytes_from(handle, max_bytes, timeout_millis)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| SocketError::new("SOCKET_UTF8", "UDP 数据报不是完整 UTF-8 文字"))?;
    Ok((text, peer))
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_udp_receive_bytes_from(
    handle: &mut SocketHandle,
    max_bytes: u64,
    timeout_millis: u64,
) -> Result<(Vec<u8>, String), SocketError> {
    let timeout = socket_timeout(timeout_millis)?;
    let capacity = socket_read_capacity(max_bytes)?;
    let SocketHandle::Udp(socket_handle) = handle else {
        return Err(socket_state(handle, "UDP接收自", "UDP套接字"));
    };
    socket_handle
        .socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| socket_io_error("SOCKET_READ", "配置 UDP 读超时", error))?;
    let mut bytes = vec![0; capacity + 1];
    let (length, peer) = socket_handle
        .socket
        .recv_from(&mut bytes)
        .map_err(|error| socket_io_error("SOCKET_READ", "接收 UDP 数据报", error))?;
    if length > capacity {
        return Err(SocketError::new(
            "SOCKET_LIMIT",
            format!("UDP 数据报超过 {max_bytes} 字节上限"),
        ));
    }
    bytes.truncate(length);
    Ok((bytes, peer.to_string()))
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_receive_from(
    _handle: &mut SocketHandle,
    _max_bytes: u64,
    _timeout_millis: u64,
) -> Result<(String, String), SocketError> {
    Err(socket_unsupported())
}

#[cfg(target_family = "wasm")]
pub fn socket_udp_receive_bytes_from(
    _handle: &mut SocketHandle,
    _max_bytes: u64,
    _timeout_millis: u64,
) -> Result<(Vec<u8>, String), SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_shutdown_write(handle: &mut SocketHandle) -> Result<(), SocketError> {
    let SocketHandle::TcpStream(stream) = handle else {
        return Err(socket_state(handle, "关闭写端", "TCP流"));
    };
    match stream.stream.shutdown(Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
        Err(error) => Err(socket_io_error("SOCKET_STATE", "关闭 TCP 写端", error)),
    }
}

#[cfg(target_family = "wasm")]
pub fn socket_shutdown_write(_handle: &mut SocketHandle) -> Result<(), SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_set_nodelay(handle: &mut SocketHandle, enabled: bool) -> Result<(), SocketError> {
    let SocketHandle::TcpStream(stream) = handle else {
        return Err(socket_state(handle, "TCP无延迟", "TCP流"));
    };
    stream
        .stream
        .set_nodelay(enabled)
        .map_err(|error| socket_io_error("SOCKET_STATE", "设置 TCP 无延迟", error))
}

#[cfg(target_family = "wasm")]
pub fn socket_set_nodelay(_handle: &mut SocketHandle, _enabled: bool) -> Result<(), SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_local_address(handle: &SocketHandle) -> Result<String, SocketError> {
    let result = match handle {
        SocketHandle::TcpStream(stream) => stream.stream.local_addr(),
        SocketHandle::TcpListener(listener) => listener.listener.local_addr(),
        SocketHandle::Udp(socket) => socket.socket.local_addr(),
        SocketHandle::Closed => return Err(socket_state(handle, "本地地址", "开放套接字")),
    };
    result
        .map(|address| address.to_string())
        .map_err(|error| socket_io_error("SOCKET_STATE", "读取本地地址", error))
}

#[cfg(target_family = "wasm")]
pub fn socket_local_address(_handle: &SocketHandle) -> Result<String, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_peer_address(handle: &SocketHandle) -> Result<Option<String>, SocketError> {
    match handle {
        SocketHandle::TcpStream(stream) => stream
            .stream
            .peer_addr()
            .map(|address| Some(address.to_string()))
            .map_err(|error| socket_io_error("SOCKET_STATE", "读取对端地址", error)),
        SocketHandle::TcpListener(_) | SocketHandle::Udp(_) => Ok(None),
        SocketHandle::Closed => Err(socket_state(handle, "对端地址", "开放套接字")),
    }
}

#[cfg(target_family = "wasm")]
pub fn socket_peer_address(_handle: &SocketHandle) -> Result<Option<String>, SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
pub fn socket_close(handle: &mut SocketHandle) -> Result<(), SocketError> {
    let previous = std::mem::replace(handle, SocketHandle::Closed);
    if let SocketHandle::TcpStream(stream) = previous {
        match stream.stream.shutdown(Shutdown::Both) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
            Err(error) => {
                return Err(socket_io_error("SOCKET_STATE", "关闭 TCP 流", error));
            }
        }
    }
    Ok(())
}

#[cfg(target_family = "wasm")]
pub fn socket_close(_handle: &mut SocketHandle) -> Result<(), SocketError> {
    Err(socket_unsupported())
}

#[cfg(not(target_family = "wasm"))]
fn resolve_socket_addresses(
    address: &str,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, SocketError> {
    let address = address.trim();
    let (_, port) = address.rsplit_once(':').ok_or_else(|| {
        SocketError::new("SOCKET_ADDRESS", "套接字地址须为主机:端口或 [IPv6]:端口")
    })?;
    if port.parse::<u16>().is_err() {
        return Err(SocketError::new(
            "SOCKET_ADDRESS",
            "套接字端口须为 0..65535 的整数",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SocketError::new(
            "SOCKET_TIMEOUT",
            format!("解析套接字地址“{address}”已超过超时上限"),
        ));
    }
    let owned = address.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = owned
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>());
        let _ = sender.send(result);
    });
    let addresses = match receiver.recv_timeout(remaining) {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(error)) => {
            return Err(SocketError::new(
                "SOCKET_DNS",
                format!("不能解析套接字地址“{address}”：{error}"),
            ));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(SocketError::new(
                "SOCKET_TIMEOUT",
                format!("解析套接字地址“{address}”已超过超时上限"),
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(SocketError::new(
                "SOCKET_DNS",
                format!("解析套接字地址“{address}”的工作线程异常结束"),
            ));
        }
    };
    if addresses.is_empty() {
        Err(SocketError::new(
            "SOCKET_DNS",
            format!("套接字地址“{address}”没有可用结果"),
        ))
    } else {
        Ok(addresses)
    }
}

#[cfg(not(target_family = "wasm"))]
fn socket_permission_error(error: crate::permissions::PermissionError) -> SocketError {
    SocketError::new("SOCKET_PERMISSION", error.to_string())
}

#[cfg(not(target_family = "wasm"))]
fn socket_timeout(timeout_millis: u64) -> Result<Duration, SocketError> {
    if timeout_millis == 0 || timeout_millis > SOCKET_MAX_TIMEOUT_MILLIS {
        Err(SocketError::new(
            "SOCKET_TIMEOUT",
            format!("套接字超时须在 1..={SOCKET_MAX_TIMEOUT_MILLIS} 毫秒之间"),
        ))
    } else {
        Ok(Duration::from_millis(timeout_millis))
    }
}

#[cfg(not(target_family = "wasm"))]
fn socket_read_capacity(max_bytes: u64) -> Result<usize, SocketError> {
    if max_bytes == 0 || max_bytes > SOCKET_MAX_READ_BYTES {
        return Err(SocketError::new(
            "SOCKET_LIMIT",
            format!("套接字单次接收上限须在 1..={SOCKET_MAX_READ_BYTES} 字节之间"),
        ));
    }
    Ok(max_bytes as usize)
}

#[cfg(not(target_family = "wasm"))]
fn socket_io_error(code: &'static str, action: &str, error: std::io::Error) -> SocketError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        SocketError::new("SOCKET_TIMEOUT", format!("{action}超时：{error}"))
    } else {
        SocketError::new(code, format!("{action}失败：{error}"))
    }
}

#[cfg(not(target_family = "wasm"))]
fn socket_state(handle: &SocketHandle, action: &str, expected: &str) -> SocketError {
    SocketError::new(
        "SOCKET_STATE",
        format!("{action}须使用{expected}，当前资源为{}", handle.kind_name()),
    )
}

#[cfg(target_family = "wasm")]
fn socket_unsupported() -> SocketError {
    SocketError::new("SOCKET_UNSUPPORTED", "WASI 运行时未授予原生套接字能力")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBytesResponse {
    pub status: u16,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn http_request(method: &str, url: &str, body: Option<&str>) -> Result<String, NetworkError> {
    http_request_with_options(
        method,
        url,
        body,
        HTTP_DEFAULT_TIMEOUT_MILLIS,
        HTTP_DEFAULT_MAX_BYTES,
    )
    .map(|response| response.body)
}

#[cfg(not(target_family = "wasm"))]
pub fn http_request_with_options(
    method: &str,
    url: &str,
    body: Option<&str>,
    timeout_millis: u64,
    max_bytes: u64,
) -> Result<HttpResponse, NetworkError> {
    http_request_with_options_guarded(
        method,
        url,
        body,
        timeout_millis,
        max_bytes,
        &crate::permissions::PermissionSet::unrestricted(),
    )
}

#[cfg(not(target_family = "wasm"))]
pub fn http_request_with_options_guarded(
    method: &str,
    url: &str,
    body: Option<&str>,
    timeout_millis: u64,
    max_bytes: u64,
    permissions: &crate::permissions::PermissionSet,
) -> Result<HttpResponse, NetworkError> {
    http_request_with_options_and_limits_guarded(
        method,
        url,
        body,
        permissions,
        HttpRequestBudget::new(
            timeout_millis,
            max_bytes,
            crate::budget::HostResourceLimits::default(),
        ),
    )
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn http_request_with_options_and_limits_guarded(
    method: &str,
    url: &str,
    body: Option<&str>,
    permissions: &crate::permissions::PermissionSet,
    budget: HttpRequestBudget,
) -> Result<HttpResponse, NetworkError> {
    let headers = vec![
        ("content-type".into(), "text/plain; charset=utf-8".into()),
        (
            "accept".into(),
            "text/plain, application/json;q=0.9, */*;q=0.1".into(),
        ),
    ];
    let response = http_request_bytes_with_options_and_limits_guarded(
        method,
        url,
        &headers,
        body.map(str::as_bytes),
        permissions,
        budget,
    )?;
    let body = String::from_utf8(response.body)
        .map_err(|_| NetworkError::new("NET_UTF8", "HTTP 响应正文不是 UTF-8 文字"))?;
    Ok(HttpResponse {
        status: response.status,
        url: response.url,
        headers: response.headers,
        body,
    })
}

#[cfg(not(target_family = "wasm"))]
pub fn http_request_bytes_with_options_guarded(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout_millis: u64,
    max_bytes: u64,
    permissions: &crate::permissions::PermissionSet,
) -> Result<HttpBytesResponse, NetworkError> {
    http_request_bytes_with_options_and_limits_guarded(
        method,
        url,
        headers,
        body,
        permissions,
        HttpRequestBudget::new(
            timeout_millis,
            max_bytes,
            crate::budget::HostResourceLimits::default(),
        ),
    )
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn http_request_bytes_with_options_and_limits_guarded(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    permissions: &crate::permissions::PermissionSet,
    budget: HttpRequestBudget,
) -> Result<HttpBytesResponse, NetworkError> {
    use ureq::ResponseExt as _;

    let HttpRequestBudget {
        timeout_millis,
        requested_max_bytes: max_bytes,
        host_limits,
    } = budget;

    let mut parsed = Url::parse(url)
        .map_err(|error| NetworkError::new("NET_URL", format!("网络地址无效：{error}")))?;
    validate_http_url(&parsed)?;
    if timeout_millis == 0 {
        return Err(NetworkError::new("NET_URL", "网络超时须大于零毫秒"));
    }
    if max_bytes == 0 {
        return Err(NetworkError::new("NET_LIMIT", "响应大小上限须大于零字节"));
    }
    let effective_max_bytes = host_limits.effective_http_response_bytes(max_bytes);
    let mut method = ureq::http::Method::from_bytes(method.as_bytes())
        .map_err(|error| NetworkError::new("NET_PROTOCOL", format!("HTTP 方法无效：{error}")))?;
    let mut request_headers = validate_request_headers(headers)?;
    let mut request_body = body.map(<[u8]>::to_vec);
    let deadline = Instant::now() + Duration::from_millis(timeout_millis);
    for redirect_count in 0..=HTTP_MAX_REDIRECTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(NetworkError::new(
                "NET_TIMEOUT",
                "HTTP 请求已超过调用级超时上限",
            ));
        }
        permissions
            .check_network(parsed.as_str())
            .map_err(network_permission_error)?;
        let denial = Arc::new(Mutex::new(None));
        let resolver = PermissionResolver {
            permissions: permissions.clone(),
            denial: denial.clone(),
        };
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(remaining))
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .proxy(None)
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::default(),
            resolver,
        );
        let mut request = ureq::http::Request::builder()
            .method(method.clone())
            .uri(parsed.as_str());
        for (name, value) in &request_headers {
            request = request.header(name, value);
        }
        let request = request
            .body(request_body.as_deref().unwrap_or_default())
            .map_err(|error| {
                NetworkError::new("NET_URL", format!("不能建立 HTTP 请求：{error}"))
            })?;
        let mut response = match agent.run(request) {
            Ok(response) => response,
            Err(error) => {
                if let Some(message) = denial.lock().expect("permission denial lock").take() {
                    return Err(NetworkError::new("NET_PERMISSION", message));
                }
                return Err(network_error_from_ureq(error));
            }
        };
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308)
            && let Some(location) = response.headers().get("location")
        {
            if redirect_count == HTTP_MAX_REDIRECTS {
                return Err(NetworkError::new(
                    "NET_PROTOCOL",
                    format!("HTTP 重定向超过 {HTTP_MAX_REDIRECTS} 跳上限"),
                ));
            }
            let location = location
                .to_str()
                .map_err(|_| NetworkError::new("NET_PROTOCOL", "HTTP Location 首部不是有效文字"))?;
            let next = parsed.join(location).map_err(|error| {
                NetworkError::new("NET_URL", format!("HTTP 重定向地址无效：{error}"))
            })?;
            validate_http_url(&next)?;
            permissions
                .check_network(next.as_str())
                .map_err(network_permission_error)?;
            if !same_http_origin(&parsed, &next) {
                request_headers.retain(|(name, _)| {
                    !matches!(
                        name.as_str(),
                        "authorization" | "cookie" | "proxy-authorization"
                    )
                });
            }
            if matches!(status, 301..=303)
                && method != ureq::http::Method::GET
                && method != ureq::http::Method::HEAD
            {
                method = ureq::http::Method::GET;
                request_body = None;
                request_headers.retain(|(name, _)| name != "content-type");
            }
            parsed = next;
            continue;
        }
        let final_url = response.get_uri().to_string();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("<非文字首部>").to_owned(),
                )
            })
            .collect::<Vec<_>>();
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > effective_max_bytes)
        {
            return Err(http_limit_error(max_bytes, effective_max_bytes));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(effective_max_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(|error| match error {
                ureq::Error::BodyExceedsLimit(_) => {
                    http_limit_error(max_bytes, effective_max_bytes)
                }
                error => network_error_from_ureq(error),
            })?;
        if bytes.len() as u64 > effective_max_bytes {
            return Err(http_limit_error(max_bytes, effective_max_bytes));
        }
        return Ok(HttpBytesResponse {
            status,
            url: final_url,
            headers,
            body: bytes,
        });
    }
    unreachable!("redirect loop returns at its configured bound")
}

#[cfg(not(target_family = "wasm"))]
fn http_limit_error(requested: u64, effective: u64) -> NetworkError {
    if effective < requested {
        NetworkError::new(
            "NET_LIMIT",
            format!("HTTP 响应超过宿主 {effective} 字节上限（应用请求 {requested} 字节）"),
        )
    } else {
        NetworkError::new(
            "NET_LIMIT",
            format!("HTTP 响应超过应用请求的 {requested} 字节上限"),
        )
    }
}

#[cfg(not(target_family = "wasm"))]
fn validate_request_headers(
    headers: &[(String, String)],
) -> Result<Vec<(String, String)>, NetworkError> {
    const FORBIDDEN: &[&str] = &[
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let mut validated = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let normalized = name.trim().to_ascii_lowercase();
        if normalized.is_empty() || FORBIDDEN.contains(&normalized.as_str()) {
            return Err(NetworkError::new(
                "NET_HEADER",
                format!("HTTP 请求首部“{name}”不可由调用方设置"),
            ));
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(NetworkError::new(
                "NET_HEADER",
                "HTTP 请求首部不得含回车或换行",
            ));
        }
        let header_name = ureq::http::HeaderName::from_bytes(normalized.as_bytes())
            .map_err(|_| NetworkError::new("NET_HEADER", format!("HTTP 请求首部名“{name}”无效")))?;
        let header_value = ureq::http::HeaderValue::from_str(value).map_err(|_| {
            NetworkError::new("NET_HEADER", format!("HTTP 请求首部“{name}”的值无效"))
        })?;
        validated.push((
            header_name.as_str().to_owned(),
            header_value.to_str().unwrap_or_default().to_owned(),
        ));
    }
    Ok(validated)
}

#[cfg(not(target_family = "wasm"))]
fn same_http_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[cfg(not(target_family = "wasm"))]
#[derive(Clone)]
struct PermissionResolver {
    permissions: crate::permissions::PermissionSet,
    denial: Arc<Mutex<Option<String>>>,
}

#[cfg(not(target_family = "wasm"))]
impl std::fmt::Debug for PermissionResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PermissionResolver")
    }
}

#[cfg(not(target_family = "wasm"))]
impl ureq::unversioned::resolver::Resolver for PermissionResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        use ureq::unversioned::resolver::DefaultResolver;

        let resource = uri.to_string();
        if let Err(error) = self.permissions.check_network(&resource) {
            *self.denial.lock().expect("permission denial lock") = Some(error.to_string());
            return Err(ureq::Error::HostNotFound);
        }
        let resolved = DefaultResolver::default().resolve(uri, config, timeout)?;
        let mut allowed = self.empty();
        let mut last_denial = None;
        for address in resolved.iter().copied() {
            match self.permissions.check_resolved_network(&resource, address) {
                Ok(()) => allowed.push(address),
                Err(error) => last_denial = Some(error.to_string()),
            }
        }
        if allowed.is_empty() {
            *self.denial.lock().expect("permission denial lock") = Some(
                last_denial.unwrap_or_else(|| format!("网络地址“{resource}”没有获准的 DNS 结果")),
            );
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(allowed)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn validate_http_url(url: &Url) -> Result<(), NetworkError> {
    if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() {
        Ok(())
    } else {
        Err(NetworkError::new(
            "NET_URL",
            "网络地址须使用 http:// 或 https:// 且含主机",
        ))
    }
}

#[cfg(not(target_family = "wasm"))]
fn network_permission_error(error: crate::permissions::PermissionError) -> NetworkError {
    NetworkError::new("NET_PERMISSION", error.to_string())
}

#[cfg(target_family = "wasm")]
pub fn http_request_with_options(
    _method: &str,
    _url: &str,
    _body: Option<&str>,
    _timeout_millis: u64,
    _max_bytes: u64,
) -> Result<HttpResponse, NetworkError> {
    Err(NetworkError::new(
        "NET_PROTOCOL",
        "WASI 运行时未授予原生网络传输能力",
    ))
}

#[cfg(target_family = "wasm")]
pub fn http_request_bytes_with_options_guarded(
    _method: &str,
    _url: &str,
    _headers: &[(String, String)],
    _body: Option<&[u8]>,
    _timeout_millis: u64,
    _max_bytes: u64,
    _permissions: &crate::permissions::PermissionSet,
) -> Result<HttpBytesResponse, NetworkError> {
    Err(NetworkError::new(
        "NET_PROTOCOL",
        "WASI 运行时未授予原生网络传输能力",
    ))
}

#[cfg(target_family = "wasm")]
pub(crate) fn http_request_bytes_with_options_and_limits_guarded(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    permissions: &crate::permissions::PermissionSet,
    budget: HttpRequestBudget,
) -> Result<HttpBytesResponse, NetworkError> {
    let HttpRequestBudget {
        timeout_millis,
        requested_max_bytes: max_bytes,
        host_limits,
    } = budget;
    let _ = host_limits;
    http_request_bytes_with_options_guarded(
        method,
        url,
        headers,
        body,
        timeout_millis,
        max_bytes,
        permissions,
    )
}

#[cfg(target_family = "wasm")]
pub fn http_request_with_options_guarded(
    _method: &str,
    _url: &str,
    _body: Option<&str>,
    _timeout_millis: u64,
    _max_bytes: u64,
    _permissions: &crate::permissions::PermissionSet,
) -> Result<HttpResponse, NetworkError> {
    Err(NetworkError::new(
        "NET_PROTOCOL",
        "WASI 运行时未授予原生网络传输能力",
    ))
}

#[cfg(target_family = "wasm")]
pub(crate) fn http_request_with_options_and_limits_guarded(
    method: &str,
    url: &str,
    body: Option<&str>,
    permissions: &crate::permissions::PermissionSet,
    budget: HttpRequestBudget,
) -> Result<HttpResponse, NetworkError> {
    let HttpRequestBudget {
        timeout_millis,
        requested_max_bytes: max_bytes,
        host_limits,
    } = budget;
    let _ = host_limits;
    http_request_with_options_guarded(method, url, body, timeout_millis, max_bytes, permissions)
}

#[cfg(not(target_family = "wasm"))]
fn network_error_from_ureq(error: ureq::Error) -> NetworkError {
    use std::io::ErrorKind;

    let code = match &error {
        ureq::Error::BadUri(_) | ureq::Error::Http(_) | ureq::Error::InvalidProxyUrl => "NET_URL",
        ureq::Error::HostNotFound => "NET_DNS",
        ureq::Error::Timeout(_) => "NET_TIMEOUT",
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "NET_TLS",
        ureq::Error::ConnectionFailed => "NET_CONNECT",
        ureq::Error::BodyExceedsLimit(_) => "NET_LIMIT",
        ureq::Error::StatusCode(_) => "NET_STATUS",
        ureq::Error::Protocol(_) | ureq::Error::RedirectFailed | ureq::Error::TooManyRedirects => {
            "NET_PROTOCOL"
        }
        ureq::Error::Io(io_error)
            if matches!(io_error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
        {
            "NET_TIMEOUT"
        }
        ureq::Error::Io(io_error)
            if matches!(
                io_error.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::AddrNotAvailable
            ) =>
        {
            "NET_CONNECT"
        }
        ureq::Error::Io(io_error)
            if matches!(
                io_error.kind(),
                ErrorKind::BrokenPipe | ErrorKind::WriteZero
            ) =>
        {
            "NET_WRITE"
        }
        ureq::Error::Io(io_error) if io_error.kind() == ErrorKind::InvalidData => "NET_TLS",
        ureq::Error::Io(_) => "NET_READ",
        _ => "NET_PROTOCOL",
    };
    NetworkError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_primitives_preserve_arbitrary_bytes_and_security_properties() {
        let bytes = bytes_from_numbers(&[0.0, 0xff as f64, 0x80 as f64, 1.0]).unwrap();
        assert_eq!(bytes, [0, 255, 128, 1]);
        assert_eq!(bytes_slice(&bytes, 1, 3).unwrap(), [255, 128]);
        assert_eq!(bytes_concat(&bytes[..2], &bytes[2..]).unwrap(), bytes);
        assert_eq!(bytes_find(&bytes, &[255, 128]), Some(1));
        assert_eq!(bytes_find(&bytes, &[2]), None);
        assert!(bytes_from_numbers(&[256.0]).is_err());

        let digest = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog").unwrap();
        assert_eq!(
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        assert!(constant_time_equal(&digest, &digest));
        assert!(!constant_time_equal(&digest, &digest[..31]));
        assert_eq!(secure_random_bytes(32).unwrap().len(), 32);
        assert_eq!(
            format_http_date(0).unwrap(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert!(format_http_date(253_402_300_800_000).is_err());
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn process_timeout_budget_accepts_long_operations_and_rejects_outside_the_hard_limit() {
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_string_lossy();
        let arguments = vec!["--list".to_owned()];
        let output =
            process_run(&executable, &arguments, None, PROCESS_MAX_TIMEOUT_MILLIS).unwrap();
        assert!(output.success);
        assert_eq!(PROCESS_MAX_TIMEOUT_MILLIS, 86_400_000);
        for timeout in [0, PROCESS_MAX_TIMEOUT_MILLIS + 1] {
            let error = process_run(&executable, &arguments, None, timeout).unwrap_err();
            assert_eq!(
                error,
                format!("PROCESS_TIMEOUT：超时须在 1..={PROCESS_MAX_TIMEOUT_MILLIS} 毫秒之间")
            );
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn binary_http_response_can_cross_the_socket_read_limit_without_truncation() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let body_length = SOCKET_MAX_READ_BYTES as usize + 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            stream.write_all(&vec![0xa5; body_length]).unwrap();
        });
        let response = http_request_bytes_with_options_guarded(
            "GET",
            &format!("http://{address}/large-binary"),
            &[],
            None,
            5_000,
            body_length as u64,
            &crate::permissions::PermissionSet::unrestricted(),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.body.len(), body_length);
        assert!(response.body.iter().all(|byte| *byte == 0xa5));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn streaming_http_response_obeys_the_smaller_host_limit() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nyanxu!\r\n0\r\n\r\n",
                )
                .unwrap();
        });
        let limits = crate::budget::HostResourceLimits::new(8, 5, 4).unwrap();
        let error = http_request_bytes_with_options_and_limits_guarded(
            "GET",
            &format!("http://{address}/stream"),
            &[],
            None,
            &crate::permissions::PermissionSet::unrestricted(),
            HttpRequestBudget::new(1_000, 64, limits),
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code, "NET_LIMIT");
        assert!(error.message.contains("宿主 5 字节上限"), "{error}");
        assert!(error.message.contains("应用请求 64 字节"), "{error}");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn binary_http_request_preserves_headers_body_and_response_bytes() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let length = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..length]);
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    && request.len() >= header_end + 4 + 3
                {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .unwrap();
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
            assert!(headers.to_ascii_lowercase().contains("x-yanxu: binary"));
            assert_eq!(&request[header_end + 4..], &[0, 255, 1]);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\nConnection: close\r\n\r\n\xff\x00\x80",
                )
                .unwrap();
        });
        let permissions = crate::permissions::PermissionSet::unrestricted();
        let response = http_request_bytes_with_options_guarded(
            "POST",
            &format!("http://{address}/binary"),
            &[("X-Yanxu".into(), "binary".into())],
            Some(&[0, 255, 1]),
            1_000,
            64,
            &permissions,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, [255, 0, 128]);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn binary_http_request_returns_non_success_status_and_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0_u8; 1024];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with("GET /missing "));
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing",
                )
                .unwrap();
        });
        let permissions = crate::permissions::PermissionSet::unrestricted();
        let response = http_request_bytes_with_options_guarded(
            "GET",
            &format!("http://{address}/missing"),
            &[],
            None,
            1_000,
            64,
            &permissions,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"missing");
    }

    #[test]
    fn normalizes_paths_without_touching_the_file_system() {
        let separator = std::path::MAIN_SEPARATOR;
        assert_eq!(path_normalize("甲/./乙/../丙"), format!("甲{separator}丙"));
        assert_eq!(
            path_normalize("../../甲"),
            format!("..{separator}..{separator}甲")
        );
        assert_eq!(path_file_name("甲/乙.yx").as_deref(), Some("乙.yx"));
        assert_eq!(path_extension("甲/乙.yx").as_deref(), Some("yx"));
        assert_eq!(path_parent("乙.yx"), None);
    }

    #[test]
    fn hashes_and_encodings_are_utf8_safe() {
        assert_eq!(
            sha256("言序"),
            "7fef6d8232f7e809249c11a4e2944571c0ab010c91329bf9b7bf675601a746e2"
        );
        assert_eq!(hex_decode(&hex_encode("言序")).unwrap(), "言序");
        assert_eq!(
            percent_decode(&percent_encode("言序 /? ")).unwrap(),
            "言序 /? "
        );
        assert!(hex_decode("abc").is_err());
        assert!(percent_decode("%GG").is_err());
    }

    #[test]
    fn post_one_zero_pure_modules_are_reproducible() {
        assert_eq!(
            seeded_random_unit(42.0).unwrap(),
            seeded_random_unit(42.0).unwrap()
        );
        assert_eq!(seeded_random_integer(42.0, 10.0, 20.0).unwrap(), 13.0);
        assert!(seeded_random_bool(42.0).unwrap());
        assert!(seeded_random_integer(1.0, 2.0, 2.0).is_err());

        let identifier = stable_uuid("言序");
        assert_eq!(identifier, "7fef6d82-32f7-8809-a49c-11a4e2944571");
        assert!(is_uuid(&identifier));
        assert_eq!(stable_short_id("言序", 8.0).unwrap(), "7fef6d82");

        let escaped = html_escape("<言序 key='值'>&\"");
        assert_eq!(html_unescape(&escaped), "<言序 key='值'>&\"");
        assert_eq!(
            template_interpolate("问{{name}}安", "name", "子衿").unwrap(),
            "问子衿安"
        );

        assert!(is_email("hello@yanxu.dev"));
        assert!(!is_email("hello@yanxu"));
        assert!(is_ipv4("127.0.0.1"));
        assert!(!is_ipv4("127.00.0.1"));
        assert!(is_hex_color("#7fef6d"));
        assert!(is_identifier("言序_1"));
    }

    #[test]
    fn one_one_text_and_date_modules_are_deterministic() {
        assert_eq!(base64_decode(&base64_encode("言序")).unwrap(), "言序");
        assert_eq!(
            base64_url_decode(&base64_url_encode("言序/语言")).unwrap(),
            "言序/语言"
        );
        assert!(base64_decode("***").is_err());

        assert!(regex_is_match(r"^言.+$", "言序").unwrap());
        assert_eq!(
            regex_first(r"\d+", "甲12乙").unwrap().as_deref(),
            Some("12")
        );
        assert_eq!(
            regex_replace_all(r"\d+", "甲12乙34", "数").unwrap(),
            "甲数乙数"
        );
        assert_eq!(
            regex_split(r"[,，]", "甲,乙，丙").unwrap(),
            ["甲", "乙", "丙"]
        );
        assert!(regex_is_match("[", "言序").is_err());

        let address = "https://yanxu.dev:8443/docs/start?lang=zh&mode=read";
        assert!(url_is_valid(address));
        assert_eq!(url_scheme(address).unwrap(), "https");
        assert_eq!(url_host(address).unwrap().as_deref(), Some("yanxu.dev"));
        assert_eq!(url_port(address).unwrap(), Some(8443.0));
        assert_eq!(url_path(address).unwrap(), "/docs/start");
        assert_eq!(
            url_query_value(address, "lang").unwrap().as_deref(),
            Some("zh")
        );
        assert_eq!(
            url_join("https://yanxu.dev/docs/", "../download").unwrap(),
            "https://yanxu.dev/download"
        );

        assert!(date_is_valid("2024-02-29"));
        assert!(!date_is_valid("2023-02-29"));
        assert!(date_is_leap_year(2000.0).unwrap());
        assert!(!date_is_leap_year(1900.0).unwrap());
        assert_eq!(date_add_days("2024-02-28", 2.0).unwrap(), "2024-03-01");
        assert_eq!(date_add_days("2024-01-01", -1.0).unwrap(), "2023-12-31");
        assert_eq!(date_days_between("2024-02-28", "2024-03-01").unwrap(), 2.0);
        assert!(date_add_days("9999-12-31", 1.0).is_err());
    }

    #[test]
    fn computes_population_statistics() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(stats_sum(&values).unwrap(), 10.0);
        assert_eq!(stats_mean(&values).unwrap(), 2.5);
        assert_eq!(stats_median(&values).unwrap(), 2.5);
        assert_eq!(stats_variance(&values).unwrap(), 1.25);
        assert_eq!(stats_stddev(&values).unwrap(), 1.25_f64.sqrt());
        assert!(stats_mean(&[]).is_err());
    }

    #[test]
    fn parses_and_serializes_rfc4180_style_csv() {
        let source = "姓名,诗句\r\n子衿,\"青青子衿,悠悠我心\"\r\n鹿鸣,\"呦呦\"\"鹿鸣\"\"\"";
        let rows = csv_parse(source).unwrap();
        assert_eq!(rows[1][1], "青青子衿,悠悠我心");
        assert_eq!(rows[2][1], "呦呦\"鹿鸣\"");
        assert_eq!(csv_parse(&csv_stringify(&rows)).unwrap(), rows);
        assert!(csv_parse("\"未闭").is_err());
    }

    #[test]
    fn rejects_unsupported_http_schemes_before_network_access() {
        let error = http_request("GET", "ftp://example.com", None).unwrap_err();
        assert_eq!(error.code, "NET_URL");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn decodes_chunked_http_and_enforces_response_limits() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n\xe5\x96\x84\xe5\x93\x89\r\n0\r\n\r\n",
                )
                .unwrap();
        });
        let response =
            http_request_with_options("GET", &format!("http://{address}/chunked"), None, 1_000, 64)
                .unwrap();
        server.join().unwrap();
        assert_eq!(response.body, "善哉");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nyanxu!",
                )
                .unwrap();
        });
        let error =
            http_request_with_options("GET", &format!("http://{address}/large"), None, 1_000, 5)
                .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code, "NET_LIMIT");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn applies_an_end_to_end_network_timeout() {
        use std::io::Read;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        let error =
            http_request_with_options("GET", &format!("http://{address}/slow"), None, 20, 64)
                .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code, "NET_TIMEOUT");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn checks_http_permissions_again_on_every_redirect_hop() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let denied_target = TcpListener::bind("127.0.0.1:0").unwrap();
        let denied_address = denied_target.local_addr().unwrap();
        let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirector_address = redirector.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = redirector.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://localhost:{}/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                denied_address.port()
            )
            .unwrap();
        });
        let permissions = crate::permissions::PermissionSet::sandboxed().allow_network("127.0.0.1");
        let error = http_request_with_options_guarded(
            "GET",
            &format!("http://{redirector_address}/redirect"),
            None,
            1_000,
            64,
            &permissions,
        )
        .unwrap_err();
        server.join().unwrap();
        drop(denied_target);
        assert_eq!(error.code, "NET_PERMISSION");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn rejects_local_http_dns_results_without_local_network_permission() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let permissions = crate::permissions::PermissionSet::sandboxed().allow_network("*");
        let error = http_request_with_options_guarded(
            "GET",
            &format!(
                "http://localhost:{}/",
                listener.local_addr().unwrap().port()
            ),
            None,
            1_000,
            64,
            &permissions,
        )
        .unwrap_err();
        assert_eq!(error.code, "NET_PERMISSION");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn allows_local_http_dns_results_with_local_network_permission() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let permissions = crate::permissions::PermissionSet::sandboxed()
            .allow_network("*")
            .allow_local_network();
        let response = http_request_with_options_guarded(
            "GET",
            &format!("http://localhost:{port}/"),
            None,
            1_000,
            64,
            &permissions,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "ok");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn returns_http_status_and_classifies_non_utf8_responses() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let response =
            http_request_with_options("GET", &format!("http://{address}/missing"), None, 1_000, 64)
                .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 404);
        assert!(response.body.is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n\xff\xfe",
                )
                .unwrap();
        });
        let error =
            http_request_with_options("GET", &format!("http://{address}/binary"), None, 1_000, 64)
                .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code, "NET_UTF8");
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn tcp_socket_client_and_listener_cover_the_full_resource_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 16];
            let length = stream.read(&mut request).unwrap();
            assert_eq!(&request[..length], "问安".as_bytes());
            stream.write_all("安好".as_bytes()).unwrap();
        });
        let mut client = socket_tcp_connect(&address.to_string(), 1_000).unwrap();
        assert_eq!(client.kind_name(), "TCP流");
        assert!(socket_local_address(&client).unwrap().contains(':'));
        assert_eq!(
            socket_peer_address(&client).unwrap().as_deref(),
            Some(address.to_string().as_str())
        );
        assert_eq!(socket_send(&mut client, "问安", 1_000).unwrap(), 6);
        assert_eq!(socket_receive(&mut client, 16, 1_000).unwrap(), "安好");
        socket_close(&mut client).unwrap();
        socket_close(&mut client).unwrap();
        assert_eq!(
            socket_send(&mut client, "晚安", 1_000).unwrap_err().code,
            "SOCKET_STATE"
        );
        server.join().unwrap();

        let mut listener = socket_tcp_listen("127.0.0.1:0").unwrap();
        let address = socket_local_address(&listener).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all("来客".as_bytes()).unwrap();
        });
        let (mut accepted, peer) = socket_accept(&mut listener, 1_000).unwrap();
        assert!(peer.contains(':'));
        assert_eq!(socket_receive(&mut accepted, 16, 1_000).unwrap(), "来客");
        client.join().unwrap();
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn tcp_receive_buffers_utf8_code_points_split_across_reads() {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0xe5]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            stream.write_all(&[0x96, 0x84]).unwrap();
        });
        let mut client = socket_tcp_connect(&address.to_string(), 1_000).unwrap();
        assert_eq!(socket_receive(&mut client, 3, 1_000).unwrap(), "善");
        server.join().unwrap();
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn tcp_binary_reads_report_eof_and_exact_read_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0, 255, 1]).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let mut client = socket_tcp_connect(&address.to_string(), 1_000).unwrap();
        socket_set_nodelay(&mut client, true).unwrap();
        assert_eq!(
            socket_read_exact_bytes(&mut client, 3, 1_000).unwrap(),
            [0, 255, 1]
        );
        let eof = socket_receive_bytes(&mut client, 8, 1_000).unwrap();
        assert!(eof.eof);
        assert!(eof.bytes.is_empty());
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[1, 2]).unwrap();
        });
        let mut client = socket_tcp_connect(&address.to_string(), 1_000).unwrap();
        assert_eq!(
            socket_read_exact_bytes(&mut client, 3, 1_000)
                .unwrap_err()
                .code,
            "SOCKET_EOF"
        );
        server.join().unwrap();
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn socket_quota_limits_resources_and_releases_capacity_on_close() {
        let permissions = crate::permissions::PermissionSet::sandboxed()
            .allow_tcp_listen("127.0.0.1")
            .allow_udp_bind("127.0.0.1");
        let quota = SocketQuota::new(2, 1);
        let mut listener = socket_tcp_listen_guarded("127.0.0.1:0", &permissions, &quota).unwrap();
        assert_eq!(quota.counts(), (1, 1));
        assert_eq!(
            socket_tcp_listen_guarded("127.0.0.1:0", &permissions, &quota)
                .unwrap_err()
                .code,
            "SOCKET_LIMIT"
        );
        let mut udp = socket_udp_bind_guarded("127.0.0.1:0", &permissions, &quota).unwrap();
        assert_eq!(quota.counts(), (2, 1));
        assert_eq!(
            socket_udp_bind_guarded("127.0.0.1:0", &permissions, &quota)
                .unwrap_err()
                .code,
            "SOCKET_LIMIT"
        );
        socket_close(&mut udp).unwrap();
        assert_eq!(quota.counts(), (1, 1));
        socket_close(&mut listener).unwrap();
        assert_eq!(quota.counts(), (0, 0));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn udp_sockets_preserve_datagrams_and_enforce_limits_and_utf8() {
        let mut receiver = socket_udp_bind("127.0.0.1:0").unwrap();
        let receiver_address = socket_local_address(&receiver).unwrap();
        let mut sender = socket_udp_bind("127.0.0.1:0").unwrap();
        assert_eq!(
            socket_udp_send_to(&mut sender, "善哉", &receiver_address, 1_000).unwrap(),
            6
        );
        let (text, peer) = socket_udp_receive_from(&mut receiver, 16, 1_000).unwrap();
        assert_eq!(text, "善哉");
        assert_eq!(peer, socket_local_address(&sender).unwrap());

        socket_udp_send_to(&mut sender, "12345", &receiver_address, 1_000).unwrap();
        assert_eq!(
            socket_udp_receive_from(&mut receiver, 4, 1_000)
                .unwrap_err()
                .code,
            "SOCKET_LIMIT"
        );

        let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.send_to(&[0xff, 0xfe], &receiver_address).unwrap();
        assert_eq!(
            socket_udp_receive_from(&mut receiver, 4, 1_000)
                .unwrap_err()
                .code,
            "SOCKET_UTF8"
        );
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn socket_errors_distinguish_address_timeout_and_hard_limits() {
        assert_eq!(
            socket_tcp_connect("没有端口", 10).unwrap_err().code,
            "SOCKET_ADDRESS"
        );
        assert_eq!(
            socket_tcp_connect("127.0.0.1:1", 0).unwrap_err().code,
            "SOCKET_TIMEOUT"
        );
        let mut receiver = socket_udp_bind("127.0.0.1:0").unwrap();
        assert_eq!(
            socket_udp_receive_from(&mut receiver, 8, 10)
                .unwrap_err()
                .code,
            "SOCKET_TIMEOUT"
        );
        assert_eq!(
            socket_udp_receive_from(&mut receiver, SOCKET_MAX_READ_BYTES + 1, 10)
                .unwrap_err()
                .code,
            "SOCKET_LIMIT"
        );
    }

    #[test]
    fn api_manifest_audits_all_unique_modules_and_members() {
        let manifest = api_manifest().unwrap();
        assert_eq!(manifest["schema_version"], API_MANIFEST_SCHEMA_VERSION);
        let modules = manifest["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 25);
        let socket_module = modules
            .iter()
            .find(|module| module["name"] == "套接字")
            .unwrap();
        assert_eq!(
            socket_module["permissions"],
            serde_json::json!(["network", "tcp_listen", "udp_bind"])
        );
        let mut module_names = std::collections::HashSet::new();
        for module in modules {
            let name = module["name"].as_str().unwrap();
            assert!(!name.is_empty());
            assert!(module_names.insert(name));
            assert!(module["permissions"].is_array());
            assert!(
                module["platforms"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty())
            );
            assert!(module["deterministic"].is_boolean());
            assert!(!module["members"].as_array().unwrap().is_empty());
            let mut members = std::collections::HashSet::new();
            for member in module["members"].as_array().unwrap() {
                assert!(members.insert(member["name"].as_str().unwrap()));
                assert!(member["signature"].is_string());
                assert!(member.get("errors").is_none_or(serde_json::Value::is_array));
                assert!(
                    member
                        .get("deterministic")
                        .is_none_or(serde_json::Value::is_boolean)
                );
            }
        }
    }
}

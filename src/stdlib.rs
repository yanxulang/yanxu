//! 可由树解释器与字节码 VM 共用的标准库内核。
//!
//! 此处只处理 Rust 基础类型，不依赖任一运行时的 `Value`，以免两个执行器
//! 各自复制路径、编码、统计、CSV 与纯函数工具算法。运行时适配层只负责
//! 类型转换和报错。

use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Component, Path, PathBuf};

pub const API_MANIFEST_SCHEMA_VERSION: u32 = 1;

pub fn api_manifest() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(include_str!("../stdlib/api-v1.json"))
}
use std::time::Duration;

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

pub fn sha256(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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

/// 发送一个小型 HTTP/1.1 请求。当前刻意只支持明文 `http://` 与非分块响应；
/// 这些限制会以明确错误返回，避免把 TLS 或分块内容误作成功结果。
pub fn http_request(method: &str, url: &str, body: Option<&str>) -> Result<String, String> {
    let target = url
        .strip_prefix("http://")
        .ok_or_else(|| "网络模块当前仅支持 http:// 地址".to_string())?;
    let (authority, path) = target
        .split_once('/')
        .map_or((target, "/".into()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, 80), |(host, port)| {
            (host, port.parse::<u16>().unwrap_or(0))
        });
    if host.is_empty() || port == 0 {
        return Err("HTTP 地址之主机或端口无效".into());
    }
    let mut stream = TcpStream::connect((host, port))
        .map_err(|error| format!("不能连接 {authority}：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("不能设置网络超时：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("不能设置网络超时：{error}"))?;
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("HTTP 请求写入失败：{error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("HTTP 响应读取失败：{error}"))?;
    let response = String::from_utf8(response).map_err(|_| "HTTP 响应不是 UTF-8 文字")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "HTTP 响应缺少首部终止符".to_string())?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| "HTTP 响应状态行无效".to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP 请求失败，状态 {status}"));
    }
    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        return Err("暂不支持分块 HTTP 响应".into());
    }
    Ok(body.into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            http_request("GET", "https://example.com", None).unwrap_err(),
            "网络模块当前仅支持 http:// 地址"
        );
    }

    #[test]
    fn api_manifest_audits_all_unique_modules_and_members() {
        let manifest = api_manifest().unwrap();
        assert_eq!(manifest["schema_version"], API_MANIFEST_SCHEMA_VERSION);
        let modules = manifest["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 17);
        let mut module_names = std::collections::HashSet::new();
        for module in modules {
            assert!(module_names.insert(module["name"].as_str().unwrap()));
            assert!(!module["members"].as_array().unwrap().is_empty());
            let mut members = std::collections::HashSet::new();
            for member in module["members"].as_array().unwrap() {
                assert!(members.insert(member["name"].as_str().unwrap()));
                assert!(member["signature"].is_string());
            }
        }
    }
}

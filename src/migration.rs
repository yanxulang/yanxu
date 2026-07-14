//! 1.x 弃用登记与可重复的源码迁移。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Note,
    Warning,
    Error,
}

impl DiagnosticLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Note => "提示",
            Self::Warning => "警告",
            Self::Error => "错误",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deprecation {
    pub id: &'static str,
    pub since: &'static str,
    pub removal: &'static str,
    pub level: DiagnosticLevel,
    pub old: &'static str,
    pub replacement: &'static str,
    pub message: &'static str,
}

pub const REGISTRY: &[Deprecation] = &[Deprecation {
    id: "YXD001",
    since: "0.9.0",
    removal: "2.0.0",
    level: DiagnosticLevel::Warning,
    old: "标准:csv",
    replacement: "标准:CSV",
    message: "标准模块名 csv 的小写兼容别名已弃用",
}];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub deprecation: &'static Deprecation,
    pub line: usize,
    pub column: usize,
    pub start: usize,
    pub end: usize,
}

impl Finding {
    pub fn render(&self, path: &str) -> String {
        format!(
            "{}[{}] {path}:{}:{}：{}；请改为“{}”（预计 {} 移除）",
            self.deprecation.level.label(),
            self.deprecation.id,
            self.line,
            self.column,
            self.deprecation.message,
            self.deprecation.replacement,
            self.deprecation.removal
        )
    }
}

pub fn analyze(source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut offset = 0usize;
    for (line_index, line) in source.split_inclusive('\n').enumerate() {
        let content = line.strip_suffix('\n').unwrap_or(line);
        if content.trim_start().starts_with('引') {
            for deprecation in REGISTRY {
                for old in [
                    format!("「{}」", deprecation.old),
                    format!("“{}”", deprecation.old),
                    format!("\"{}\"", deprecation.old),
                ] {
                    if let Some(relative) = content.find(&old) {
                        let old_name = relative + old.find(deprecation.old).unwrap_or(0);
                        let start = offset + old_name;
                        findings.push(Finding {
                            deprecation,
                            line: line_index + 1,
                            column: content[..old_name].chars().count() + 1,
                            start,
                            end: start + deprecation.old.len(),
                        });
                    }
                }
            }
        }
        offset += line.len();
    }
    findings.sort_by_key(|finding| finding.start);
    findings
}

pub fn migrate(source: &str) -> (String, Vec<Finding>) {
    let findings = analyze(source);
    let mut migrated = source.to_owned();
    for finding in findings.iter().rev() {
        migrated.replace_range(finding.start..finding.end, finding.deprecation.replacement);
    }
    (migrated, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_migrates_deprecated_names_in_import_statements() {
        let source = "定 文本 为「标准:csv」；\n引「标准:csv」为 表；\n";
        let (migrated, findings) = migrate(source);
        assert_eq!(findings.len(), 1);
        assert!(migrated.contains("定 文本 为「标准:csv」"));
        assert!(migrated.contains("引「标准:CSV」为 表"));
        assert_eq!(findings[0].deprecation.id, "YXD001");
    }
}

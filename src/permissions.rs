//! 宿主能力权限模型。
//!
//! 直接 CLI 为兼容既有脚本可显式使用 [`PermissionSet::unrestricted`]；嵌入式
//! 运行时默认使用 [`PermissionSet::sandboxed`]，只开放宿主选择的能力。

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSet {
    allow_all: bool,
    file_roots: Vec<PathBuf>,
    network_hosts: BTreeSet<String>,
    environment_variables: BTreeSet<String>,
    process: bool,
}

impl PermissionSet {
    pub fn unrestricted() -> Self {
        Self {
            allow_all: true,
            file_roots: Vec::new(),
            network_hosts: BTreeSet::new(),
            environment_variables: BTreeSet::new(),
            process: true,
        }
    }

    pub fn sandboxed() -> Self {
        Self {
            allow_all: false,
            file_roots: Vec::new(),
            network_hosts: BTreeSet::new(),
            environment_variables: BTreeSet::new(),
            process: false,
        }
    }

    pub fn allow_file(mut self, root: impl AsRef<Path>) -> Self {
        let root = normalize_existing_or_lexical(root.as_ref());
        if !self.file_roots.contains(&root) {
            self.file_roots.push(root);
            self.file_roots.sort();
        }
        self
    }

    pub fn allow_network(mut self, host: impl Into<String>) -> Self {
        self.network_hosts
            .insert(normalize_host(&host.into()).to_owned());
        self
    }

    pub fn allow_environment(mut self, name: impl Into<String>) -> Self {
        self.environment_variables.insert(name.into());
        self
    }

    pub fn allow_process(mut self) -> Self {
        self.process = true;
        self
    }

    pub fn check_file(&self, path: impl AsRef<Path>) -> Result<(), PermissionError> {
        if self.allow_all {
            return Ok(());
        }
        let requested = normalize_existing_or_lexical(path.as_ref());
        if self
            .file_roots
            .iter()
            .any(|root| requested.starts_with(root))
        {
            Ok(())
        } else {
            Err(PermissionError::new(
                "文件",
                requested.display().to_string(),
            ))
        }
    }

    pub fn check_network(&self, url: &str) -> Result<(), PermissionError> {
        if self.allow_all {
            return Ok(());
        }
        let authority = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .and_then(|target| target.split('/').next())
            .unwrap_or(url);
        let host = normalize_host(authority);
        if self.network_hosts.contains("*")
            || self.network_hosts.contains(authority)
            || self.network_hosts.contains(host)
        {
            Ok(())
        } else {
            Err(PermissionError::new("网络", authority))
        }
    }

    pub fn check_environment(&self, name: &str) -> Result<(), PermissionError> {
        if self.allow_all
            || self.environment_variables.contains("*")
            || self.environment_variables.contains(name)
        {
            Ok(())
        } else {
            Err(PermissionError::new("环境", name))
        }
    }

    pub fn check_process(&self) -> Result<(), PermissionError> {
        if self.allow_all || self.process {
            Ok(())
        } else {
            Err(PermissionError::new("进程", "启动子进程"))
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.allow_all
    }

    pub fn file_roots(&self) -> &[PathBuf] {
        &self.file_roots
    }

    pub fn network_hosts(&self) -> impl Iterator<Item = &str> {
        self.network_hosts.iter().map(String::as_str)
    }

    pub fn environment_variables(&self) -> impl Iterator<Item = &str> {
        self.environment_variables.iter().map(String::as_str)
    }

    pub fn process_allowed(&self) -> bool {
        self.allow_all || self.process
    }
}

impl Default for PermissionSet {
    fn default() -> Self {
        Self::sandboxed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionError {
    pub capability: String,
    pub resource: String,
}

impl PermissionError {
    fn new(capability: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            resource: resource.into(),
        }
    }
}

impl fmt::Display for PermissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "未获{}权限，不可访问“{}”",
            self.capability, self.resource
        )
    }
}

impl std::error::Error for PermissionError {}

fn normalize_existing_or_lexical(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut existing = absolute.as_path();
    let mut suffix = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    if let Ok(mut canonical) = fs::canonicalize(existing) {
        for component in suffix.into_iter().rev() {
            canonical.push(component);
        }
        return canonical;
    }
    PathBuf::from(crate::stdlib::path_normalize(&absolute.to_string_lossy()))
}

fn normalize_host(authority: &str) -> &str {
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map_or(authority, |(host, _)| host)
    } else if authority.matches(':').count() == 1 {
        authority
            .rsplit_once(':')
            .filter(|(_, port)| port.parse::<u16>().is_ok())
            .map_or(authority, |(host, _)| host)
    } else {
        authority
    };
    let host = host.strip_prefix('[').unwrap_or(host);
    host.strip_suffix(']').unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_denies_by_default_and_allows_scoped_capabilities() {
        let root = std::env::temp_dir().join("yanxu-permission-test");
        let permissions = PermissionSet::sandboxed()
            .allow_file(&root)
            .allow_network("localhost")
            .allow_environment("YANXU_TEST");
        assert!(permissions.check_file(root.join("a.txt")).is_ok());
        assert!(permissions.check_file("/unrelated/file").is_err());
        assert!(permissions.check_network("http://localhost:8080/a").is_ok());
        assert!(permissions.check_network("http://example.com").is_err());
        assert!(permissions.check_environment("YANXU_TEST").is_ok());
        assert!(permissions.check_environment("HOME").is_err());
        assert!(permissions.check_process().is_err());

        let ipv6 = PermissionSet::sandboxed().allow_network("::1");
        assert!(ipv6.check_network("[::1]:8080").is_ok());
    }
}

//! 宿主能力权限模型。
//!
//! 直接 CLI 为兼容既有脚本可显式使用 [`PermissionSet::unrestricted`]；嵌入式
//! 运行时默认使用 [`PermissionSet::sandboxed`]，只开放宿主选择的能力。

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Stable capability names exposed by version and engineering handshakes.
pub const PERMISSION_CAPABILITIES: &[&str] = &[
    "文件",
    "网络",
    "TCP监听",
    "UDP绑定",
    "环境",
    "进程",
    "原生扩展",
    "图形界面",
    "剪贴板",
    "文件对话框",
    "系统通知",
    "托盘",
    "打开外部地址",
    "全局快捷键",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSet {
    allow_all: bool,
    file_roots: Vec<PathBuf>,
    network_hosts: BTreeSet<String>,
    tcp_listen_hosts: BTreeSet<String>,
    udp_bind_hosts: BTreeSet<String>,
    environment_variables: BTreeSet<String>,
    process: bool,
    native_extensions: bool,
    graphical_interface: bool,
    clipboard: bool,
    file_dialog: bool,
    system_notifications: bool,
    tray: bool,
    open_external_url: bool,
    global_shortcuts: bool,
}

impl PermissionSet {
    pub fn unrestricted() -> Self {
        Self {
            allow_all: true,
            file_roots: Vec::new(),
            network_hosts: BTreeSet::new(),
            tcp_listen_hosts: BTreeSet::new(),
            udp_bind_hosts: BTreeSet::new(),
            environment_variables: BTreeSet::new(),
            process: true,
            native_extensions: true,
            graphical_interface: true,
            clipboard: true,
            file_dialog: true,
            system_notifications: true,
            tray: true,
            open_external_url: true,
            global_shortcuts: true,
        }
    }

    pub fn sandboxed() -> Self {
        Self {
            allow_all: false,
            file_roots: Vec::new(),
            network_hosts: BTreeSet::new(),
            tcp_listen_hosts: BTreeSet::new(),
            udp_bind_hosts: BTreeSet::new(),
            environment_variables: BTreeSet::new(),
            process: false,
            native_extensions: false,
            graphical_interface: false,
            clipboard: false,
            file_dialog: false,
            system_notifications: false,
            tray: false,
            open_external_url: false,
            global_shortcuts: false,
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
        self.network_hosts.insert(normalize_grant(&host.into()));
        self
    }

    pub fn allow_tcp_listen(mut self, host: impl Into<String>) -> Self {
        self.tcp_listen_hosts.insert(normalize_grant(&host.into()));
        self
    }

    pub fn allow_udp_bind(mut self, host: impl Into<String>) -> Self {
        self.udp_bind_hosts.insert(normalize_grant(&host.into()));
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

    pub fn allow_native_extensions(mut self) -> Self {
        self.native_extensions = true;
        self
    }

    pub fn allow_graphical_interface(mut self) -> Self {
        self.graphical_interface = true;
        self
    }

    pub fn allow_clipboard(mut self) -> Self {
        self.clipboard = true;
        self
    }

    pub fn allow_file_dialog(mut self) -> Self {
        self.file_dialog = true;
        self
    }

    pub fn allow_system_notifications(mut self) -> Self {
        self.system_notifications = true;
        self
    }

    pub fn allow_tray(mut self) -> Self {
        self.tray = true;
        self
    }

    pub fn allow_open_external_url(mut self) -> Self {
        self.open_external_url = true;
        self
    }

    pub fn allow_global_shortcuts(mut self) -> Self {
        self.global_shortcuts = true;
        self
    }

    /// 将应用申请权限收敛到宿主授权上限内。
    ///
    /// `self`表示宿主最终允许的能力，`requested`表示应用清单申请的能力。
    /// 返回值绝不会比任一侧更宽；不受限的一侧等同于只采用另一侧。
    pub fn intersect(&self, requested: &Self) -> Self {
        if self.allow_all {
            return requested.clone();
        }
        if requested.allow_all {
            return self.clone();
        }
        let mut file_roots = Vec::new();
        for host_root in &self.file_roots {
            for requested_root in &requested.file_roots {
                let narrower = if host_root.starts_with(requested_root) {
                    Some(host_root)
                } else if requested_root.starts_with(host_root) {
                    Some(requested_root)
                } else {
                    None
                };
                if let Some(root) = narrower
                    && !file_roots.contains(root)
                {
                    file_roots.push(root.clone());
                }
            }
        }
        file_roots.sort();
        Self {
            allow_all: false,
            file_roots,
            network_hosts: intersect_network_grants(&self.network_hosts, &requested.network_hosts),
            tcp_listen_hosts: intersect_network_grants(
                &self.tcp_listen_hosts,
                &requested.tcp_listen_hosts,
            ),
            udp_bind_hosts: intersect_network_grants(
                &self.udp_bind_hosts,
                &requested.udp_bind_hosts,
            ),
            environment_variables: intersect_exact_grants(
                &self.environment_variables,
                &requested.environment_variables,
            ),
            process: self.process && requested.process,
            native_extensions: self.native_extensions && requested.native_extensions,
            graphical_interface: self.graphical_interface && requested.graphical_interface,
            clipboard: self.clipboard && requested.clipboard,
            file_dialog: self.file_dialog && requested.file_dialog,
            system_notifications: self.system_notifications && requested.system_notifications,
            tray: self.tray && requested.tray,
            open_external_url: self.open_external_url && requested.open_external_url,
            global_shortcuts: self.global_shortcuts && requested.global_shortcuts,
        }
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
        let authority = normalize_grant(url);
        let host = normalize_host(&authority);
        if self.network_hosts.contains("*")
            || self.network_hosts.contains(&authority)
            || self.network_hosts.contains(host)
        {
            Ok(())
        } else {
            Err(PermissionError::new("网络", authority))
        }
    }

    pub fn check_resolved_network(
        &self,
        resource: &str,
        address: SocketAddr,
    ) -> Result<(), PermissionError> {
        self.check_network(resource)?;
        if self.allow_all || !is_sensitive_ip(address.ip()) {
            return Ok(());
        }
        let ip = address.ip().to_string();
        let endpoint = if address.is_ipv6() {
            format!("[{ip}]:{}", address.port())
        } else {
            format!("{ip}:{}", address.port())
        };
        if self.network_hosts.contains(&ip) || self.network_hosts.contains(&endpoint) {
            Ok(())
        } else {
            Err(PermissionError::new(
                "网络地址",
                format!("{resource} → {ip}（回环、私网或特殊地址须精确授权）"),
            ))
        }
    }

    pub fn check_tcp_listen(&self, address: &str) -> Result<(), PermissionError> {
        self.check_bind_permission("TCP监听", &self.tcp_listen_hosts, address)
    }

    pub fn check_udp_bind(&self, address: &str) -> Result<(), PermissionError> {
        self.check_bind_permission("UDP绑定", &self.udp_bind_hosts, address)
    }

    pub fn check_tcp_listen_resolved(
        &self,
        requested: &str,
        address: SocketAddr,
    ) -> Result<(), PermissionError> {
        self.check_tcp_listen(requested)?;
        self.check_bind_ip("TCP监听", &self.tcp_listen_hosts, requested, address)
    }

    pub fn check_udp_bind_resolved(
        &self,
        requested: &str,
        address: SocketAddr,
    ) -> Result<(), PermissionError> {
        self.check_udp_bind(requested)?;
        self.check_bind_ip("UDP绑定", &self.udp_bind_hosts, requested, address)
    }

    fn check_bind_permission(
        &self,
        capability: &str,
        grants: &BTreeSet<String>,
        address: &str,
    ) -> Result<(), PermissionError> {
        if self.allow_all {
            return Ok(());
        }
        let authority = normalize_grant(address);
        let host = normalize_host(&authority);
        if grants.contains("*") || grants.contains(&authority) || grants.contains(host) {
            Ok(())
        } else {
            Err(PermissionError::new(capability, authority))
        }
    }

    fn check_bind_ip(
        &self,
        capability: &str,
        grants: &BTreeSet<String>,
        requested: &str,
        address: SocketAddr,
    ) -> Result<(), PermissionError> {
        if self.allow_all {
            return Ok(());
        }
        let requested_authority = normalize_grant(requested);
        let requested_host = normalize_host(&requested_authority);
        let ip = address.ip().to_string();
        if grants.contains("*")
            || grants.contains(&requested_authority)
            || grants.contains(requested_host)
            || grants.contains(&ip)
        {
            Ok(())
        } else {
            Err(PermissionError::new(
                capability,
                format!("{requested} → {ip}"),
            ))
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

    pub fn check_native_extension(&self, path: impl AsRef<Path>) -> Result<(), PermissionError> {
        if self.allow_all || self.native_extensions {
            Ok(())
        } else {
            Err(PermissionError::new(
                "原生扩展",
                path.as_ref().display().to_string(),
            ))
        }
    }

    pub fn check_graphical_interface(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.graphical_interface, "图形界面", "创建桌面界面")
    }

    pub fn check_clipboard(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.clipboard, "剪贴板", "系统剪贴板")
    }

    pub fn check_file_dialog(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.file_dialog, "文件对话框", "用户选择文件或目录")
    }

    pub fn check_system_notifications(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.system_notifications, "系统通知", "发送系统通知")
    }

    pub fn check_tray(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.tray, "托盘", "系统托盘")
    }

    pub fn check_open_external_url(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(
            self.open_external_url,
            "打开外部地址",
            "交给外部应用打开地址",
        )
    }

    pub fn check_global_shortcuts(&self) -> Result<(), PermissionError> {
        self.check_boolean_capability(self.global_shortcuts, "全局快捷键", "注册系统级快捷键")
    }

    fn check_boolean_capability(
        &self,
        granted: bool,
        capability: &str,
        resource: &str,
    ) -> Result<(), PermissionError> {
        if self.allow_all || granted {
            Ok(())
        } else {
            Err(PermissionError::new(capability, resource))
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

    pub fn tcp_listen_hosts(&self) -> impl Iterator<Item = &str> {
        self.tcp_listen_hosts.iter().map(String::as_str)
    }

    pub fn udp_bind_hosts(&self) -> impl Iterator<Item = &str> {
        self.udp_bind_hosts.iter().map(String::as_str)
    }

    pub fn environment_variables(&self) -> impl Iterator<Item = &str> {
        self.environment_variables.iter().map(String::as_str)
    }

    pub fn process_allowed(&self) -> bool {
        self.allow_all || self.process
    }

    pub fn native_extensions_allowed(&self) -> bool {
        self.allow_all || self.native_extensions
    }

    pub fn graphical_interface_allowed(&self) -> bool {
        self.allow_all || self.graphical_interface
    }

    pub fn clipboard_allowed(&self) -> bool {
        self.allow_all || self.clipboard
    }

    pub fn file_dialog_allowed(&self) -> bool {
        self.allow_all || self.file_dialog
    }

    pub fn system_notifications_allowed(&self) -> bool {
        self.allow_all || self.system_notifications
    }

    pub fn tray_allowed(&self) -> bool {
        self.allow_all || self.tray
    }

    pub fn open_external_url_allowed(&self) -> bool {
        self.allow_all || self.open_external_url
    }

    pub fn global_shortcuts_allowed(&self) -> bool {
        self.allow_all || self.global_shortcuts
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
    normalize_lexical(&absolute)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
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

fn network_authority(resource: &str) -> &str {
    resource
        .strip_prefix("http://")
        .or_else(|| resource.strip_prefix("https://"))
        .and_then(|target| target.split('/').next())
        .unwrap_or(resource)
}

fn normalize_grant(resource: &str) -> String {
    network_authority(resource).trim().to_ascii_lowercase()
}

fn intersect_exact_grants(
    host: &BTreeSet<String>,
    requested: &BTreeSet<String>,
) -> BTreeSet<String> {
    if host.contains("*") {
        return requested.clone();
    }
    if requested.contains("*") {
        return host.clone();
    }
    host.intersection(requested).cloned().collect()
}

fn intersect_network_grants(
    host: &BTreeSet<String>,
    requested: &BTreeSet<String>,
) -> BTreeSet<String> {
    if host.contains("*") {
        return requested.clone();
    }
    if requested.contains("*") {
        return host.clone();
    }
    let mut effective = BTreeSet::new();
    for host_grant in host {
        for requested_grant in requested {
            if host_grant == requested_grant {
                effective.insert(host_grant.clone());
                continue;
            }
            if normalize_host(host_grant) != normalize_host(requested_grant) {
                continue;
            }
            match (explicit_port(host_grant), explicit_port(requested_grant)) {
                (Some(host_port), Some(requested_port)) if host_port != requested_port => {}
                (Some(_), _) => {
                    effective.insert(host_grant.clone());
                }
                (_, Some(_)) => {
                    effective.insert(requested_grant.clone());
                }
                _ => {
                    effective.insert(host_grant.clone());
                }
            }
        }
    }
    effective
}

fn explicit_port(authority: &str) -> Option<u16> {
    if authority.starts_with('[') {
        return authority
            .split_once(']')
            .and_then(|(_, suffix)| suffix.strip_prefix(':'))
            .and_then(|port| port.parse().ok());
    }
    authority
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':'))
        .and_then(|(_, port)| port.parse().ok())
}

pub fn is_sensitive_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [first, second, third, _] = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 198 && matches!(second, 18 | 19))
                || first >= 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|ipv4| is_sensitive_ip(IpAddr::V4(ipv4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersection_never_exceeds_host_or_application_permissions() {
        let root = std::env::temp_dir().join("yanxu-permission-intersection");
        let host = PermissionSet::sandboxed()
            .allow_file(&root)
            .allow_network("example.com:443")
            .allow_tcp_listen("127.0.0.1")
            .allow_environment("LANG")
            .allow_process();
        let application = PermissionSet::sandboxed()
            .allow_file(root.join("data"))
            .allow_network("example.com")
            .allow_tcp_listen("*")
            .allow_udp_bind("127.0.0.1")
            .allow_environment("*")
            .allow_native_extensions();
        let effective = host.intersect(&application);
        assert!(effective.check_file(root.join("data/file.txt")).is_ok());
        assert!(effective.check_file(root.join("other.txt")).is_err());
        assert!(effective.check_network("https://example.com:443/").is_ok());
        assert!(effective.check_network("https://example.com:80/").is_err());
        assert!(effective.check_tcp_listen("127.0.0.1:9000").is_ok());
        assert!(effective.check_udp_bind("127.0.0.1:9000").is_err());
        assert!(effective.check_environment("LANG").is_ok());
        assert!(effective.check_environment("PATH").is_err());
        assert!(effective.check_process().is_err());
        assert!(effective.check_native_extension("extension.so").is_err());
    }

    #[test]
    fn sandbox_denies_by_default_and_allows_scoped_capabilities() {
        let root = std::env::temp_dir().join("yanxu-permission-test");
        let permissions = PermissionSet::sandboxed()
            .allow_file(&root)
            .allow_network("localhost")
            .allow_network("127.0.0.1")
            .allow_tcp_listen("127.0.0.1")
            .allow_udp_bind("127.0.0.1")
            .allow_environment("YANXU_TEST");
        assert!(permissions.check_file(root.join("a.txt")).is_ok());
        assert!(permissions.check_file("/unrelated/file").is_err());
        assert!(permissions.check_network("http://localhost:8080/a").is_ok());
        assert!(
            permissions
                .check_resolved_network("localhost:8080", "127.0.0.1:8080".parse().unwrap())
                .is_ok()
        );
        assert!(permissions.check_tcp_listen("127.0.0.1:0").is_ok());
        assert!(permissions.check_udp_bind("127.0.0.1:0").is_ok());
        assert!(
            PermissionSet::sandboxed()
                .allow_tcp_listen("localhost:8080")
                .check_tcp_listen_resolved("localhost:8080", "127.0.0.1:8080".parse().unwrap())
                .is_ok()
        );
        assert!(permissions.check_network("http://example.com").is_err());
        assert!(permissions.check_environment("YANXU_TEST").is_ok());
        assert!(permissions.check_environment("HOME").is_err());
        assert!(permissions.check_process().is_err());

        let ipv6 = PermissionSet::sandboxed().allow_network("::1");
        assert!(ipv6.check_network("[::1]:8080").is_ok());

        let wildcard = PermissionSet::sandboxed().allow_network("*");
        assert!(wildcard.check_network("https://example.com").is_ok());
        assert!(
            wildcard
                .check_resolved_network("example.com:443", "127.0.0.1:443".parse().unwrap())
                .is_err()
        );
        assert!(
            PermissionSet::sandboxed()
                .allow_network("127.0.0.1")
                .check_resolved_network("127.0.0.1:80", "127.0.0.1:80".parse().unwrap())
                .is_ok()
        );
        assert!(
            PermissionSet::sandboxed()
                .allow_network("127.0.0.1:80")
                .check_resolved_network("127.0.0.1:80", "127.0.0.1:80".parse().unwrap())
                .is_ok()
        );
        assert!(
            PermissionSet::sandboxed()
                .allow_network("127.0.0.1:80")
                .check_resolved_network("127.0.0.1:81", "127.0.0.1:81".parse().unwrap())
                .is_err()
        );
        assert!(
            PermissionSet::sandboxed()
                .allow_network("127.0.0.1")
                .check_tcp_listen("127.0.0.1:0")
                .is_err()
        );
    }

    #[test]
    fn gui_capabilities_are_independent_and_intersect_with_host_limits() {
        let requested = PermissionSet::sandboxed()
            .allow_graphical_interface()
            .allow_clipboard()
            .allow_file_dialog()
            .allow_system_notifications()
            .allow_tray()
            .allow_open_external_url()
            .allow_global_shortcuts();
        assert!(requested.check_graphical_interface().is_ok());
        assert!(requested.check_clipboard().is_ok());
        assert!(requested.check_file_dialog().is_ok());
        assert!(requested.check_system_notifications().is_ok());
        assert!(requested.check_tray().is_ok());
        assert!(requested.check_open_external_url().is_ok());
        assert!(requested.check_global_shortcuts().is_ok());
        assert!(requested.check_file("unrelated").is_err());
        assert!(requested.check_network("https://example.com").is_err());
        assert!(requested.check_native_extension("extension.so").is_err());

        let host = PermissionSet::sandboxed()
            .allow_graphical_interface()
            .allow_file_dialog();
        let effective = host.intersect(&requested);
        assert!(effective.check_graphical_interface().is_ok());
        assert!(effective.check_file_dialog().is_ok());
        assert!(effective.check_clipboard().is_err());
        assert!(effective.check_system_notifications().is_err());
    }
}

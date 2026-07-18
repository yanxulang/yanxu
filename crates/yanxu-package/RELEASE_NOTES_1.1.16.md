# yanxu-package 1.1.16

本版本与言序 1.1.16 同步发布，保持清单格式 2、锁文件格式 2 与公开 API 兼容。

- `PermissionSet`的网络授权支持 IPv4 与 IPv6 CIDR。
- 主机/应用权限交集支持 CIDR 与 CIDR、单 IP、带端口 IP 的安全收窄。
- DNS 解析后的敏感地址复核接受显式 CIDR，但通配符与本地网络能力的既有边界不变。

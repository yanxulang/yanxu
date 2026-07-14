# 迁移到言序 1.1.5

1.1.5 保持语言规范 1 的源码兼容性，主要变化位于项目、依赖和构建流程。格式 1 清单/锁文件仍可读取，但要获得完整传递图、导出表、离线恢复和 YXB 构建，项目应升级到格式 2。

## 1. 安装言序，再使用言包

言包 0.2.0 已完全改用言序源码编写，不再是 Rust/Cargo 程序。因此安装顺序是：

```sh
yanxu version --json
yanbao doctor --manifest-path .
```

`言包`启动时会确认当前言序支持清单 2、锁 2、YXB 1 和原生 ABI 1；不兼容时会要求先升级言序。Unix/Windows 启动器只负责定位`src/主.yx`和`yanxu`，不实现清单或依赖逻辑。

## 2. 升级清单

```toml
[包]
格式 = 2
名 = "我的应用"
版 = "0.1.0"
言序 = ">=1.1.5"
入口 = "src/主.yx"

[依赖]
HTTP = { 包 = "yanxu-http", 版 = "^0.1" }

[导出]
默认 = "src/主.yx"

[资源]
目录 = ["public", "templates"]

[构建]
目标 = "字节码"
```

读取时仍兼容`名/名称`、`版/版本`与中英文表名。工程工具写回时使用统一中文格式。发布类库应填写`[导出]`；没有显式`默认`时核心会以包入口作为默认导出。

## 3. 重建完整锁图

```sh
yanbao install
yanbao tree
yanbao why HTTP
yanbao outdated
yanbao update --dry-run
```

旧格式 1 锁文件不包含完整传递边。在联网环境下重建一次格式 2 锁文件后，后续才能用`--offline`或`yanbao vendor`按精确锁定恢复。不要手工编辑`言序.lock`。

## 4. 收紧模块边界

外部导入只使用三种形式：

```yanxu
引「标准:JSON」为 JSON；
引「包:HTTP」为 HTTP；
引「包:HTTP/请求」为 请求；
引「相对模块.yx」为 模块；
```

请把原来依赖包内部文件的路径导入改成清单导出名。应用不能直接导入只由其它依赖引入的传递包；若源码确实使用它，将它加为自己的直接依赖。

## 5. 构建和验证制品

```sh
yanbao check
yanbao test
yanbao build --release
yanxu run build/我的应用.yxb
yanbao build --release --standalone
```

YXB 已包含所有可达预编译模块和声明资源，不应在运行时读取`.yx`。可用一个临时目录复制制品、移除源码后再执行，作为发布前验收。自包含程序只对其构建目标平台可用，不能把 macOS 制品复制到 Windows/Linux 直接执行。

## 6. CI 建议

三个平台均执行：

```sh
yanbao install --offline
yanbao check
yanbao test
yanbao build --release
yanbao build --release --standalone
```

同时校验两次 YXB/YXP 的 SHA-256 相同，并在删除项目源码副本后运行 YXB。包含原生制品的包还要分目标校验 ABI、制品校验和与权限拒绝路径。

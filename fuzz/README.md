# 言序模糊测试

安装`cargo-fuzz`后，可执行`cargo fuzz run <目标>`。目标包括`frontend`、`formatting`、`bytecode_archive`、`application_archive`、`manifest`、`lockfile`和`engineering_protocol`，分别覆盖词法/解析、格式化重解析与幂等性、版本化字节码、YXB 应用归档、清单、锁文件和工程协议输入。

`corpus/`保存已知边界种子；触发崩溃的最小输入必须先加入对应目录，再修复实现。普通`cargo test`还会以固定内嵌种子调用同一入口，因此不依赖 libFuzzer 的回归检查始终在 CI 执行。

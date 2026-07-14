# 言序模糊测试

安装`cargo-fuzz`后，在本目录执行`cargo fuzz run frontend`、`cargo fuzz run formatting`或`cargo fuzz run bytecode_archive`。三个目标分别覆盖词法/解析、格式化重解析与幂等性、版本化字节码归档解码/重编码。

`corpus/`保存已知边界种子；触发崩溃的最小输入必须先加入对应目录，再修复实现。普通`cargo test`还会以固定内嵌种子调用同一入口，因此不依赖 libFuzzer 的回归检查始终在 CI 执行。

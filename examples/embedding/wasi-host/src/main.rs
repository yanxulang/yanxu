fn main() {
    let execution =
        yanxu::wasm::run_utf8("言「WASI 中的言序」；").expect("纯计算程序应在 WASI 沙箱运行");
    for line in execution.output {
        println!("{line}");
    }
}

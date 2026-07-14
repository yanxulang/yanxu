//! 无状态模糊测试入口；`fuzz/`中的 cargo-fuzz 目标复用这些函数。

pub fn frontend(data: &[u8]) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tokens) = crate::lexer::scan_named(source, "<fuzz>") {
        let _ = crate::parser::parse(tokens);
    }
}

pub fn formatting(data: &[u8]) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(statements) = crate::parse_named(source, "<fuzz>") else {
        return;
    };
    let formatted = crate::formatter::format(&statements);
    let reparsed =
        crate::parse_named(&formatted, "<fuzz-formatted>").expect("格式化器不得生成不可解析源码");
    assert_eq!(crate::formatter::format(&reparsed), formatted);
}

pub fn bytecode_archive(data: &[u8]) {
    if let Ok(chunk) = crate::bytecode::deserialize(data) {
        let encoded = crate::bytecode::serialize(&chunk).expect("已验证归档必须能再次序列化");
        crate::bytecode::deserialize(&encoded).expect("重编码归档必须能再次解码");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_regression_seeds_do_not_panic() {
        for seed in [
            &b"\x00\xff\xe8"[..],
            "异 法 求（）：数 则 归 1；终 言 候 求（）；".as_bytes(),
            "令 表 为 {「未闭」：【1，2；".as_bytes(),
            br#"{"format_version":999,"code":[]}"#,
        ] {
            frontend(seed);
            formatting(seed);
            bytecode_archive(seed);
        }
    }
}

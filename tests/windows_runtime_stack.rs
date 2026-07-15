#![cfg(windows)]

use std::path::Path;

const MINIMUM_STACK_RESERVE: u64 = 8 * 1024 * 1024;

#[test]
fn yanxu_runtime_reserves_stack_for_owner_thread_callbacks() {
    let executable = Path::new(env!("CARGO_BIN_EXE_yanxu"));
    let bytes = std::fs::read(executable).expect("read yanxu executable");
    let pe_offset = read_u32(&bytes, 0x3c) as usize;
    assert_eq!(bytes.get(pe_offset..pe_offset + 4), Some(b"PE\0\0"));

    let optional_header = pe_offset + 24;
    assert_eq!(read_u16(&bytes, optional_header), 0x20b, "expected PE32+");
    let stack_reserve = read_u64(&bytes, optional_header + 0x48);
    assert!(
        stack_reserve >= MINIMUM_STACK_RESERVE,
        "yanxu.exe stack reserve is {stack_reserve} bytes"
    );
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("PE u16 field"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("PE u32 field"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("PE u64 field"))
}

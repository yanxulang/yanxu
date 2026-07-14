#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| yanxu::fuzzing::bytecode_archive(data));

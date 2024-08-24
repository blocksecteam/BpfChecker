#![feature(bench_black_box)]
#![no_main]

use std::collections::BTreeMap;
use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use grammar_aware::*;
use solana_rbpf::{
    elf::{register_bpf_function, Executable},
    insn_builder::{Arch, IntoBytes},
    memory_region::MemoryRegion,
    user_error::UserError,
    verifier::check,
    vm::{EbpfVm, SyscallRegistry, TestInstructionMeter},
};

use crate::common::ConfigTemplate;

mod common;
mod grammar_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
    arch: Arch,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog, data.arch);
    let config = data.template.into();
    if check(prog.into_bytes(), &config).is_err() {
        // verify please
        return;
    }
    let mut mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        prog.into_bytes(),
        None,
        config,
        SyscallRegistry::default(),
        bpf_functions,
    )
    .unwrap();
    let mem_region = MemoryRegion::new_writable(&mem, ebpf::MM_INPUT_START);
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], vec![mem_region]).unwrap();

    drop(black_box(vm.execute_program_interpreted(
        &mut TestInstructionMeter { remaining: 1 << 16 },
    )));
});

#![feature(bench_black_box)]
#![no_main]

use std::collections::BTreeMap;
use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

use solana_rbpf::{
    elf::{register_bpf_function, Executable},
    memory_region::MemoryRegion,
    ebpf,
    user_error::UserError,
    verifier::check,
    vm::{EbpfVm, SyscallRegistry, TestInstructionMeter},
};

use crate::common::ConfigTemplate;

mod common;

#[derive(arbitrary::Arbitrary, Debug)]
struct DumbFuzzData {
    template: ConfigTemplate,
    prog: Vec<u8>,
    mem: Vec<u8>,
}

fuzz_target!(|data: DumbFuzzData| {
    let prog = data.prog;
    let config = data.template.into();
    if check(&prog, &config).is_err() {
        // verify please
        return;
    }
    let mut mem = data.mem;
    let registry = SyscallRegistry::default();
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        &prog,
        None,
        config,
        SyscallRegistry::default(),
        bpf_functions,
    )
    .unwrap();
    let mem_region = MemoryRegion::new_writable(mem.as_mut(), ebpf::MM_INPUT_START);
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], vec![mem_region]).unwrap();

    drop(black_box(vm.execute_program_interpreted(
        &mut TestInstructionMeter { remaining: 1024 },
    )));
});

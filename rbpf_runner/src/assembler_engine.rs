use solana_rbpf::assembler::assemble;
use solana_rbpf::ebpf;
use solana_rbpf::user_error::UserError;
use solana_rbpf::vm::{Config, SyscallRegistry, TestInstructionMeter};

pub fn asm(src: &str) -> Result<Vec<ebpf::Insn>, String> {
    let executable = assemble::<UserError, TestInstructionMeter>(
        src,
        None,
        Config::default(),
        SyscallRegistry::default(),
    )?;
    let (_program_vm_addr, program) = executable.get_text_bytes();
    Ok((0..program.len() / ebpf::INSN_SIZE)
        .map(|insn_ptr| ebpf::get_insn(program, insn_ptr))
        .collect())
}
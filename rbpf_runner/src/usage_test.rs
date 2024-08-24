extern crate solana_rbpf;

use solana_rbpf::{syscalls, user_error::UserError, vm::{Config, EbpfVm, Executable, SyscallObject, SyscallRegistry, TestInstructionMeter}, assembler::assemble, ebpf};
use std::collections::BTreeMap;

fn direct_exec(prog: &[u8], expected_instruction_count: u64) -> u64 {
    println!("will direct_exec");
    // let config = Config {
    //     enable_instruction_tracing: false,
    //     ..Config::default()
    // };
    // let mut syscall_registry = SyscallRegistry::default();
    // $(test_interpreter_and_jit!(register, syscall_registry, $location => $syscall_function; $syscall_context_object);)*
    // let mut executable = assemble::<UserError, TestInstructionMeter>(source, None, config, syscall_registry).unwrap();
    use solana_rbpf::{elf::register_bpf_function, verifier::check};
    let mut bpf_functions = std::collections::BTreeMap::new();
    register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
    // let mut executable = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(prog, None, Config::default(), SyscallRegistry::default(), bpf_functions);
    let mut executable = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog,
        None, //Some(check),
        Config {
            enable_instruction_tracing: true,
            ..Config::default()
        },
        SyscallRegistry::default(),
        bpf_functions,
    ).unwrap();
    println!("EP: {}", executable.get_entrypoint_instruction_offset().unwrap());

    let mem = &mut [
        0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
    ];
    println!("{:?}", executable.get_text_bytes().1);

    if executable.jit_compile().is_err() {
        println!("Fail to JIT it !!!");
    } else {
        println!("jit it!");
    }
    let mut vm = EbpfVm::new(executable.as_ref(), &mut [], mem).unwrap();
    let result = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: expected_instruction_count });

    result.unwrap()
    // test_interpreter_and_jit!(executable, [], ($($location => $syscall_function; $syscall_context_object),*), $check, $expected_instruction_count);
}

fn assemble_and_exec(source: &str, expected_instruction_count: u64) -> u64 {
    let config = Config {
        enable_instruction_tracing: true,
        ..Config::default()
    };
    let mut syscall_registry = SyscallRegistry::default();
    // $(test_interpreter_and_jit!(register, syscall_registry, $location => $syscall_function; $syscall_context_object);)*
    // let mut executable = assemble::<UserError, TestInstructionMeter>(source, None, config, syscall_registry).unwrap();
    let mut executable = assemble::<UserError, TestInstructionMeter>(source, None, config, syscall_registry).unwrap();


    println!("{:?}", executable.get_text_bytes().1);

    // test_interpreter_and_jit!(executable, $mem, ($($location => $syscall_function; $syscall_context_object),*), $check, $expected_instruction_count);
    let mut vm = EbpfVm::new(executable.as_ref(), &mut [], &mut []).unwrap();
    let result_interpreter = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: expected_instruction_count });

    result_interpreter.unwrap()
    // test_interpreter_and_jit!(executable, [], ($($location => $syscall_function; $syscall_context_object),*), $check, $expected_instruction_count);
}

fn main() {
    use rand::{rngs::SmallRng, RngCore, SeedableRng};
    use solana_rbpf::ebpf;
    let instruction_count = 1;
    let iteration_count = 5;//1000000;
    let mut program = vec![0; instruction_count * ebpf::INSN_SIZE];
    program[ebpf::INSN_SIZE * (instruction_count - 1)..ebpf::INSN_SIZE * instruction_count]
        .copy_from_slice(&[ebpf::EXIT, 0, 0, 0, 0, 0, 0, 0]);
    // let seed = 0xC2DB2F8F282284A0;

    let prog = [
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit and return r0
    ];

    // let mut prng = SmallRng::seed_from_u64(seed);
    // println!("will test total chaos!!!");
    // for _ in 0..iteration_count {
    //     // prng.fill_bytes(&mut program[0..ebpf::INSN_SIZE * (instruction_count - 1)]);
    //     if !execute_generated_program(&prog) {
    //         println!("fail while exec generated program!");
    //     } else {
    //         println!("ok");
    //     }
    // }

    // let instruction_count = 1;
    // let mut prog = vec![0; instruction_count * ebpf::INSN_SIZE];
    // prog[ebpf::INSN_SIZE * (instruction_count - 1)..ebpf::INSN_SIZE * instruction_count]
    //     .copy_from_slice(&[ebpf::EXIT, 0, 0, 0, 0, 0, 0, 0]);
    // let prog = &[
    //     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
    // ];

    let result = direct_exec(&prog, 1024);
    println!("result : {}", result);

//
//     //[149, 0, 0, 0, 0, 0, 0, 0]
// //        mov32 r1, 1
// //         mov32 r0, r1
// //     let result = assemble_and_exec(
// //         "
// //
// //         exit",
// //         3,
// //     );
//     println!("result : {}", result);
}


#[cfg(all(not(windows), target_arch = "x86_64"))]
fn execute_generated_program(prog: &[u8]) -> bool {
    use solana_rbpf::{elf::register_bpf_function, verifier::check};
    use std::collections::BTreeMap;

    let max_instruction_count = 1024;
    let mem_size = 1024 * 1024;
    let mut bpf_functions = BTreeMap::new();
    register_bpf_function(&mut bpf_functions, 0, "entrypoint").unwrap();
    let executable = <dyn Executable<UserError, TestInstructionMeter>>::from_text_bytes(
        prog,
        Some(check),
        Config {
            enable_instruction_tracing: true,
            ..Config::default()
        },
        SyscallRegistry::default(),
        bpf_functions,
    );
    let mut executable = if let Ok(executable) = executable {
        executable
    } else {
        println!("fail to generate executable");
        return false;
    };
    println!("EP: {}", executable.get_entrypoint_instruction_offset().unwrap());
    if executable.jit_compile().is_err() {
        println!("fail to jit...");
        return false;
    }
    let (instruction_count_interpreter, tracer_interpreter, result_interpreter) = {
        let mut mem = vec![0u8; mem_size];
        let mut vm = EbpfVm::new(executable.as_ref(), &mut [], &mut mem).unwrap();
        let result_interpreter = vm.execute_program_interpreted(&mut TestInstructionMeter {
            remaining: max_instruction_count,
        });
        let tracer_interpreter = vm.get_tracer().clone();
        (
            vm.get_total_instruction_count(),
            tracer_interpreter,
            result_interpreter,
        )
    };
    let mut mem = vec![0u8; mem_size];
    let mut vm = EbpfVm::new(executable.as_ref(), &mut [], &mut mem).unwrap();
    let result_jit = vm.execute_program_jit(&mut TestInstructionMeter {
        remaining: max_instruction_count,
    });
    let tracer_jit = vm.get_tracer();
    if result_interpreter != result_jit
        || !solana_rbpf::vm::Tracer::compare(&tracer_interpreter, tracer_jit)
    {
        let analysis = solana_rbpf::static_analysis::Analysis::from_executable(executable.as_ref());
        println!("result_interpreter={:?}", result_interpreter);
        println!("result_jit={:?}", result_jit);
        let stdout = std::io::stdout();
        tracer_interpreter
            .write(&mut stdout.lock(), &analysis)
            .unwrap();
        tracer_jit.write(&mut stdout.lock(), &analysis).unwrap();
        panic!();
    }
    if executable.get_config().enable_instruction_meter {
        let instruction_count_jit = vm.get_total_instruction_count();
        assert_eq!(instruction_count_interpreter, instruction_count_jit);
    }
    true
}

#[cfg(all(not(windows), target_arch = "x86_64"))]
#[test]
fn test_total_chaos() {
    use rand::{rngs::SmallRng, RngCore, SeedableRng};
    use solana_rbpf::ebpf;
    let instruction_count = 1;
    let iteration_count = 5;//1000000;
    let mut program = vec![0; instruction_count * ebpf::INSN_SIZE];
    program[ebpf::INSN_SIZE * (instruction_count - 1)..ebpf::INSN_SIZE * instruction_count]
        .copy_from_slice(&[ebpf::EXIT, 0, 0, 0, 0, 0, 0, 0]);
    let seed = 0xC2DB2F8F282284A0;
    let mut prng = SmallRng::seed_from_u64(seed);
    println!("will test total chaos!!!");
    for _ in 0..iteration_count {
        prng.fill_bytes(&mut program[0..ebpf::INSN_SIZE * (instruction_count - 1)]);
        if !execute_generated_program(&program) {
            println!("fail while exec generated program!");
        }
    }
    for _ in 0..iteration_count {
        prng.fill_bytes(&mut program[0..ebpf::INSN_SIZE * (instruction_count - 1)]);
        for index in (0..program.len()).step_by(ebpf::INSN_SIZE) {
            program[index + 0x1] &= 0x77;
            program[index + 0x2] &= 0x00;
            program[index + 0x3] &= 0x77;
            program[index + 0x4] &= 0x00;
            program[index + 0x5] &= 0x77;
            program[index + 0x6] &= 0x77;
            program[index + 0x7] &= 0x77;
        }
        execute_generated_program(&program);
    }
}

extern crate solana_rbpf;

use std::{fs, io};
use std::cmp::max;
use std::collections::BTreeMap;
use std::fmt::format;
use std::fs::{DirEntry, File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::process::exit;
use std::ptr::drop_in_place;
use std::str::FromStr;
use std::io::Write;
use clap::{App, Arg, Command};
use solana_rbpf::{ebpf, elf::Executable, static_analysis, static_analysis::Analysis, user_error::UserError, vm::{Config, EbpfVm, SyscallRegistry, TestInstructionMeter}};
use solana_rbpf::error::EbpfError;
use solana_rbpf::memory_region::MemoryRegion;

mod assembler_engine;

// use std::collections::BTreeMap;
// use rand::{rngs::SmallRng, RngCore, SeedableRng};

#[derive(Clone)]
pub struct DifferentialOption {
    // trace and compare register state
    pub enable_trace: bool,
    pub print_debug_message: bool,
    // compare memory state
    pub enable_mem: bool,
    // jit related
    pub enable_jit: bool,
    // is verifier checked
    pub enable_check: bool,
    pub input_space: Vec<u8>,
    pub heap_space: Vec<u8>,
    // should forcibly continue to run
    pub force_continue: bool,
    pub enable_result_log: bool,
    pub result_log_path: Option<String>,
}

impl Default for DifferentialOption {
    fn default() -> Self {
        Self {
            enable_trace: false,
            print_debug_message: false,
            enable_jit: if cfg!(target_arch = "x86_64") {
                true
            } else {
                false
            },
            enable_mem: false,
            enable_check: false, // enable it to get reachable findings,
            // TODO: Note that these default input/heap spaces are only used in test/rbpf mode,
            // we will fill random data to them in batch mode.
            input_space: vec!(1, 0xFF, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF, 16, 17),
            heap_space: vec![0; 0x1000],
            force_continue: false,
            enable_result_log: false,
            result_log_path: None,
        }
    }
}

fn is_program_checked(program: &[u8]) -> bool {
    use solana_rbpf::verifier::check;

    use solana_rbpf::{elf::register_bpf_function};

    let mut bpf_functions = std::collections::BTreeMap::new();
    let registry = SyscallRegistry::default();
    let config = Config {
        enable_instruction_tracing: true,
        disable_deprecated_load_instructions: false,
        ..Config::default()
    };
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    return !Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        program,
        Some(check),
        config,
        SyscallRegistry::default(),
        bpf_functions,
    ).is_err();
}


fn is_same_err(interpreter_err: &EbpfError<UserError>, jit_err: &EbpfError<UserError>) -> bool {
    match interpreter_err {
        EbpfError::ExceededMaxInstructions(vm_pc, vm_max_size) => {
            match jit_err {
                EbpfError::ExceededMaxInstructions(jit_pc, jit_max_size) => {
                    assert!(vm_max_size == jit_max_size);
                    assert!(vm_pc == jit_pc);
                    return true;
                }
                _ => { assert!(false, "JIT should raise ExceededMaxInstructions.") }
            };
        }
        _ => {}
    };
    return interpreter_err == jit_err;
}

fn is_same_slice_data(slice_a: &Box<[u8]>, slice_b: &Box<[u8]>) -> bool {
    if slice_a.len() != slice_b.len() {
        return false;
    }

    for index in 0..slice_a.len() {
        if slice_a[index] != slice_b[index] {
            return false;
        }
    }

    return true;
}

fn write_to_log(differential_option: &DifferentialOption, log_msg: &str) {
    if (differential_option.enable_result_log) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(differential_option.result_log_path.as_ref().unwrap())
            .unwrap();
        if let Err(e) = writeln!(file, "{}", log_msg) {
            eprintln!("Couldn't write result to file {:?}: {}", differential_option.result_log_path.as_ref(), e);
        }
    }
}

enum ResultMsg {
    ParseTextFailed,
    InterpreterFailed,
    DifferentialInputMemory,
    DifferentialHeapMemory,
    RegisterResult,
    InputMemoryResult,
    HeapMemoryResult,
}

impl ResultMsg {
    fn as_str(&self) -> &'static str {
        match self {
            ResultMsg::ParseTextFailed => "Error in parsing text as executable",
            ResultMsg::InterpreterFailed => "Error in Interpreter mode execution",
            ResultMsg::DifferentialInputMemory => "Differential memory input space found!",
            ResultMsg::DifferentialHeapMemory => "Differential memory heap space found!",
            ResultMsg::RegisterResult => "RegisterResult",
            ResultMsg::InputMemoryResult => "InputMemoryResult",
            ResultMsg::HeapMemoryResult => "HeapMemoryResult",
        }
    }
}

fn direct_exec(program: &[u8], expected_instruction_count: u64, differential_option: DifferentialOption) -> u64 {
    // enable_trace: bool, enable_jit: bool, enable_check: bool
    // println!("will direct_exec");
    use solana_rbpf::{elf::register_bpf_function}; //verifier::check
    use solana_rbpf::verifier::check;
    use solana_rbpf::vm::Verifier;

    let INVALID_EXEC_RESULT = u64::MAX;

    let mut bpf_functions = std::collections::BTreeMap::new();
    let config = Config {
        enable_instruction_tracing: true,
        disable_deprecated_load_instructions: false,
        ..Config::default()
    };
    let registry = SyscallRegistry::default();
    register_bpf_function(&config, &mut bpf_functions, &registry, 0, "entrypoint").unwrap();
    let mut checker: Option<Verifier> = Some(check);
    if !differential_option.enable_check {
        checker = None;
    }

    let mut executable_raw = Executable::<UserError, TestInstructionMeter>::from_text_bytes(
        program,
        checker, // None, //Some(check),
        config,
        SyscallRegistry::default(),
        bpf_functions,
    );

    if executable_raw.is_err() {
        let err_msg = format!("{} -> {:?}", ResultMsg::ParseTextFailed.as_str(), executable_raw.err().unwrap());
        eprintln!("{}", err_msg);
        write_to_log(&differential_option, &err_msg);
        return u64::MAX;
    }
    let mut executable = executable_raw.unwrap();
    let could_jit;
    if differential_option.enable_jit {
        if Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).is_err() {
            could_jit = false;
            eprintln!("couldn't jit this executable");
        } else {
            eprintln!("jit mode is available for this executable.");
            could_jit = true;
        }
    } else {
        could_jit = false;
        println!("JIT is disabled.");
    }

    // disassembler::disassemble_instruction(program);
    // Analysis::disassemble(executable)

    // println!("EP: {}", executable.get_entrypoint_instruction_offset().unwrap());
    // println!("{:?}", executable.get_text_bytes().1);

    // Exec in interpreter mode:
    // let mut vm = EbpfVm::new(executable.as_ref(), &mut [], &mut []).unwrap();
    // let mut slice_input_space_for_vm = [1, 0xFF, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF, 16, 17];
    let mut input_space_for_vm = differential_option.input_space.clone().into_boxed_slice();
    let mut heap_space_for_vm = differential_option.heap_space.clone().into_boxed_slice();

    let input_mem_region_vm = MemoryRegion::new_writable(input_space_for_vm.as_mut(), ebpf::MM_INPUT_START);
    let mut vm = EbpfVm::new(&executable, heap_space_for_vm.as_mut(), vec![input_mem_region_vm]).unwrap();
    let result_interpreter_raw = vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: expected_instruction_count });
    let mut vresult_interpreter_err = None;
    if result_interpreter_raw.is_err() {
        vresult_interpreter_err = Some(result_interpreter_raw.as_ref().err().unwrap());
        let err_msg = format!("{} -> {:?}", ResultMsg::InterpreterFailed.as_str(), vresult_interpreter_err.unwrap());
        eprintln!("{}", err_msg);
        write_to_log(&differential_option, &err_msg);
        if (!could_jit) {
            return INVALID_EXEC_RESULT;
        }
    }
    let mut tracer_interpreter = None;

    // register state
    if differential_option.enable_trace {
        // disable control_flow_graph_dominance_hierarchy manually!
        let analysis = static_analysis::Analysis::from_executable(&executable).unwrap();
        tracer_interpreter = Some(vm.get_tracer());
        let mut dis_result = Vec::new();
        println!("[+] ------- Interpreter Mode: --------");
        println!("[+]Disassemble:");
        let _ = analysis.disassemble(&mut dis_result);
        println!("{}", String::from_utf8(dis_result).unwrap());
        println!("[+]Tracer:");
        let mut trace_result = Vec::new();
        // tracer_jit.write(&mut stdout.lock(), &analysis).unwrap();
        tracer_interpreter.unwrap().write(&mut trace_result, &analysis).unwrap();
        if (differential_option.print_debug_message) {
            println!("{}", String::from_utf8(trace_result).unwrap());
        }
    }
    // memory state:
    if differential_option.enable_mem {
        // To fetch the memory mapping in the vm, we should patch the vm.rs and memory_region.rs, set the memory_mapping/regions field as pub (see readme for detail.)
        // for (index, region) in vm.memory_mapping.regions.iter().enumerate() {
        //     // we only check the writable memory since we trust that the access check for the read-only memory is correct.
        //     if region.is_writable {}
        // }

        // Trade off:
        // As the initial memory region could be controlled by ourselves, we needn't to fetch the region again,
        //  we only care about the MM_HEAP_START and MM_INPUT_START:
        //
        //         let regions: Vec<MemoryRegion> = vec![
        //             MemoryRegion::new_from_slice(&[], 0, 0, false),
        //             MemoryRegion::new_from_slice(ro_region, ebpf::MM_PROGRAM_START, 0, false),
        //             stack.get_memory_region(),
        //             MemoryRegion::new_from_slice(heap_region, ebpf::MM_HEAP_START, 0, true),
        //             MemoryRegion::new_from_slice(input_region, ebpf::MM_INPUT_START, 0, true),
        //         ];
        // println!("[+] input space after vm exec:\n{:?}", input_space_for_vm);
        // println!("[+] heap space after vm exec:\n{:?}", heap_space_for_vm);
    }

    // record VM mode memory state:
    //      we assume this should be same as the one in JIT mode,
    //      otherwise, the corresponding error will be raised to reflect the differential state.
    let err_msg = format!("{} -> {:?}\n{} -> {:?}", ResultMsg::InputMemoryResult.as_str(), input_space_for_vm, ResultMsg::HeapMemoryResult.as_str(), heap_space_for_vm);
    write_to_log(&differential_option, &err_msg);


    // Exec in JIT mode:
    if could_jit {
        let mut input_space_for_jit = differential_option.input_space.clone().into_boxed_slice();
        let mut heap_space_for_jit = differential_option.heap_space.clone().into_boxed_slice();
        let input_mem_region_jit = MemoryRegion::new_writable(input_space_for_jit.as_mut(), ebpf::MM_INPUT_START);
        let mut vm_jit = EbpfVm::new(&executable, heap_space_for_jit.as_mut(), vec![input_mem_region_jit]).unwrap();

        let result_jit_raw = vm_jit.execute_program_jit(&mut TestInstructionMeter {
            remaining: expected_instruction_count,
        });
        // preprint error message to avoid the differential memory result flooding this runtime error.
        if result_jit_raw.is_err() {
            assert!(result_interpreter_raw.is_err());
            println!("Error in JIT mode execution:         {:?}", result_jit_raw.as_ref().err().unwrap());
        }

        // DIFFERENTIAL CORE:

        // no matter whether the program raises error, its memory region should be same as the one in interpreter mode,
        // hence we compare and check the memory state here in advance.
        // compare the memory state after the program executed:
        if differential_option.enable_mem {
            if (!is_same_slice_data(&input_space_for_vm, &input_space_for_jit)) {
                eprintln!("[!] Different memory input space found!");
                eprintln!("input space in vm:\n{:?}", input_space_for_vm);
                eprintln!("input space in jit:\n{:?}", input_space_for_jit);
                let err_msg = format!("{} -> \n\tinput space in vm:\n{:?}\n\tinput space in jit:\n{:?}", ResultMsg::DifferentialInputMemory.as_str(), input_space_for_vm, input_space_for_jit);
                write_to_log(&differential_option, &err_msg);
                if !differential_option.force_continue {
                    assert!(false);// "different memory input space between vm and jit."
                } else {
                    eprintln!("{}", "*".repeat(30));
                }
            }
            if (!is_same_slice_data(&heap_space_for_vm, &heap_space_for_jit)) {
                eprintln!("[!] Different memory heap space found!");
                eprintln!("heap space in vm:\n{:?}", heap_space_for_vm);
                eprintln!("heap space in jit:\n{:?}", heap_space_for_jit);
                let err_msg = format!("{} -> \n\theap space in vm:\n{:?}\n\theap space in jit:\n{:?}", ResultMsg::DifferentialHeapMemory.as_str(), heap_space_for_vm, heap_space_for_jit);
                write_to_log(&differential_option, &err_msg);
                if !differential_option.force_continue {
                    assert!(false);// "different memory heap space between vm and jit."
                } else {
                    eprintln!("{}", "*".repeat(30));
                }
            }
            if (differential_option.print_debug_message) {
                println!("input space in vm:\n{:?}", input_space_for_vm);
                println!("input space in jit:\n{:?}", input_space_for_jit);
                println!("heap space in vm:\n{:?}", heap_space_for_vm);
                println!("heap space in jit:\n{:?}", heap_space_for_jit);
            }
            println!("[+] Same memory result.");
        }

        if result_jit_raw.is_err() {
            assert!(result_interpreter_raw.is_err());
            // println!("Error in JIT mode execution:         {:?}", result_jit_raw.as_ref().err().unwrap());
            assert!(is_same_err(result_interpreter_raw.as_ref().err().unwrap(), result_jit_raw.as_ref().err().unwrap()));
            return INVALID_EXEC_RESULT;
        }

        // compare the register state after each invocation of instruction:
        if differential_option.enable_trace {
            let analysis = solana_rbpf::static_analysis::Analysis::from_executable(&executable).unwrap();
            let tracer_jit = vm_jit.get_tracer();
            println!("[+] ------- JIT Mode: --------");
            println!("[+]Tracer:");
            let mut trace_result = Vec::new();
            // tracer_jit.write(&mut stdout.lock(), &analysis).unwrap();
            tracer_jit.write(&mut trace_result, &analysis).unwrap();
            if (differential_option.print_debug_message) {
                println!("{}", String::from_utf8(trace_result).unwrap());
            }
            if !solana_rbpf::vm::Tracer::compare(&tracer_interpreter.unwrap(), tracer_jit) {
                eprintln!("[!] Different tracer result found!");
                assert!(false);
            } else {
                println!("[+] Same register result.");
            }
        }


        // assume the execution doesn't meet any error

        assert!(result_interpreter_raw.as_ref().unwrap() == result_jit_raw.as_ref().unwrap());
    } else {
        if (differential_option.print_debug_message && differential_option.enable_mem) {
            println!("input space in vm:\n{:?}", input_space_for_vm);
            println!("heap space in vm:\n{:?}", heap_space_for_vm);
        }
    }

    // error in interpreter is handled before
    *result_interpreter_raw.as_ref().unwrap()
}


// #[cfg(all(not(windows), target_arch = "x86_64"))]
#[test]
fn test_direct_run() {
    use solana_rbpf::ebpf;
    let instruction_count = 1;
    let mut program = vec![0; instruction_count * ebpf::INSN_SIZE];
    program[ebpf::INSN_SIZE * (instruction_count - 1)..ebpf::INSN_SIZE * instruction_count]
        .copy_from_slice(&[ebpf::EXIT, 0, 0, 0, 0, 0, 0, 0]);

    let prog = [
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit and return r0
    ];

    fs::write("./expect_3_obj.o", prog).unwrap();

    #[cfg(all(not(windows), target_arch = "x86_64"))]
        let result = direct_exec(&prog, 1024, DifferentialOption {
        enable_trace: false,
        enable_jit: true,
        enable_check: false,
        ..DifferentialOption::default()
    });

    #[cfg(all(target_arch = "aarch64"))]
        let result = direct_exec(&prog, 1024, DifferentialOption {
        enable_trace: false,
        enable_jit: false,
        enable_check: false,
        ..DifferentialOption::default()
    });

    println!("result : {}", result);
}

// Bpf Mode for runner
enum BpfMode {
    RBPF,
    BATCH,
    CHECK,
}

impl FromStr for BpfMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rbpf" => Ok(BpfMode::RBPF),
            "batch" => Ok(BpfMode::BATCH),
            "check" => Ok(BpfMode::CHECK),
            _ => Err("no match"),
        }
    }
}

fn main() {
    let matches = Command::new("BPF Runner")
        .version("0.1.0")
        .author("BpfChecker")
        .about("Bpf program runner.")
        .arg(Arg::new("mode")
            .short('m')
            .long("mode")
            .help("Set bpf mode")
            .possible_values(["rbpf", "batch", "check"])
            .takes_value(true))
        .arg(Arg::new("output")
            .short('o')
            .help("Set result output file")
            .takes_value(true))
        .arg(Arg::new("INPUT")
            .help("Sets the input file to run")
            .required(true)
            .index(1))
        .arg(Arg::new("trace")
            .short('t')
            .help("Enable trace"))
        .arg(Arg::new("verbose")
            .short('v')
            .help("Enable debug message printing"))
        .arg(Arg::new("mem")
            .long("mem")
            .takes_value(false)
            .help("enable memory comparison"))
        .arg(Arg::new("continue")
            .long("continue")
            .takes_value(false)
            .help("forcibly continue to run when found differential cases"))
        .arg(Arg::new("meter_factor")
            .long("meter_factor")
            .short('f')
            .takes_value(true)
            .validator(|s| s.parse::<usize>())
            .help("factor to instruction meter count of each program"))
        .arg(Arg::new("only_vm")
            .long("only_vm")
            .help("enable vm-only and disable jit"))

        // .arg(Arg::new("v")
        //     .short('v')
        //     .multiple_occurrences(true)
        //     .takes_value(true)
        //     .help("Sets the level of verbosity"))
        .get_matches();


    let mode = matches.value_of("mode").unwrap_or("rbpf").parse().unwrap();
    match mode {
        BpfMode::RBPF => println!("Run in rbpf mode."),
        BpfMode::BATCH => println!("Run in batch mode."),
        BpfMode::CHECK => println!("Run in check mode."),
    }

    let input_file = matches.value_of("INPUT").unwrap();
    let mut differential_option = DifferentialOption::default();

    if matches.is_present("trace") {
        differential_option.enable_trace = true; // default false
    }

    if matches.is_present("verbose") {
        differential_option.print_debug_message = true; // default false
    }

    if matches.is_present("mem") {
        differential_option.enable_mem = true; // enable memory comparison
    }

    if matches.is_present("continue") {
        differential_option.force_continue = true; // forcibly continue to run
    }

    if matches.is_present("only_vm") {
        differential_option.enable_jit = false; // only vm mode
    }

    if matches.is_present("output") {
        differential_option.enable_result_log = true; // enable log
    }


    match mode {
        BpfMode::RBPF => {
            println!("input file : {}", input_file);
            let object_data = fs::read(input_file).unwrap();
            let expected_instruction_cnt = (object_data.len() * 10) as u64; // (object_data.len() / 8 + 1) as u64
            // let expected_instruction_cnt = 2; // (object_data.len() / 8 + 1) as u64
            let result = direct_exec(&object_data, expected_instruction_cnt, differential_option);
            println!("result : {} (i.e. {:#x})", result, result);
            if matches.is_present("output") {
                let output_path = matches.value_of("output").unwrap();
                fs::write(output_path, result.to_string()).unwrap();
            }
        }
        BpfMode::BATCH => {
            if !Path::new(input_file).is_dir() {
                eprintln!("{} is not a directory.", input_file);
                exit(-1);
            }
            let mut paths = fs::read_dir(input_file).unwrap()
                .flat_map(|res| res.map(|e| e.path()))
                .collect::<Vec<_>>();
            paths.sort();
            println!("Test {} files in {}", paths.len(), input_file);
            // prepare output log directory
            if differential_option.enable_result_log {
                let log_output_directory = Path::new(matches.value_of("output").unwrap());
                if !log_output_directory.exists() {
                    std::fs::create_dir_all(log_output_directory).unwrap();
                }
            }
            for path in paths {
                let object_data = fs::read(&path).unwrap();

                // let expected_instruction_cnt = (object_data.len() * 10) as u64; // (object_data.len() / 8 + 1) as u64
                let mut expected_instruction_cnt = (object_data.len() / 8 + 1) as u64; // (object_data.len() / 8 + 1) as u64
                if matches.is_present("meter_factor") {
                    let factor: usize = matches.value_of_t("meter_factor").unwrap();
                    expected_instruction_cnt = (object_data.len() / 8 * factor) as u64;
                }
                // let expected_instruction_cnt = 3; // (object_data.len() / 8 + 1) as u64
                println!("[+] Running {:?} with maximum {} instruction cnt.", &path, &expected_instruction_cnt);
                // for batch testing, we should enable verifier check by default
                differential_option.enable_check = true;
                // TODO: we should fill random data to input/heap space, however, to sync with the kernel mode in the future, we left it as default.
                // differential_option.input_space
                if differential_option.enable_result_log {
                    let obj_log_file_base_name = path.file_name().unwrap();
                    let log_output_directory = matches.value_of("output").unwrap();
                    let log_path = Path::new(log_output_directory).join(obj_log_file_base_name).into_os_string().to_str().unwrap().to_owned() + "_result.txt";
                    differential_option.result_log_path = Option::from(log_path);
                }
                let result = direct_exec(&object_data, expected_instruction_cnt, differential_option.clone());
                println!("result : {} (i.e. {:#x})", result, result);
            }
        }
        BpfMode::CHECK => {
            if Path::new(input_file).is_dir() {
                let mut paths = fs::read_dir(input_file).unwrap()
                    .flat_map(|res| res.map(|e| e.path()))
                    .collect::<Vec<_>>();
                paths.sort();
                println!("Check {} files in {}", paths.len(), input_file);
                for path in paths {
                    let object_data = fs::read(&path).unwrap();
                    let result = is_program_checked(&object_data);
                    println!("{:?} status : {} ", &path, result);
                }
            } else {
                println!("Will check {} program", input_file);
                let object_data = fs::read(input_file).unwrap();
                let result = is_program_checked(&object_data);
                println!("Program check status: {}", result);
            }
        }
    }
}


fn run_asm_instructions(instructions: &str) {
    use assembler_engine::asm;

    let program_data = asm(
        instructions
    ).unwrap();
    let mut program = vec![];
    for x in program_data.as_slice() {
        program.append(&mut x.to_vec().clone());
    }
    println!("{:?}", &program);

    #[cfg(all(not(windows), target_arch = "x86_64"))]
        let result = direct_exec(&program, 1024, DifferentialOption {
        enable_trace: false,
        enable_jit: true,
        enable_check: false,
        ..DifferentialOption::default()
    });

    #[cfg(all(target_arch = "aarch64"))]
        let result = direct_exec(&program, 1024, DifferentialOption {
        enable_trace: false,
        enable_jit: false,
        enable_check: false,
        ..DifferentialOption::default()
    });

    println!("result : {}", result);
}


#[test]
fn test_call_instruction() {
    run_asm_instructions("
    mov64 r0, 999
    mov64 r1, -1
    callx 1
    exit
    ")
}


#[test]
fn elf_parsing_test() {
    let mut file = File::open("reloc.so").expect("file open failed");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("failed to read elf file");
    let _ = Executable::<UserError, TestInstructionMeter>::load(Config::default(), &*bytes, SyscallRegistry::default());
    // let mut parsed_elf = Elf::parse(&bytes).unwrap();
    // let elf_bytes = bytes.to_vec();
}

#[test]
fn test_is_same_slice_data() {
    let mut slice_a: Box<[u8]> = vec!(1, 2, 3, 4, 5, ).into_boxed_slice();
    let mut slice_b: Box<[u8]> = vec!(1, 2, 3, 4, 6, ).into_boxed_slice();
    let mut slice_c: Box<[u8]> = vec!(1, 2, 3, 4, 5, 6, 7, 8, 9).into_boxed_slice();
    slice_a[4] = 6;
    slice_a[0] = 0xff;
    slice_b[0] = 0xff;
    println!("{:?}", slice_a);
    println!("{:?}", slice_b);
    println!("{:?}", slice_c);
    assert!(is_same_slice_data(&slice_a, &slice_b));
    assert!(!is_same_slice_data(&slice_a, &slice_c));
}
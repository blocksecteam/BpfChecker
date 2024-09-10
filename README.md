# BpfChecker

Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing

### Module Structure

- `bpf_ir`: lightweight eBPF IR
- `rbpf_runner`: instrumented rBPF
- `ubpf_runner`: instrumented Windows eBPF core VM

### Requirements

The following toolchains are required to be installed in advanced:

- clang
- rust toolchain

### Usage

See README in `bpf_ir` for details about how to generate IR eBPF program, and how to mutate, fix the IR program.

For differential fuzzing of the `rbpf` and Windows eBPF, please see `rbpf_runner` for detail.

#### Demo Usage

> Note that the script is aimed at running on the Ubuntu host.

To build the IR generator and the runner, run `build.sh`.

After building the necessary, run fuzzer by `run.sh`. You can change the necessary path in the script. 

When correctly running the fuzzer, the output would be:
```
[-] Fuzzing iteration 0 completed in 0.369602 seconds.
[-] Fuzzing iteration 1 completed in 0.461553 seconds.
[-] Fuzzing iteration 2 completed in 0.37018 seconds.
[-] Fuzzing iteration 3 completed in 0.370709 seconds.
[-] Fuzzing iteration 4 completed in 0.387481 seconds.
```

### Trophy

Details of the found bugs and the fix commits are listed in https://gist.github.com/bpfchecker/34a31c23a2da08564577df1bc8d8fce8

### TODO

Further cleanup and the instructions for the runner.

# BpfChecker

Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing

### Module Structure

- `bpf_ir`: lightweight eBPF IR
- `rbpf_runner`: instrumented rBPF
- `ubpf_runner`: instrumented Windows eBPF core VM

### Usage

See README in `bpf_ir` for details about how to generate IR eBPF program, and how to mutate, fix the IR program.

For differential fuzzing of the `rbpf` and Windows eBPF, please see `rbpf_runner` for detail.

### Trophy

See https://gist.github.com/bpfchecker/34a31c23a2da08564577df1bc8d8fce8 for detail.

### TODO

Further cleanup and the instructions for the runner.

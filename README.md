# BpfChecker

Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing

### Module Structure

- `bpf_ir`: lightweight eBPF IR
- `rbpf_runner`: instrumented rBPF
- `ubpf_runner`: instrumented Windows eBPF core VM

### Usage

See README in `bpf_ir` for details about how to generate IR eBPF program, and how to mutate, fix the IR program.
For differential fuzzing of the `rbpf` and Windows eBPF, see `rbpf_runner` for detail.
# BpfChecker

This is the repository for paper "Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing" accepted to CCS 2024.

# Tools

## Module Structure

- `bpf_ir`: lightweight eBPF IR
- `rbpf_runner`: instrumented rBPF
- `ubpf_runner`: instrumented Windows eBPF core VM

## Requirements

The following toolchains are required to be installed in advanced:

- Clang
- Rust Toolchain
- Ninja, Cmake

### Demo Usage

> Note that the script is aimed at running on the Ubuntu host. This demo performs the differential fuzzing between the JIT and interpreter mode of the Solana rBPF.

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

## Trophy

Details of the found bugs and the fix commits are listed in https://gist.github.com/bpfchecker/34a31c23a2da08564577df1bc8d8fce8

# Citation

If you use the related tools or the insights we observed in our paper. Please considering cite our paper.

```
@inproceedings{10.1145/3658644.3690237,
author = {Chaoyuan, Peng and Jiang, Muhui and Lei, Wu and Zhou, Yajin},
title = {Toss a Fault to BpfChecker: Revealing Implementation Flaws for eBPF runtimes with Differential Fuzzing},
year = {2024},
isbn = {9798400706363},
url = {https://doi.org/10.1145/3658644.3690237},
doi = {10.1145/3658644.3690237},
keywords = {Differential Fuzzing, eBPF, Software Security},
}
```
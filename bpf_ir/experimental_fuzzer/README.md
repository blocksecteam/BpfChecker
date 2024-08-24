## initial support for fuzzing kernel eBPF

Although BpfChecker is not targeted at the kernel eBPF, we implement our initial version for differential fuzzing between Linux kernel eBPF and Windows eBPF. Since this is only the initial support, there still remain 

### Preparation

1. The current version requires `lkl` to be installed, please refer https://github.com/lkl/linux for instructions.

2. Fetch and build the source code of the Windows eBPF verifier in https://github.com/vbpf/ebpf-verifier

Modify the corresponding path (lkl library and verifier object) in the `CMakeLists.txt`. You may need to build the underlying library/object with `-fsanitize=address` or other sanitizer compiler flag.

3. Build and run the `combineFuzzer` target. The fuzzer will boot the LKL at the initial stage and perform differential verification later.


### Trivial LKL Setup Instructions

To build a bpf-supported kernel, add the following options to the `defconfig`:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPFILTER=y

CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_KALLSYMS_USE_DATA_SECTION=y
CONFIG_BPF_SYSCALL=y
```

#### LKL 

Take building lkl for an example:

1. Get the lkl source and i nstall the dependency.
```
sudo apt install -y bison flex libelf-dev libfuse-dev libarchive-dev xfsprogs
```

2. Modify the `arch/lkl/configs/defconfig` with the above options.

3. part from https://github.com/lkl/linux/blob/master/.circleci/config.yml

If you want to build with clang:
```shell
make ARCH=lkl CC=clang mrproper
pushd tools/lkl && make CC=clang clean-conf && popd
pushd tools/lkl && make CC=clang ARCH=lkl -j12 dpdk=no && popd
```
Otherwise just:
```shell
make ARCH=lkl defconfig
```


```
make mrproper
pushd tools/lkl && make clean-conf && popd
pushd tools/lkl && make -j`nproc` dpdk=no && popd
```
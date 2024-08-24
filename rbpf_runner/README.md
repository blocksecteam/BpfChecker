# Rbpf runner

## Usage
```
BPF Runner 0.1.0

Bpf program runner.

USAGE:
    rbpf_runner [OPTIONS] <INPUT>

ARGS:
    <INPUT>    Sets the input file to run

OPTIONS:
    -h, --help           Print help information
    -m, --mode <mode>    Set bpf mode [possible values: rbpf, kernel]
    -v <v>               Sets the level of verbosity
    -V, --version        Print version information
```

## some manual patches

In the future, we could leverage some auto patcher scripts and patch them automatically no matter which rbpf version we use.

To fetch and compare memory state, apply the following minimized patches:
```diff
diff --git a/src/vm.rs b/src/vm.rs
index d9fe4c0..aaaf459 100644
--- a/src/vm.rs
+++ b/src/vm.rs
@@ -454,7 +454,7 @@ pub struct EbpfVm<'a, E: UserDefinedError, I: InstructionMeter> {
     executable: &'a Executable<E, I>,
     program: &'a [u8],
     program_vm_addr: u64,
-    memory_mapping: MemoryMapping<'a>,
+    pub memory_mapping: MemoryMapping<'a>,
     tracer: Tracer,
     syscall_context_objects: Vec<*mut u8>,
     syscall_context_object_pool: Vec<Box<dyn SyscallObject<E> + 'a>>,
```

```diff
diff --git a/src/memory_region.rs b/src/memory_region.rs
index d6f6f21..1060d95 100644
--- a/src/memory_region.rs
+++ b/src/memory_region.rs
@@ -111,7 +111,7 @@ pub enum AccessType {
 /// Indirection to use instead of a slice to make handling easier
 pub struct MemoryMapping<'a> {
     /// Mapped memory regions
-    regions: Box<[MemoryRegion]>,
+    pub regions: Box<[MemoryRegion]>,
     /// VM configuration
     config: &'a Config,
 }
```
#ifndef BPF_IR_IR_H
#define BPF_IR_IR_H

#include <ostream>
#include <memory>
#include <vector>

#define DUMMY_OFFSET (0)
#define DUMMY_MAP_FD (0)

class Instruction;

class BasicBlock;

class Module;

using InstPtr = std::unique_ptr<Instruction>;
using Insts = std::vector<InstPtr>;
using BasicBlockPtr = std::unique_ptr<BasicBlock>;
using BasicBlockPtrs = std::vector<BasicBlockPtr>;
using ModulePtr = std::unique_ptr<Module>;
using BytecodeData = std::vector<struct bpf_insn>;

#endif //BPF_IR_IR_H

#ifndef BPF_IR_IRDUMP_H
#define BPF_IR_IRDUMP_H

#include "../Instruction.h"

void printInstruction(int i, struct bpf_insn *in_data);

#endif //BPF_IR_IRDUMP_H

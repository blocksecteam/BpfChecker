#include <gtest/gtest.h>

#include "Module.h"
#include "util/irDump.h"
#include <iostream>

using namespace std;

void print_instruction(bpf_insn input) {
    char *buffer = reinterpret_cast<char *>(&input);

    for (int i = 0; i < sizeof(bpf_insn); ++i) {
        printf("0x%02x,", (unsigned char) buffer[i]);
    }
}

void print_instructions(BytecodeData &input) {
    printf("unsigned char data[]={");
    size_t size = input.size();
    for (int i = 0; i < size; ++i) {
        print_instruction(input[i]);
    }
    printf("};\n");
}


TEST(InstructionTest, SimpleMapInstructionGenerator) {

    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    bb->add(std::make_unique<LoadMapInst>(0, defaultReservedRegisters.getMapPtrRegister(),
                                          defaultReservedRegisters.getMapFdRegister(), true));
    bb->add(std::make_unique<LoadInst>(Register::REG_2, defaultReservedRegisters.getMapPtrRegister(), 0,
                                       BitWidth::bit64));
//    bb->add(std::make_unique<MovInst>(Register::REG_3, defaultReservedRegisters.getMapPtrRegister(),
//                                      BitWidth::bit64));
//    bb->add(std::make_unique<MovInst>(Register::REG_4, defaultReservedRegisters.getMapPtrRegister(),
//                                      BitWidth::bit64));
//    bb->add(std::make_unique<AluInst>(AluOpcode::ADD, Register::REG_3, 1,
//                                      BitWidth::bit64));
//    bb->add(std::make_unique<AluInst>(AluOpcode::SUB, Register::REG_3, Register::REG_4,
//                                      BitWidth::bit64));
    bb->add(std::make_unique<StoreInst>(defaultReservedRegisters.getMapPtrRegister(),
                                        777, 0,
                                        BitWidth::bit16));
    bb->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit64));
    bb->setExitTerminator();
    module.addBasicBlock(std::move(bb));
    print_instructions(module.CodeGen());
    std::cout << module;
}
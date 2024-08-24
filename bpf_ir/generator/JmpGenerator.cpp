#include <sstream>
#include "JmpGenerator.h"

using namespace std;

TestCase generate_jmp_instruction() {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    // Notice:
    //  JA instruction is only supported in JMP_IMM mode!
    bb->add(std::make_unique<BranchInst>(BranchOpcode::JA, Register::REG_1, 0, -1, BitWidth::bit64));
    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

TestCase generate_call_instruction() {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    // Notice:
    //  JA instruction is only supported in JMP_IMM mode!
    bb->add(std::make_unique<BranchInst>(BranchOpcode::JA, Register::REG_1, 0, -1, BitWidth::bit64));
    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

std::vector<TestCase> generate_jmp_instructions() {
    vector<TestCase> result;
    result.push_back(generate_jmp_instruction());
    return result;
}
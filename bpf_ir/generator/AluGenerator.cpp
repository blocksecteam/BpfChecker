#include <sstream>
#include "AluGenerator.h"

std::vector<AluOpcode> aluOpcodeList = {
        AluOpcode::ADD,
        AluOpcode::SUB,
        AluOpcode::MUL,
        AluOpcode::DIV,
        AluOpcode::OR,
        AluOpcode::AND,
        AluOpcode::LSH,
        AluOpcode::RSH,
        AluOpcode::NEG,
        AluOpcode::MOD,
        AluOpcode::XOR,
};

enum RegisterRelation {
    Each,
    EachReverse,
    FirstOnly,
    SecondOnly,
};

enum ResultRegister {
    FirstResultShort,
    FirstResultFull,
    SecondResultShort,
    SecondResultFull,
};

TestCase
generate_simple_alu_instruction(size_t opcodeIdx, RegisterRelation relation, bool use_32_bit_width,
                                ResultRegister result_reg) {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
//    bb->add(std::make_unique<LoadMapInst>(0, defaultReservedRegisters.getMapPtrRegister(),
//                                          defaultReservedRegisters.getMapFdRegister(), true));
//    bb->add(std::make_unique<LoadInst>(Register::REG_5,
//                                       defaultReservedRegisters.getMapPtrRegister(), 0, BitWidth::bit64));
//    bb->add(std::make_unique<LoadInst>(Register::REG_4,
//                                       defaultReservedRegisters.getMapPtrRegister(), 8, BitWidth::bit64));

//    bb->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit64));

    auto anchor = getRandomRegister();
//    bb->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));
    bb->add(std::make_unique<LoadImm64Inst>(anchor, random_generator()));
    auto subtle = getRandomRegister();
    bb->add(std::make_unique<LoadImm64Inst>(subtle, random_generator()));

    BitWidth width = BitWidth::bit64;
    if (use_32_bit_width) {
        width = BitWidth::bit32;
    }
    assert(opcodeIdx < aluOpcodeList.size());
    switch (relation) {
        case Each:
            bb->add(std::make_unique<AluInst>(aluOpcodeList[opcodeIdx], anchor, subtle, width));
            break;
        case EachReverse:
            bb->add(std::make_unique<AluInst>(aluOpcodeList[opcodeIdx], subtle, anchor, width));
            break;
        case FirstOnly:
            bb->add(std::make_unique<AluInst>(aluOpcodeList[opcodeIdx], anchor, anchor, width));
            break;
        case SecondOnly:
            bb->add(std::make_unique<AluInst>(aluOpcodeList[opcodeIdx], subtle, subtle, width));
            break;
    }

    // rewrite anchor/subtle to r0
    switch (result_reg) {
        case FirstResultShort:
            bb->add(std::make_unique<MovInst>(Register::REG_0, anchor, BitWidth::bit32));
            break;
        case FirstResultFull:
            bb->add(std::make_unique<MovInst>(Register::REG_0, anchor, BitWidth::bit64));
            break;
        case SecondResultShort:
            bb->add(std::make_unique<MovInst>(Register::REG_0, subtle, BitWidth::bit32));
            break;
        case SecondResultFull:
            bb->add(std::make_unique<MovInst>(Register::REG_0, subtle, BitWidth::bit64));
            break;
    }
    bb->setExitTerminator();
    int size = bb->getInstructions().size();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

std::vector<TestCase> generate_one_alu_program() {
    std::vector<TestCase> result;
    for (size_t opcodeIdx = 0; opcodeIdx < aluOpcodeList.size(); ++opcodeIdx) {
        for (auto relation = 0; relation <= RegisterRelation::SecondOnly; relation++) {
            for (auto use_32_bit_width = 0; use_32_bit_width <= 1; use_32_bit_width++) {
                for (auto result_reg = 0; result_reg <= SecondResultFull; ++result_reg) {
                    result.push_back(
                            generate_simple_alu_instruction(opcodeIdx, (RegisterRelation) relation, use_32_bit_width,
                                                            (ResultRegister) result_reg));
                    goto end;

                }

            }
        }
    }
    end:
    return result;
}

std::vector<TestCase> generate_simple_alu_set() {
    std::vector<TestCase> result;
    for (size_t opcodeIdx = 0; opcodeIdx < aluOpcodeList.size(); ++opcodeIdx) {
        for (auto relation = 0; relation <= RegisterRelation::SecondOnly; relation++) {
            for (auto use_32_bit_width = 0; use_32_bit_width <= 1; use_32_bit_width++) {
                for (auto result_reg = 0; result_reg <= SecondResultFull; ++result_reg) {
                    result.push_back(
                            generate_simple_alu_instruction(opcodeIdx, (RegisterRelation) relation,
                                                            use_32_bit_width,
                                                            (ResultRegister) result_reg)
                    );
                }
            }
        }
    }
    return result;
}


TestCase generate_div_by_zero_instruction(bool use_32_bit_width) {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    auto anchor = getRandomRegister();
//    bb->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));
    bb->add(std::make_unique<LoadImm64Inst>(anchor, random_generator()));
    auto subtle = getRandomRegister();
    bb->add(std::make_unique<LoadImm64Inst>(subtle, 0));

    BitWidth width = BitWidth::bit64;
    if (use_32_bit_width) {
        width = BitWidth::bit32;
    }
//    bb->add(std::make_unique<AluInst>(AluOpcode::DIV, anchor, subtle, width));
    bb->add(std::make_unique<AluInst>(AluOpcode::DIV, anchor, 0, width));

    bb->add(std::make_unique<MovInst>(Register::REG_0, anchor, BitWidth::bit32));
    bb->setExitTerminator();
    int size = bb->getInstructions().size();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

TestCase generate_shift_instruction(uint32_t shift_offset) {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    auto anchor = getRandomRegister();
    bb->add(std::make_unique<LoadImm64Inst>(anchor, -2));
    auto subtle = getRandomRegister();
    bb->add(std::make_unique<LoadImm64Inst>(subtle, shift_offset));
//    bb->add(std::make_unique<LoadImm64Inst>(subtle, 256*256));

    BitWidth width = BitWidth::bit32;
//    BitWidth width = BitWidth::bit64;
//    if (use_32_bit_width) {
//        width = BitWidth::bit32;
//    }
//    bb->add(std::make_unique<AluInst>(AluOpcode::DIV, anchor, subtle, width));
    bb->add(std::make_unique<AluInst>(AluOpcode::RSH, anchor, subtle, width));
    bb->add(std::make_unique<MovInst>(Register::REG_0, anchor, BitWidth::bit64));
    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

std::vector<TestCase> generate_shift_instructions() {
    std::vector<TestCase> result;

    for (int i = 0; i < 255 * 255; ++i) {
        result.push_back(generate_shift_instruction(i));
    }
    return result;
}

// TODO: cleanup and add more ALU instruction generation here
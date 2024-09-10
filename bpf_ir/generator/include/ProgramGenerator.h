#ifndef BPF_IR_PROGRAMGENERATOR_H
#define BPF_IR_PROGRAMGENERATOR_H

#include "Util.h"
#include "Randomizer.hpp"
#include <vector>
#include <optional>

const size_t MM_PROGRAM_START64 = 0x100000000;
/// Start of the stack in the memory map
const size_t MM_STACK_START = 0x200000000;
/// Start of the heap in the memory map
const size_t MM_HEAP_START = 0x300000000;
/// Start of the input buffers in the memory map
const size_t MM_INPUT_START = 0x400000000;

enum GeneratorAction {
    CREATE_ALU,
    CREATE_MOV,
    CREATE_LOAD,
    CREATE_LOAD_IMM,
    CREATE_LOAD_PACKET,
    CREATE_STORE,
    CREATE_CALL,
    SET_BLOCK_JMP,
    SET_BLOCK_EXIT,
    ADD_BLOCK,
    SWITCH_BLOCK_UP,
    SWITCH_BLOCK_DOWN,
    SWITCH_BLOCK_RANDOM,
};

class ProgramGenerator {

public:

    enum class GeneratorType {
        UBPF_OOB_POC,
        UBPF_INTEGER_OVERFLOW_ADDR_POC,
    };

    virtual TestCase generateProgram(size_t action_size) = 0;

    TestCase generatePoC(GeneratorType type);

    ProgramGenerator() = default;
    ~ProgramGenerator() = default;

    std::unique_ptr<Instruction>
    generateWriteUsageInstruction(Register writtenRegister, Registers &initializedRegisters);

protected:


    GeneratorAction getRandomGeneratorAction();

    // Instruction Creation Related
    std::unique_ptr<Instruction> createRandomAluInstruction();

    std::unique_ptr<Instruction> createRandomMovInstruction();

    std::unique_ptr<Instruction> createRandomLoadInstruction();

    std::unique_ptr<Instruction> createRandomLoadImm64Instruction();

    std::unique_ptr<Instruction> createRandomLoadPacketInstruction();

    std::unique_ptr<Instruction> createRandomStoreInstruction();

    std::unique_ptr<Instruction> createRandomCallInstruction();


    Variable createRandomVariable();

    // Basic Generation Function:
    static Variable createRandomImm32(int32_t maxImm);

    Variable createRandomTrivialDstRegister();

    Variable createRandomTrivialRegister();


    std::unique_ptr<Randomizer<GeneratorAction>> action_randomizer_;

    // Opcode Related
    std::unique_ptr<Randomizer<AluOpcode>> alu_opcode_randomizer_;
    std::unique_ptr<Randomizer<BranchOpcode>> branch_opcode_randomizer_;

//    std::unique_ptr<Randomizer<AluOpcode>> ptr_alu_opcode_randomizer_;

    // Variable Related
    std::unique_ptr<Randomizer<VariableType>> variable_randomizer_;

    // Register Related
    std::unique_ptr<Randomizer<Register>> trivial_reg_randomizer_;
    std::unique_ptr<Randomizer<Register>> trivial_dst_reg_randomizer_;
    std::unique_ptr<Randomizer<Register>> trivial_src_reg_randomizer_;

    // bit-width related
    std::unique_ptr<Randomizer<BitWidth>> trivial_bw_randomizer_;
    std::unique_ptr<Randomizer<BitWidth>> endian_bw_randomizer_;
    std::unique_ptr<Randomizer<BitWidth>> limited_bw_randomizer_;

    std::vector<WeightedType<VariableType>> weightedVariable_ = {
            {VariableType::Register, 20},
            {VariableType::Imm32,    20},
    };

    std::vector<WeightedType<Register>> weightedTrivialRegister_ = {
            {Register::REG_0, 20},
            {Register::REG_1, 20},
            {Register::REG_2, 20},
//        {Register::REG_3,  50},
            {Register::REG_4, 50},
//        {Register::REG_5,  50},
//        {Register::REG_6,  50},
//        {Register::REG_7,  20},
//        {Register::REG_8,  20},
//        {Register::REG_9,  20},
//        {Register::REG_10, 5},
    };

    std::vector<WeightedType<BranchOpcode>> weightedBranchOpcode_ = {
            {BranchOpcode::JA,   20},
            {BranchOpcode::JEQ,  20},
            {BranchOpcode::JGT,  20},
            {BranchOpcode::JGE,  20},
            {BranchOpcode::JNE,  20},
            {BranchOpcode::JLT,  20},
            {BranchOpcode::JLE,  20},
            {BranchOpcode::JSET, 20},
            {BranchOpcode::JSGT, 20},
            {BranchOpcode::JSGE, 20},
            {BranchOpcode::JSLT, 20},
            {BranchOpcode::JSLE, 20},
    };

    std::vector<WeightedType<Register>> weightedTrivialDstRegister_ = {
            {Register::REG_0, 200},
            {Register::REG_1, 200},
            {Register::REG_2, 200},
//        {Register::REG_3,  500},
//            {Register::REG_4,  500},
            {Register::REG_5, 500},
//        {Register::REG_6,  500},
//        {Register::REG_7, 200},
//        {Register::REG_8, 200},
//        {Register::REG_9,  200},
//        {Register::REG_10, 1}, // r10 shouldn't be written
    };

    std::vector<WeightedType<BitWidth>> weightedTrivialBitWidth_ = {
            {BitWidth::bit8,  20},
            {BitWidth::bit16, 20},
            {BitWidth::bit32, 20},
            {BitWidth::bit64, 20},
    };

    std::vector<WeightedType<BitWidth>> weightedEndianBitWidth_ = {
            {BitWidth::bit16, 20},
            {BitWidth::bit32, 20},
            {BitWidth::bit64, 20},
    };

    std::vector<WeightedType<BitWidth>> weightedLimitedBitWidth_ = {
            {BitWidth::bit32, 20},
            {BitWidth::bit64, 20},
    };


private:
    std::unique_ptr<Instruction> createAluInstruction(AluOpcode opcode);

    std::unique_ptr<Instruction>
    createDetailedAluInstruction(AluOpcode opcode, Register dstRegister, std::optional<Variable> candidateSrc,
                                 std::optional<BitWidth> candidateBitWidth);
};


#endif //BPF_IR_PROGRAMGENERATOR_H

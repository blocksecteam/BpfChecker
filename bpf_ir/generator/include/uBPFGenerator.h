#ifndef BPF_IR_UBPFGENERATOR_H
#define BPF_IR_UBPFGENERATOR_H

#include "ProgramGenerator.h"


class UBPFGenerator : public ProgramGenerator {
public:
    UBPFGenerator();
    ~UBPFGenerator() = default;

    TestCase generateProgram(size_t action_size) override;

private:
    std::vector<WeightedType<GeneratorAction>> weightedGeneratorAction_ = { // NOLINT(cert-err58-cpp)
            {GeneratorAction::CREATE_ALU,          20},
            {GeneratorAction::CREATE_MOV,          20},
            {GeneratorAction::CREATE_LOAD,         20},
            {GeneratorAction::CREATE_LOAD_IMM,     20},
            // { GeneratorAction::CREATE_LOAD_PACKET, 20 },
            {GeneratorAction::CREATE_STORE,        20},
            //  { GeneratorAction::CREATE_CALL, 20 },
            {GeneratorAction::SET_BLOCK_JMP,       30},
            {GeneratorAction::SET_BLOCK_EXIT,      20},
            {GeneratorAction::ADD_BLOCK,           30},
            {GeneratorAction::SWITCH_BLOCK_UP,     20},
            {GeneratorAction::SWITCH_BLOCK_DOWN,   20},
            {GeneratorAction::SWITCH_BLOCK_RANDOM, 20},
    };

    std::vector<WeightedType<AluOpcode>> weightedAluOpcode_ = {
            {AluOpcode::ADD,   20},
            {AluOpcode::SUB,   20},
            {AluOpcode::MUL,   20},
            {AluOpcode::DIV,   20},
            // {AluOpcode::SDIV,   20}, // sdiv is rbpf-only, skip for ubpf
            {AluOpcode::OR,    60},
            {AluOpcode::AND,   40},
            {AluOpcode::LSH,   50},
            {AluOpcode::ARSH,  50},
            {AluOpcode::RSH,   50},
            {AluOpcode::NEG,   20},
            {AluOpcode::MOD,   20},
            {AluOpcode::XOR,   50},
            {AluOpcode::TO_LE, 50},
            {AluOpcode::TO_BE, 50},
    };
};

#endif //BPF_IR_UBPFGENERATOR_H

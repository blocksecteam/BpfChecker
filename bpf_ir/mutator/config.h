
#ifndef BPF_IR_CONFIG_H
#define BPF_IR_CONFIG_H

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"

#include "Instruction.h"
#include <cstdint>
#include <cstddef>
#include <limits>
#include "common.h"
/// Configuration of all random weight:

const int MAX_SHIFT_BIT = 64;

std::vector<WeightedType<InstructionType>> weightedTrivialInst = {
        {InstructionType::AluInst,       50},
        {InstructionType::MovInst,       30},
        {InstructionType::LoadInst,      20},
        {InstructionType::LoadImm64Inst, 20},
//        {InstructionType::LoadMapInst,   5},
//        {InstructionType::StoreInst,     20},
//        {InstructionType::MemXAddInst,   20},
};

std::vector<WeightedType<Register>> weightedRegister = {
        {Register::REG_0,  20},
//        {Register::REG_1,  20},
//        {Register::REG_2,  20},
//        {Register::REG_3,  20},
        {Register::REG_4, 20},
//        {Register::REG_5, 20},
//        {Register::REG_6,  20},
//        {Register::REG_7,  20},
//        {Register::REG_8,  20},
//        {Register::REG_9,  20},
//        {Register::REG_10, 20},
};

std::vector<WeightedType<Register>> weightedTrivialDstRegister = {
        {Register::REG_0,  200},
//        {Register::REG_1, 200},
//        {Register::REG_2, 200},
//        {Register::REG_3,  500},
        {Register::REG_4,  500},
//        {Register::REG_5,  500},
//        {Register::REG_6,  500},
//        {Register::REG_7, 200},
//        {Register::REG_8, 200},
//        {Register::REG_9,  200},
//        {Register::REG_10, 1}, // r10 shouldn't be written
};

std::vector<WeightedType<Register>> weightedTrivialRegister = {
        {Register::REG_0,  20},
//        {Register::REG_1,  20},
//        {Register::REG_2,  20},
//        {Register::REG_3,  50},
        {Register::REG_4,  50},
//        {Register::REG_5,  50},
//        {Register::REG_6,  50},
//        {Register::REG_7,  20},
//        {Register::REG_8,  20},
//        {Register::REG_9,  20},
//        {Register::REG_10, 5},
};

std::vector<WeightedType<AluOpcode>> weightedPointerAluOpcode = {
        {AluOpcode::ADD, 20},
        {AluOpcode::SUB, 20},
};

std::vector<WeightedType<AluOpcode>> weightedAluOpcode = {
        {AluOpcode::ADD,   20},
        {AluOpcode::SUB,   20},
        {AluOpcode::MUL,   20},
        {AluOpcode::DIV,   20},
//        {AluOpcode::SDIV,   20}, // UBPF_ONLY
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

std::vector<WeightedType<BitWidth>> weightedEndianBitWidth = {
//        {BitWidth::bit8,  20},
        {BitWidth::bit16, 20},
        {BitWidth::bit32, 20},
        {BitWidth::bit64, 20},
};

std::vector<WeightedType<BitWidth>> weightedTrivialBitWidth = {
        {BitWidth::bit8,  20},
        {BitWidth::bit16, 20},
        {BitWidth::bit32, 20},
        {BitWidth::bit64, 20},
};

std::vector<WeightedType<BitWidth>> weightedBitWidth = {
        {BitWidth::bit32, 20},
        {BitWidth::bit64, 20},
};

std::vector<WeightedType<VariableType>> weightedVariable = {
        {VariableType::Register, 20},
        {VariableType::Imm32,    20},
};

std::vector<WeightedType<BranchOpcode>> weightedBranchOpcode = {
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


#define INTERESTING_8                                    \
  -128,    /* Overflow signed 8-bit when decremented  */ \
      -1,  /*                                         */ \
      0,   /*                                         */ \
      1,   /*                                         */ \
      16,  /* One-off with common buffer size         */ \
      32,  /* One-off with common buffer size         */ \
      64,  /* One-off with common buffer size         */ \
      100, /* One-off with common buffer size         */ \
      127                        /* Overflow signed 8-bit when incremented  */

//#define INTERESTING_8_LEN 9

#define INTERESTING_16                                    \
  -32768,   /* Overflow signed 16-bit when decremented */ \
      -129, /* Overflow signed 8-bit                   */ \
      128,  /* Overflow signed 8-bit                   */ \
      255,  /* Overflow unsig 8-bit when incremented   */ \
      256,  /* Overflow unsig 8-bit                    */ \
      512,  /* One-off with common buffer size         */ \
      1000, /* One-off with common buffer size         */ \
      1024, /* One-off with common buffer size         */ \
      4096, /* One-off with common buffer size         */ \
      32767                      /* Overflow signed 16-bit when incremented */

//#define INTERESTING_16_LEN 10

#define INTERESTING_32                                          \
  -2147483648LL,  /* Overflow signed 32-bit when decremented */ \
      -100663046, /* Large negative number (endian-agnostic) */ \
      -32769,     /* Overflow signed 16-bit                  */ \
      32768,      /* Overflow signed 16-bit                  */ \
      65535,      /* Overflow unsig 16-bit when incremented  */ \
      65536,      /* Overflow unsig 16 bit                   */ \
      100663045,  /* Large positive number (endian-agnostic) */ \
      2147483647                 /* Overflow signed 32-bit when incremented */

//#define INTERESTING_32_LEN 8

int8_t interesting_8[] = {INTERESTING_8};
int16_t interesting_16[] = {INTERESTING_8, INTERESTING_16};

int16_t interesting_offset[] = {-2, -1, 0, 1, 2, 3, 4, 8, 16, 32, 64, 127, 128,};

int32_t interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};
int64_t interesting_64[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32,
                            INT64_MAX,
                            INT64_MAX >> 1,
                            INT64_MAX - 1,
                            INT64_MIN,
                            INT64_MIN + 1,
                            INT64_MIN >> 1,
                            25769803777,
                            INT32_MAX + 1L,
                            INT32_MAX + 2L,
                            UINT32_MAX + 1L,
                            UINT32_MAX + 2L,
                            0x100000000, // rbpf memory address related
                            0x10000000 - 1,
                            0x10000000 + 1,
                            0x200000000 - 1,
                            0x200000000 + 1,
                            0x300000000 - 1,
                            0x300000000 + 1,
                            0x400000000 - 1,
                            0x400000000 + 1,
                            0x500000000,
};
constexpr size_t interesting_8_length = sizeof(interesting_8) / sizeof(int8_t);
constexpr size_t interesting_16_length = sizeof(interesting_16) / sizeof(int16_t);
constexpr size_t interesting_offset_length = sizeof(interesting_offset) / sizeof(int16_t);
constexpr size_t interesting_32_length = sizeof(interesting_32) / sizeof(int32_t);
constexpr size_t interesting_64_length = sizeof(interesting_64) / sizeof(int64_t);
static_assert(sizeof interesting_32 == (9 + 10 + 8) * 4, "");

#pragma clang diagnostic pop


#endif //BPF_IR_CONFIG_H


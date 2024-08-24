#include <sstream>
#include "MemGenerator.h"

const size_t MM_PROGRAM_START64 = 0x100000000;
/// Start of the stack in the memory map
const size_t MM_STACK_START = 0x200000000;
/// Start of the heap in the memory map
const size_t MM_HEAP_START = 0x300000000;
/// Start of the input buffers in the memory map
const size_t MM_INPUT_START = 0x400000000;

TestCase generate_random_mem_load() {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();

    // Randomly choose a register for the base address
    auto base_reg = getRandomRegister();
    // We aim at keeping memory access as valid as possible. 
    // We exercise the edge case of the memory access in another random program generation
    bb->add(std::make_unique<LoadImm64Inst>(base_reg, MM_INPUT_START));

    // Randomly choose a destination register
    auto dest_reg = getRandomRegister();

    // Randomly choose the type of load instruction
    int load_type = rand() % 3;

    switch (load_type) {
        case 0: {
            // Regular LoadInst
            int offset = rand() % 256;  // Random offset
            BitWidth width = static_cast<BitWidth>(rand() % 4);  // Random bit width
            bb->add(std::make_unique<LoadInst>(dest_reg, base_reg, offset, width));
            break;
        }
        case 1: {
            // LoadMapInst
            bool is_double = rand() % 2 == 0;  // Randomly decide if it's a double map
            bb->add(std::make_unique<LoadMapInst>(0, dest_reg, defaultReservedRegisters.getMapFdRegister(), is_double));
            break;
        }
        case 2: {
            // LoadImm64Inst
            int64_t imm_value = rand();  // Random immediate value
            bb->add(std::make_unique<LoadImm64Inst>(dest_reg, imm_value));
            break;
        }
    }

    // Move the result to R0
    bb->add(std::make_unique<MovInst>(Register::REG_0, dest_reg, BitWidth::bit64));

    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

TestCase generate_mem_write() {
    Module module(defaultReservedRegisters, 3, false);
    BasicBlockPtr bb = createBasicBlock();
    auto anchor = Register::REG_2;
    bb->add(std::make_unique<LoadImm64Inst>(anchor, MM_INPUT_START + 2));
    bb->add(std::make_unique<LoadInst>(Register::REG_1, anchor, 1, BitWidth::bit8));
    bb->add(std::make_unique<StoreInst>(anchor, 0xee, 0, BitWidth::bit8));
    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

std::vector<TestCase> generate_random_mem_programs(int num_operations = 5) {
    std::vector<TestCase> test_cases;
    
    for (int i = 0; i < num_operations; ++i) {
        Module module(defaultReservedRegisters, 3, false);
        BasicBlockPtr bb = createBasicBlock();
        
        Register base_reg = static_cast<Register>(rand() % 10 + 1);
        bb->add(std::make_unique<LoadImm64Inst>(base_reg, MM_INPUT_START + rand() % 1024));
        
        for (int j = 0; j < rand() % 5 + 1; ++j) {
            bool is_load = rand() % 2 == 0;
            Register op_reg = static_cast<Register>(rand() % 10 + 1);
            int offset = rand() % 256;
            BitWidth width = static_cast<BitWidth>(rand() % 4);
            
            if (is_load) {
                bb->add(std::make_unique<LoadInst>(op_reg, base_reg, offset, width));
            } else {
                int64_t value = rand();
                bb->add(std::make_unique<StoreInst>(base_reg, value, offset, width));
            }
        }
        
        // Move the last operation result to R0 (if it was a load)
        bb->add(std::make_unique<MovInst>(Register::REG_0, static_cast<Register>(rand() % 10 + 1), BitWidth::bit64));
        
        bb->setExitTerminator();
        BytecodeData bytecode = bb->CodeGen();
        std::stringstream stream;
        stream << *bb;
        test_cases.push_back({bytecode, stream.str()});
    }
    
    return test_cases;
}

TestCase generate_random_mem_write_program() {
    Module module(defaultReservedRegisters, 3, false);
    BasicBlockPtr bb = createBasicBlock();
    
    Register base_reg = static_cast<Register>(rand() % 10 + 1);
    bb->add(std::make_unique<LoadImm64Inst>(base_reg, MM_INPUT_START + rand() % 1024));
    
    int num_operations = rand() % 10 + 1;  
    for (int i = 0; i < num_operations; ++i) {
        Register value_reg = static_cast<Register>(rand() % 10 + 1);  // R1 to R10
        int offset = rand() % 256;
        BitWidth width = static_cast<BitWidth>(rand() % 4);
        
        int64_t value = rand();
        bb->add(std::make_unique<LoadImm64Inst>(value_reg, value));
        
        bb->add(std::make_unique<StoreInst>(base_reg, value_reg, offset, width));
    }
    
    bb->setExitTerminator();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}

TestCase generate_mem_program_example() {
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    bb->add(std::make_unique<LoadImm64Inst>(Register::REG_6, 9223372036854775806));
    bb->add(std::make_unique<LoadInst>(Register::REG_3, Register::REG_6, 4, BitWidth::bit32));
    bb->setExitTerminator();
    int size = bb->getInstructions().size();
    BytecodeData bytecode = bb->CodeGen();
    std::stringstream stream;
    stream << *bb;
    return {bytecode, stream.str()};
}
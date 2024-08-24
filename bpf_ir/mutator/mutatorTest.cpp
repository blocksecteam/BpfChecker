#include "ir.h"
#include "Module.h"
#include "mutator.h"
#include "Template.h"
#include "Lifter.h"

#include "../fuzzer/fuzzerConfig.h"
#include <iostream>
#include <fstream>

static std::string banner = "=====================\n";

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

#define COMPLETE

int main() {
    // generate template

    // header:
    //  Load maps
    //  Load two random registers from maps (corresponding to the offset 0, 8)
    //  Generate minimum/maximum bound for these registers,
    //      The bounds is a random number is in -MAP_SIZE ~ MAP_SIZE. The size could be MAP_SIZE.

    // body:
    //  some ALU instructions to these registers
    //  TODO : branch instruction. The source comes from the previous registers or the immediate

    // footer:
    //  ALU pointer instruction to map_ptr_reg and one of the previous registers (The calc result is map_ptr_reg)
    //  Memory access in terms of map_ptr_reg
    //  set reg0 to 1
    //  exit

#ifdef COMPLETE
    // header
    Module module(defaultReservedRegisters, 3);
    BasicBlockPtr bb = createBasicBlock();
    bb->add(std::make_unique<LoadMapInst>(0, defaultReservedRegisters.getMapPtrRegister(),
                                          defaultReservedRegisters.getMapFdRegister(), true));
    bb->add(std::make_unique<LoadInst>(Register::REG_5,
                                       defaultReservedRegisters.getMapPtrRegister(), 0, BitWidth::bit64));
    bb->add(std::make_unique<LoadInst>(Register::REG_4,
                                       defaultReservedRegisters.getMapPtrRegister(), 8, BitWidth::bit64));

//    bb->add(std::make_unique<MovInst>(Register::REG_0,99, BitWidth::bit64));
    bb->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit64));

    // place holder for 64bit compare
    bb->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));

    bb->setExitTerminator();
    auto ifStmt = createIfStmt(std::move(bb), BranchOpcode::JSLE, Register::REG_4, 0x40, BitWidth::bit64);
    module.addBasicBlock(std::move(ifStmt.condBlock));
    ifStmt.nextBlock->add(std::make_unique<MovInst>(Register::REG_0, FAIL_FIRST_REG_OVER_UPPER_BOUND, BitWidth::bit64));
    module.addBasicBlock(std::move(ifStmt.nextBlock));

    // place holder for 64bit compare
    ifStmt.offsetBlock->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));
    auto secondIfStmt = createIfStmt(std::move(ifStmt.offsetBlock), BranchOpcode::JSLE, Register::REG_5, 0x40,
                                     BitWidth::bit64);
    module.addBasicBlock(std::move(secondIfStmt.condBlock));
    secondIfStmt.nextBlock->add(
            std::make_unique<MovInst>(Register::REG_0, FAIL_SECOND_REG_OVER_UPPER_BOUND, BitWidth::bit64));
    module.addBasicBlock(std::move(secondIfStmt.nextBlock));

    // place holder for 64bit compare
    secondIfStmt.offsetBlock->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));
    auto minBoundFirstIfStmt = createIfStmt(std::move(secondIfStmt.offsetBlock), BranchOpcode::JSGE, Register::REG_4,
                                            0x8,
                                            BitWidth::bit64);
    module.addBasicBlock(std::move(minBoundFirstIfStmt.condBlock));
    minBoundFirstIfStmt.nextBlock->add(
            std::make_unique<MovInst>(Register::REG_0, FAIL_FIRST_REG_UNDER_MIN_BOUND, BitWidth::bit64));
    module.addBasicBlock(std::move(minBoundFirstIfStmt.nextBlock));

    // place holder for 64bit compare
    minBoundFirstIfStmt.offsetBlock->add(std::make_unique<LoadImm64Inst>(defaultReservedRegisters.getBoundRegister(), 0));
    auto minBoundSecondIfStmt = createIfStmt(std::move(minBoundFirstIfStmt.offsetBlock), BranchOpcode::JSGE,
                                             Register::REG_5, 0x8,
                                             BitWidth::bit64);
    module.addBasicBlock(std::move(minBoundSecondIfStmt.condBlock));
    minBoundSecondIfStmt.nextBlock->add(
            std::make_unique<MovInst>(Register::REG_0, FAIL_SECOND_REG_UNDER_MIN_BOUND, BitWidth::bit64));
    module.addBasicBlock(std::move(minBoundSecondIfStmt.nextBlock));

    auto mapPointerMinBoundIfStmt = createIfStmt(std::move(minBoundSecondIfStmt.offsetBlock), BranchOpcode::JSGE,
                                                 defaultReservedRegisters.getMapPtrRegister(), 0x8,
                                                 BitWidth::bit64);
    module.addBasicBlock(std::move(mapPointerMinBoundIfStmt.condBlock));
    module.addBasicBlock(std::move(mapPointerMinBoundIfStmt.nextBlock));


//    auto mapPointerMaxBoundIfStmt = createIfStmt(std::move(mapPointerMinBoundIfStmt.offsetBlock), BranchOpcode::JLE, defaultReservedRegisters.getMapPtrRegister(),0xFFF0,
//                                                 BitWidth::bit64);
//    module.addBasicBlock(std::move(mapPointerMaxBoundIfStmt.condBlock));
//    module.addBasicBlock(std::move(mapPointerMaxBoundIfStmt.nextBlock));

    // body:
    auto &&target = mapPointerMinBoundIfStmt.offsetBlock;
    auto opcode = createRandomAluOpcode();
    target->add(std::make_unique<AluInst>(opcode, Register::REG_4, Register::REG_5, createRandomBitWidth()));

    // change bound bit width
    target->add(std::make_unique<MovInst>( Register::REG_6, Register::REG_4, BitWidth::bit32));
    target->add(std::make_unique<AluInst>(opcode, Register::REG_6, Register::REG_5, createRandomBitWidth()));
    // target->add(std::make_unique<AluInst>(opcode, Register::REG_6, Register::REG_5, createRandomBitWidth()));

    // footer:
    opcode = createRandomPointerAluOpcode();
    target->add(std::make_unique<AluInst>(opcode, defaultReservedRegisters.getMapPtrRegister(), Register::REG_6,
                                          BitWidth::bit64));

//    target->add(std::make_unique<AluInst>(AluOpcode::MOD, defaultReservedRegisters.getMapPtrRegister(), Register::REG_5,
//                                          BitWidth::bit64));
//    target->add(std::make_unique<LoadInst>(Register::REG_4, defaultReservedRegisters.getMapPtrRegister(), 0,
//                                           BitWidth::bit64));
    target->add(std::make_unique<StoreInst>(defaultReservedRegisters.getMapPtrRegister(), 6, 0x10,
                                            BitWidth::bit8));

    target->add(std::make_unique<MovInst>(Register::REG_0, FINISH_RUN, BitWidth::bit64));
    target->setExitTerminator();
    module.addBasicBlock(std::move(target));

#else
   Module module(defaultReservedRegisters, 3);
   BasicBlockPtr bb = createBasicBlock();
   bb->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 6));
   bb->setExitTerminator();
   module.addBasicBlock(std::move(bb));
#endif

    auto result = module.CodeGen();
    print_instructions(result);
    std::ofstream outfile("simple-bytecode.bin", std::ios::out);
    outfile.write(reinterpret_cast<const char *>(result.data()), result.size() * sizeof(result[0]));
    outfile.close();

    std::cout << banner;
    std::cout << module;
    std::cout << banner;


    std::unique_ptr<Module> liftedModule = Lift(reinterpret_cast<unsigned char *>(result.data()), result.size() * sizeof(result[0]));


//    auto inserter = new InstInjectorStrategy();
//    inserter->mutate(module);
//    std::cout << banner;
//    std::cout << module;
//    std::cout << banner;
    return 0;
}
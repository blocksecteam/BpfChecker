#include "Instruction.h"
#include "BasicBlock.h"
#include "Module.h"
#include <iostream>
#include "Template.h"

#include "Lifter.h"

#include "ProgramTest.h"

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

bool isSameCodeGen(BytecodeData &first, BytecodeData &second) {
    if (first.size() != second.size())return false;
    for (int i = 0; i < first.size(); ++i) {
        if (!(first[i] == second[i]))return false;
    }
    return true;
}

int main() {
    Module module(defaultReservedRegisters, 3);
//    AluInst alu(AluOpcode::ADD, Variable(Register::REG_0), Variable(Register::REG_1), BitWidth::bit64);
//    bpf_insn result = alu.CodeGen();
//    int base_address = 0;
////    printInstruction(base_address, &result);
//
//    cout << "dump:" << endl;
//    printf("unsigned char data[]={");
//    print_instruction(MovInst(666, Register::REG_6, BitWidth::bit64).CodeGen());
//    print_instruction(MovInst(Register::REG_1, Register::REG_6, BitWidth::bit64).CodeGen());
//    print_instruction(MovInst(Register::REG_6, 233, BitWidth::bit64).CodeGen());
////    print_instruction(result);
//    print_instruction(ExitInst().CodeGen());
//    BasicBlockPtr bb = std::make_unique<BasicBlock>();
    BasicBlockPtr bb = createBasicBlock();
//    bb.Add(std::move(new MovInst(Register::REG_6, 233, BitWidth::bit64)));
//    bb.Add(MovInst(Register::REG_6, 666, BitWidth::bit64));
    bb->add(std::make_unique<MovInst>(Register::REG_3, 666, BitWidth::bit64));
    bb->add(std::make_unique<MovInst>(Register::REG_0, 66, BitWidth::bit64));
    bb = createLoadMapValueInst(std::move(bb), 0, Register::REG_4, false, &module);

//    bb->add(std::make_unique<LoadInst>(Register::REG_6, 666, BitWidth::bit64));
//    auto result_bb = bb->CodeGen();
//    print_instructions(result_bb);

//    bb->setExitTerminator();
//    module.addBasicBlock(std::move(bb));


    IfStmt ifStmt = createIfStmt(std::move(bb), BranchOpcode::JGE, Register::REG_0, Register::REG_4, BitWidth::bit64);

    ifStmt.nextBlock->add(std::make_unique<MovInst>(Register::REG_5, 77, BitWidth::bit64));
//    cout << ifStmt.condBlock->getBytecodeSize() << endl;
//    cout << ifStmt.nextBlock->getBytecodeSize() << endl;
//    cout << ifStmt.offsetBlock->getBytecodeSize() << endl;
    ifStmt.offsetBlock->add(std::make_unique<MovInst>(Register::REG_0, 1, BitWidth::bit64));
    ifStmt.offsetBlock->add(std::make_unique<MovInst>(Register::REG_6, 7, BitWidth::bit32));
    ifStmt.offsetBlock->add(std::make_unique<LoadInst>(Register::REG_6, Register::REG_4, 7, BitWidth::bit32));
    ifStmt.offsetBlock->add(std::make_unique<LoadImm64Inst>(Register::REG_6, 6));
    ifStmt.offsetBlock->add(
            std::make_unique<AluInst>(AluOpcode::OR, Register::REG_4, Register::REG_6, BitWidth::bit64));
    ifStmt.offsetBlock->add(std::make_unique<StoreInst>(Register::REG_4, Register::REG_6, 4, BitWidth::bit64));
    IfStmt secondIfStmt = createIfStmt(std::move(ifStmt.offsetBlock), BranchOpcode::JGE, Register::REG_4,
                                       Register::REG_6, BitWidth::bit64);

    module.addBasicBlock(std::move(ifStmt.condBlock));
    module.addBasicBlock(std::move(ifStmt.nextBlock));
//    module.addBasicBlock(std::move(ifStmt.offsetBlock));
    module.addBasicBlock(std::move(secondIfStmt.condBlock));
    module.addBasicBlock(std::move(secondIfStmt.nextBlock));
    module.addBasicBlock(std::move(secondIfStmt.offsetBlock));

    auto result = module.CodeGen();
    print_instructions(result);
    auto bytecodeData = reinterpret_cast<unsigned char *>(result.data());
    auto bytecodeSize = result.size() * sizeof(bpf_insn);

    auto liftedModule = Lift(bytecodeData, bytecodeSize);
    liftedModule->updateMapFd(3);
    auto liftedResult = liftedModule->CodeGen();
    print_instructions(liftedResult);

    assert(isSameCodeGen(result, liftedResult));
}
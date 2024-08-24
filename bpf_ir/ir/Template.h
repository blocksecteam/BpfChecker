#ifndef BPF_IR_TEMPLATE_H
#define BPF_IR_TEMPLATE_H

#include "ir.h"
#include "Instruction.h"
#include "BasicBlock.h"
#include "Module.h"

//struct IfStmt {
//    BasicBlock *condBlock;
//    BasicBlock *nextBlock;
//    BasicBlock *offsetBlock;
//};
struct IfStmt {
    BasicBlockPtr condBlock;
    BasicBlockPtr nextBlock;
    BasicBlockPtr offsetBlock;
};

// The Template is deprecated since we generate style and fixer -oriented programs, which can cover the current template program

void createIfStmt(BasicBlock *conditionBlock, BasicBlock *nextBlock, BasicBlock *offsetBlock, BranchOpcode opcode,
                  Variable dst, Variable src, BitWidth width) {
    assert(width == BitWidth::bit32 || width == BitWidth::bit64);
    conditionBlock->setBranchTerminator(opcode, dst, src, nextBlock, offsetBlock, width);
    nextBlock->setExitTerminator();
    offsetBlock->setExitTerminator();
}

IfStmt createIfStmt(BasicBlockPtr conditionBlock, BranchOpcode opcode, Variable dst, Variable src, BitWidth width) {
//    auto judge = createBasicBlock();
    auto nextBlock = createBasicBlock();
    auto offsetBlock = createBasicBlock();
    createIfStmt(conditionBlock.get(), nextBlock.get(), offsetBlock.get(), opcode, dst, src, width);
    nextBlock->setExitTerminator();
    offsetBlock->setExitTerminator();
//    return {conditionBlock, std::move(nextBlock.get()), std::move(offsetBlock.get())};
    return {std::move(conditionBlock), std::move(nextBlock), std::move(offsetBlock)};
//    judge->setBranchTerminator(opcode, dst, src, nextBlock.release(), offsetBlock.release(), width);

//    return {std::move(judge), std::move(nextBlock), std::move(offsetBlock)};
}


BasicBlockPtr
createLoadMapValueInst(BasicBlockPtr block, bpf_offset_type offset, Register dst, bool loadAddress,
                       Module *module = nullptr) {
//    assert((block->getModule() || module) && "No valid module is found.");
    Module *targetModule = nullptr;
    if (block->getModule() && !module) {
        targetModule = block->getModule();
    } else if (module) {
        targetModule = module;
    }
    assert(targetModule && "No valid module is found.");
    auto map_fd_reg = targetModule->getReservedRegisters().getMapFdRegister();
    block->add(std::make_unique<LoadMapInst>(offset, Variable(dst), Variable(map_fd_reg), loadAddress));
    return std::move(block);
}

#endif //BPF_IR_TEMPLATE_H

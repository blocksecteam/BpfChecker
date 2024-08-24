#include "BasicBlock.h"
#include "Instruction.h"

BasicBlock::BasicBlock() = default;

BasicBlockPtr createBasicBlock() {
    return std::make_unique<BasicBlock>();
}

void BasicBlock::add(InstPtr &&inst) {
//        assert(inst->instType != InstructionType::BranchInst && inst->instType != InstructionType::ExitInst &&
//               "Control flow instruction should be set with terminator");
    inst->setBasicBlock(this);
    _instructions.push_back(std::move(inst));
//        this->calibrated = false;
}

void BasicBlock::insert(int position, InstPtr &&inst) {
    if (this->_instructions.empty()) {
        this->add(std::move(inst));
        return;
    }
    assert(position < this->_instructions.size());
    auto iter = std::next(_instructions.cbegin(), position);
    assert(inst->instType != InstructionType::BranchInst && inst->instType != InstructionType::ExitInst &&
           "Control flow instruction should be set with terminator");
    inst->setBasicBlock(this);
    _instructions.insert(iter, std::move(inst));
//        this->calibrated = false;
}

void BasicBlock::remove(int position) {
    if (this->_instructions.empty())
        return;
    assert(position < this->_instructions.size());
    auto iter = std::next(_instructions.cbegin(), position);
    this->_instructions.erase(iter);
}

void BasicBlock::setExitTerminator() {
    if (this->terminator) {
        this->terminator.release();
        this->terminator = nullptr;
    }
    this->successor = nullptr;
    this->target = nullptr;
    this->terminator = std::make_unique<ExitInst>();
    this->calibrated = true; // exit doesn't need calibration.
//        if (this->successor) {
//            this->successor->setPredecessor(nullptr);
//        }
}

void BasicBlock::setBranchTerminator(BranchOpcode opcode, Variable dst, Variable src, BasicBlock *next,
                                     BasicBlock *targetBlock, BitWidth width) {
    if (this->terminator) {
        this->terminator.release();
        this->terminator = nullptr;
    }
    this->terminator = std::make_unique<BranchInst>(opcode, dst, src, DUMMY_OFFSET, width);

    this->successor = next;
    this->target = targetBlock;
    this->calibrated = false;
}



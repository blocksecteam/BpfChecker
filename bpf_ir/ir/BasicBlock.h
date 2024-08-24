#ifndef BPF_IR_BASICBLOCK_H
#define BPF_IR_BASICBLOCK_H

#include <vector>
#include "ir.h"
#include "Instruction.h"

const size_t INVALID_ADDRESS = -1;

class BasicBlock {
public:
    BasicBlock();

    void add(InstPtr &&inst);

    void insert(int position, InstPtr &&inst);

    void remove(int position);

    Insts &getInstructions() {
        return this->_instructions;
    }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-unused-return-value"

    void setExitTerminator();

    void
    setBranchTerminator(BranchOpcode opcode, Variable dst, Variable src, BasicBlock *next, BasicBlock *targetBlock,
                        BitWidth width);

#pragma clang diagnostic pop

    Instruction *getTerminator() {
        return this->terminator.get();
    }

    bool isExitTerminator() {
        return this->terminator && this->terminator->instType == InstructionType::ExitInst;
    }

    bool isBranchTerminator() {
        return this->terminator && this->terminator->instType == InstructionType::BranchInst;
    }

    bool hasTerminator() {
        return this->isExitTerminator() || this->isBranchTerminator();
    }

    [[nodiscard]] bool hasSuccessor() const {
        return successor != nullptr;
    }

    void setPredecessor(BasicBlock *pred) {
        this->predecessor = pred;
    }

    [[nodiscard]] const BasicBlock *getSuccessor() const {
        return successor;
    }

    void setSuccessor(BasicBlock *s) {
        this->successor = s;
    }

    void setAddress(size_t thisAddress) {
        this->address = thisAddress;
    }

    void setTargetAddress(size_t targetAddr) {
        this->targetAddress = targetAddr;
        this->calibrated = true;
    }

    [[nodiscard]] BytecodeData &CodeGen() {
        assert(this->calibrated && "Lack of calibration in code generation.");
        assert(this->hasTerminator() && "Terminator is needed in code generation.");
        data.clear();
//        manager = new BytecodeManager(this->_instructions.size());
        for (const auto &inst:this->_instructions) {
            auto gen = inst->CodeGen();
            data.insert(std::end(data), std::begin(gen), std::end(gen));
//            data.push_back(gen);
        }

        // terminator related:
        // need calibrate first if the terminator is branch instruction.
        // we rely on the module to update the correct offset of the basic block!

        if (this->isBranchTerminator()) {
            assert(this->isBranchTerminator());
            assert(this->targetAddress != INVALID_ADDRESS && this->address != INVALID_ADDRESS &&
                   "address is not updated.");
            Instruction *branchTerminator = this->terminator.get();
            bpf_offset_type off = this->targetAddress - (this->address + this->getBytecodeSize());
            static_cast<BranchInst *>(branchTerminator)->updateOffset(off);
        }
        auto gen = terminator->CodeGen();
        data.insert(std::end(data), std::begin(gen), std::end(gen));
        return data;
    }

    // use sizeof bpf_insn as a unit of measure
    size_t getBytecodeSize() {
        assert(this->hasTerminator() && "Invalid calculation of bytecode size without terminator");
        size_t size = 0;
        // TODO: cache the size when operate on the instructions
        for (auto &inst:this->_instructions) {
            size += inst->getBytecodeSize();
        }
        size += this->terminator->getBytecodeSize();
        return size;
    }

    size_t getBytecodeSizeWithoutTerm() {
        size_t size = 0;
        // TODO: cache the size when operate on the instructions
        for (auto &inst:this->_instructions) {
            size += inst->getBytecodeSize();
        }
        return size;
    }

//    size_t instNum() {
//        return this->_instructions.size();
//    }

    [[nodiscard]] bool empty() const {
        return this->_instructions.empty();
    }

    bool isValid() {
        return !this->empty() &&
               (this->_instructions.back()->instType == InstructionType::ExitInst ||
                this->_instructions.back()->instType == InstructionType::BranchInst);
    }

    [[nodiscard]] Module *getModule() const {
        return module;
    }

    void setModule(Module *m) {
        BasicBlock::module = m;
    }

    void setOffsetBlock(BasicBlock *offsetBlock) {
        BasicBlock::offsetBasicBlock = offsetBlock;
    }

    void setNextBlock(BasicBlock *nextBlock) {
        BasicBlock::nextBasicBlock = nextBlock;
    }

    [[nodiscard]] BasicBlock *getOffsetBasicBlock() const {
        return offsetBasicBlock;
    }

    [[nodiscard]] BasicBlock *getNextBasicBlock() const {
        return nextBasicBlock;
    }

    [[nodiscard]] size_t getAddress() const {
        assert(this->address != INVALID_ADDRESS && "address is not inited.");
        return address;
    }


    BasicBlock *getTarget() const {
        return target;
    }

    friend std::ostream &operator<<(std::ostream &stream, const BasicBlock &bb) {
        for (auto &&inst:bb._instructions) {
            stream << "\t" << *inst << "\n";
        }
        if (bb.terminator) {
            stream << "\t" << *bb.terminator << "\n";
        }
        return stream;
    }

private:
    BasicBlock *successor = nullptr;
    BasicBlock *target = nullptr;
    size_t targetAddress = INVALID_ADDRESS;
    // TODO : predecessors
    BasicBlock *predecessor = nullptr;
    Insts _instructions;

    InstPtr terminator = nullptr;
    BytecodeData data;
    Module *module = nullptr;
    BasicBlock *offsetBasicBlock = nullptr;
    BasicBlock *nextBasicBlock = nullptr;
    size_t address = INVALID_ADDRESS;
    bool calibrated = false;


};


// Utils for facilitating generation

BasicBlockPtr createBasicBlock();

#endif //BPF_IR_BASICBLOCK_H

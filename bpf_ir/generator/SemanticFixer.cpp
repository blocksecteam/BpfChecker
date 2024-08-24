#include "SemanticFixer.h"
#include "BasicBlock.h"
#include "Instruction.h"
#include <set>
#include "ProgramGenerator.h"

using namespace std;

// Aggresive optimization
void SemanticFixer::fixUninitializedMemory(ProgramGenerator *program_generator) {
    std::set<Variable> initialized_memory;
    for (auto &bb : bbs_) {
        std::set<Variable> uninitialized_memory;
        for (auto &&inst : bb->getInstructions()) {
            if (inst->instType == InstructionType::LoadInst) {
                auto load_inst = dynamic_cast<LoadInst*>(inst.get());
                if (!initialized_memory.count(load_inst->getSrc())) {
                    uninitialized_memory.insert(load_inst->getSrc());
                }
            } else if (inst->instType == InstructionType::StoreInst) {
                auto store_inst = dynamic_cast<StoreInst*>(inst.get());
                initialized_memory.insert(store_inst->getDst());
            }
        }
        
        for (auto &mem : uninitialized_memory) {
            std::unique_ptr<Instruction> init_inst;
            if (program_generator) {
                init_inst = program_generator->generateMemoryInitInstruction(mem);
            } else {
                init_inst = std::make_unique<StoreInst>(mem, Variable(0), BitWidth::bit32);
            }
            bb->insert(0, std::move(init_inst));
        }
    }
}

// Aggresive optimization
void SemanticFixer::fixUnusedRegisters(ProgramGenerator *program_generator) {
    std::set<Register> used_registers;
    for (auto &bb : bbs_) {
        for (auto &&inst : bb->getInstructions()) {
            auto read_regs = getInstReadReg(inst.get());
            used_registers.insert(read_regs.begin(), read_regs.end());
            if (auto written_reg = getInstWriteDstReg(inst.get()); written_reg.has_value()) {
                used_registers.insert(written_reg.value());
            }
        }
    }
    
    std::vector<Register> unused_registers;
    for (int i = 0; i < 11; ++i) {  // Assuming 11 registers (R0-R10)
        Register reg = static_cast<Register>(i);
        if (!used_registers.count(reg)) {
            unused_registers.push_back(reg);
        }
    }
    
    if (!unused_registers.empty() && program_generator) {
        auto last_bb = bbs_.back().get();
        for (auto reg : unused_registers) {
            auto use_inst = program_generator->generateRegisterUseInstruction(reg);
            last_bb->insert(last_bb->getInstructions().size() - 1, std::move(use_inst));
        }
    }
}


// Aggresive optimization
void SemanticFixer::fixDeadCode(ProgramGenerator *program_generator) {
    std::set<BasicBlock*> reachable_blocks;
    std::vector<BasicBlock*> worklist = {bbs_[0].get()};
    
    while (!worklist.empty()) {
        BasicBlock* bb = worklist.back();
        worklist.pop_back();
        
        if (reachable_blocks.insert(bb).second) {
            auto terminator = bb->getTerminator();
            if (terminator->instType == InstructionType::BranchInst) {
                auto branch = dynamic_cast<BranchInst*>(terminator);
                worklist.push_back(branch->getTrueTarget());
                if (branch->getFalseTarget()) {
                    worklist.push_back(branch->getFalseTarget());
                }
            }
        }
    }
    
    for (auto it = bbs_.begin(); it != bbs_.end(); ) {
        if (reachable_blocks.count(it->get()) == 0) {
            it = bbs_.erase(it);
        } else {
            ++it;
        }
    }
}

void SemanticFixer::fixUninitializedRegister(ProgramGenerator *program_generator) {
    // last stage since we assume all instructions are grammar-valid
    // track uninitialized register usage here.
    set<Register> initialized_registers;
    for (auto &bb: bbs_) {
        set<Register> uninitialized_registers;
        auto catch_register_usage = [&initialized_registers, &uninitialized_registers, this](
                Instruction *inst) {
            auto read_regs = this->getInstReadReg(inst);
            for (const auto &reg: read_regs) {
                if (!initialized_registers.count(reg)) {
                    // found uninitialized register
                    uninitialized_registers.insert(reg);
                }
            }
            if (auto written_reg = getInstWriteDstReg(inst); written_reg.has_value()) {
                initialized_registers.insert(written_reg.value());
            }
        };
        for (auto &&inst: bb->getInstructions()) {
            catch_register_usage(inst.get());
        }
        catch_register_usage(bb->getTerminator());

        vector<Register> initialized_registers_vector(initialized_registers.size());
        std::copy(initialized_registers.begin(), initialized_registers.end(),
                  initialized_registers_vector.begin());
        for (auto used_reg: uninitialized_registers) {
            unique_ptr<Instruction> next_inst;
            if (program_generator) {
                // this may not complete correct, since there may exist dead blocks
                next_inst = program_generator->generateWriteUsageInstruction(used_reg, initialized_registers_vector);
            } else {
                // rollback to default one.
                next_inst = std::make_unique<MovInst>(used_reg, 0, BitWidth::bit32);
            }
            bb->insert(0, std::move(next_inst));
        }
    }
    // we prefer second fix to achieve better performance.
    if (program_generator) {
        fixUninitializedRegister(nullptr);
    }
}

void SemanticFixer::fixUninitializedRegisterAggressively(ProgramGenerator *program_generator, bool is_aggressive) {
    set<Register> used_registers;
    for (auto &bb: bbs_) {
        auto catch_register_usage = [&used_registers](
                Instruction *inst) {
            if (auto read_regs = SemanticFixer::getInstWriteDstReg(inst); read_regs.has_value()) {
                used_registers.insert(read_regs.value());
            }
        };
        for (auto &&inst: bb->getInstructions()) {
            catch_register_usage(inst.get());
        }
        catch_register_usage(bb->getTerminator());

    }
//    for (auto used_reg: used_registers) {
//        unique_ptr<Instruction> next_inst;
//        if (program_generator) {
//            // this may not complete correct, since there may exist dead blocks
//            next_inst = program_generator->generateWriteUsageInstruction(used_reg, initialized_registers_vector);
//        } else {
//            // rollback to default one.
//            next_inst = std::make_unique<MovInst>(used_reg, 0, BitWidth::bit32);
//        }
//        bb->insert(0, std::move(next_inst));
//    }
}

optional<Register> SemanticFixer::getInstWriteDstReg(Instruction *inst) {
    switch (inst->instType) {
        case InstructionType::AluInst: {
            auto cur_inst = dynamic_cast<AluInst *>(inst);
            assert(cur_inst->getDst().isRegister());
            return {cur_inst->getDst().getReg()};
        }
        case InstructionType::MovInst: {
            auto cur_inst = dynamic_cast<MovInst *>(inst);
            assert(cur_inst->getDst().isRegister());
            return {cur_inst->getDst().getReg()};
        }
        case InstructionType::LoadInst: {
            auto cur_inst = dynamic_cast<LoadInst *>(inst);
            assert(cur_inst->getDst().isRegister());
            return {cur_inst->getDst().getReg()};
        }
        case InstructionType::LoadImm64Inst: {
            auto cur_inst = dynamic_cast<LoadImm64Inst *>(inst);
            assert(cur_inst->getDst().isRegister());
            return {cur_inst->getDst().getReg()};
        }
        case InstructionType::LoadPacketInst: {
            // load to r0 register
            return {Register::REG_0};
        }
        case InstructionType::LoadMapInst: {
            return nullopt;
        }
        case InstructionType::StoreInst: {
            auto cur_inst = dynamic_cast<StoreInst *>(inst);
            assert(cur_inst->getDst().isRegister());
            return {cur_inst->getDst().getReg()};
        }
        case InstructionType::MemXAddInst:
        case InstructionType::BranchInst:
        case InstructionType::CallInst:
        case InstructionType::ExitInst:
            return nullopt;
//        default:
//            assert(false && "semantic of this instruction is not implemented.");
    }
}


void SemanticFixer::fixDivByZero() {
    for (auto& bb : bbs_) {
        for (auto it = bb->getInstructions().begin(); it != bb->getInstructions().end(); ++it) {
            if ((*it)->instType == InstructionType::AluInst) {
                auto alu_inst = dynamic_cast<AluInst*>(it->get());
                if (alu_inst->getOpcode() == AluOpcode::DIV || alu_inst->getOpcode() == AluOpcode::MOD) {
                    // Insert a check before the division/modulo operation
                    auto check_inst = std::make_unique<BranchInst>(
                        BranchOpcode::JNE,
                        alu_inst->getSrc(),
                        Variable(0),
                        bb->getNextBlock(),
                        bb.get(),
                        alu_inst->getBitWidth()
                    );
                    it = bb->getInstructions().insert(it, std::move(check_inst));
                    ++it; // Move iterator past the newly inserted instruction
                }
            }
        }
    }
}

// this fix rule is aggressive, should be take carefully 
void SemanticFixer::fixOutOfBounds() {
    for (auto& bb : bbs_) {
        for (auto it = bb->getInstructions().begin(); it != bb->getInstructions().end(); ++it) {
            if ((*it)->instType == InstructionType::LoadInst || (*it)->instType == InstructionType::StoreInst) {
                auto mem_inst = dynamic_cast<MemoryInst*>(it->get());
                // Insert a bounds check before the memory operation
                auto check_inst = std::make_unique<BranchInst>(
                    BranchOpcode::JGT,
                    mem_inst->getSrc(),
                    Variable(MM_INPUT_START + 65536), // Assuming 64KB input buffer
                    bb->getNextBlock(),
                    bb.get(),
                    BitWidth::bit64
                );
                it = bb->getInstructions().insert(it, std::move(check_inst));
                ++it;
            } else if ((*it)->instType == InstructionType::CallInst) {
                auto call_inst = dynamic_cast<CallInst*>(it->get());
                // Insert a check for valid call target
                auto check_inst = std::make_unique<BranchInst>(
                    BranchOpcode::JGT,
                    call_inst->getTarget(),
                    Variable(5), // Assuming helper functions 0-5 are valid
                    bb->getNextBlock(),
                    bb.get(),
                    BitWidth::bit64
                );
                it = bb->getInstructions().insert(it, std::move(check_inst));
                ++it;
            }
        }
    }
}

void SemanticFixer::fixBasicVerifierRules() {
    for (auto& bb : bbs_) {
        // Ensure last instruction is EXIT or JMP
        if (!bb->getInstructions().empty()) {
            auto last_inst = bb->getInstructions().back().get();
            if (last_inst->instType != InstructionType::ExitInst && last_inst->instType != InstructionType::BranchInst) {
                auto exit_inst = std::make_unique<ExitInst>();
                bb->getInstructions().push_back(std::move(exit_inst));
            }
        }

        // Limit instruction count
        if (bb->getInstructions().size() > 40960) {
            bb->getInstructions().resize(40960);
        }
    }
}


std::vector<Register> SemanticFixer::getInstReadReg(Instruction *inst) {
    std::vector<Register> result;
    switch (inst->instType) {
        case InstructionType::AluInst: {
            auto cur_inst = dynamic_cast<AluInst *>(inst);
            if (cur_inst->getSrc().isRegister()) {
                result.push_back(cur_inst->getSrc().getReg());
            }
            break;
        }
        case InstructionType::MovInst: {
            auto cur_inst = dynamic_cast<MovInst *>(inst);
            if (cur_inst->getSrc().isRegister()) {
                result.push_back(cur_inst->getSrc().getReg());
            }
            break;
        }
        case InstructionType::LoadInst: {
            auto cur_inst = dynamic_cast<LoadInst *>(inst);
            assert(cur_inst->getSrc().isRegister());
            result.push_back(cur_inst->getSrc().getReg());
            break;
        }
        case InstructionType::LoadImm64Inst: {
            break;
        }
        case InstructionType::LoadPacketInst: {
            // load to r0 register
            auto cur_inst = dynamic_cast<LoadPacketInst *>(inst);
            if (cur_inst->getSrc().isValid() && cur_inst->getSrc().isRegister()) {
                result.push_back(cur_inst->getSrc().getReg());
            }
            break;
        }
        case InstructionType::LoadMapInst: {
            break;
        }
        case InstructionType::StoreInst: {
            auto cur_inst = dynamic_cast<StoreInst *>(inst);
            if (cur_inst->getSrc().isRegister()) {
                result.push_back(cur_inst->getSrc().getReg());
            }
            break;
        }
        case InstructionType::MemXAddInst: {
            auto cur_inst = dynamic_cast<MemXAddInst *>(inst);
            assert(cur_inst->getSrc().isRegister() && cur_inst->getDst().isRegister());
            result.push_back(cur_inst->getSrc().getReg());
            result.push_back(cur_inst->getDst().getReg());
            break;
        }
        case InstructionType::BranchInst: {
            auto cur_inst = dynamic_cast<BranchInst *>(inst);
            if (cur_inst->getOpcode() == BranchOpcode::JA) {
                break;
            }
            assert(cur_inst->getDst().isRegister());
            result.push_back(cur_inst->getDst().getReg());
            if (cur_inst->getSrc().isRegister()) {
                result.push_back(cur_inst->getSrc().getReg());
            }
            break;
        }
        case InstructionType::CallInst: {
            auto cur_inst = dynamic_cast<CallInst *>(inst);
            if (cur_inst->getTarget().isRegister()) {
                result.push_back(cur_inst->getTarget().getReg());
            }
            break;
        }
        case InstructionType::ExitInst: {
            break;
        }
        default:
            assert(false && "semantic of this instruction is not implemented.");
    }
    return result;
}


// ALL IN ALL PLAN:

// ARSH || RSH || LSH : src(const) should <= MAX_SHIFT_BIT (64);
//  avoid mod/div/sdiv zero

// NEG: src should be imm <= INT32_MAX
//    return std::make_unique<AluInst>
//            (opcode, createRandomTrivialDstRegister(), createRandomImm32(INT32_MAX),
//             createRandomBitWidth());

// TODO: CALL INSTRUCTION: minimize this callee offset to achieve better semantics
// rbpf doesn't support 32-bit-width in jmp32 In Branch : BitWidth::bit64 only
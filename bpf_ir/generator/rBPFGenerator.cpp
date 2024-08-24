#include "rBPFGenerator.h"
#include "ir.h"
#include "Module.h"
#include "Instruction.h"
#include "SemanticFixer.h"
#include <vector>
#include <sstream>
#include <iostream>

using namespace std;

RBPFGenerator::RBPFGenerator() {
    action_randomizer_ = std::make_unique<Randomizer<GeneratorAction>>(weightedGeneratorAction_); // rbpf
    branch_opcode_randomizer_ = std::make_unique<Randomizer<BranchOpcode>>(weightedBranchOpcode_);
    alu_opcode_randomizer_ = std::make_unique<Randomizer<AluOpcode>>(weightedAluOpcode_); // rbpf
    variable_randomizer_ = std::make_unique<Randomizer<VariableType>>(weightedVariable_);

    trivial_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedTrivialBitWidth_);
    endian_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedEndianBitWidth_);
    limited_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedLimitedBitWidth_);

    trivial_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialRegister_);
    trivial_dst_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialDstRegister_);
    trivial_src_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialRegister_); // unused
}

TestCase RBPFGenerator::generateProgram(size_t action_size) {
    // SHALL CHECKOUT SOME SEMANTICS
    auto *module = new Module(defaultReservedRegisters, 3, false);
    vector<BasicBlockPtr> bbs;
    bbs.push_back(createBasicBlock());
    bbs.push_back(createBasicBlock());
    bbs[0]->setExitTerminator();
    bbs[0]->add(make_unique<LoadImm64Inst>(Register::REG_0, 0));
    bbs[1]->setExitTerminator();
    size_t block_index = 0;
    while (action_size--) {
        assert(block_index >= 0 && block_index < bbs.size());
        auto block_cursor = bbs.at(block_index).get();
        switch (getRandomGeneratorAction()) {
            case CREATE_ALU:
                block_cursor->add(createRandomAluInstruction());
                break;
            case CREATE_MOV:
                block_cursor->add(createRandomMovInstruction());
                break;
            case CREATE_LOAD:
                block_cursor->add(createRandomLoadInstruction());
                break;
            case CREATE_LOAD_IMM:
                block_cursor->add(createRandomLoadImm64Instruction());
                break;
            case CREATE_LOAD_PACKET:
                block_cursor->add(createRandomLoadPacketInstruction());
                break;
            case CREATE_STORE:
                block_cursor->add(createRandomStoreInstruction());
                break;
            case CREATE_CALL:
                block_cursor->add(createRandomCallInstruction());
                break;
            case SET_BLOCK_JMP:
                if (bbs.size() > 1 && block_index < bbs.size() - 1) {
                    block_cursor->setBranchTerminator(branch_opcode_randomizer_->getRandomizedChoice(),
                                                      createRandomTrivialRegister(),
                                                      createRandomVariable(),
                            // TODO: As we have difficulty handling specific next block address, drop it as the next block
                                                      bbs.at(block_index + 1).get(),
                                                      bbs.at(random() % bbs.size()).get(),
                                                      limited_bw_randomizer_->getRandomizedChoice());
                }
                break;
            case SET_BLOCK_EXIT:
                block_cursor->setExitTerminator();
                break;
            case ADD_BLOCK:
                bbs.push_back(createBasicBlock());
                bbs[bbs.size() - 1]->setExitTerminator();
                break;
            case SWITCH_BLOCK_UP:
                if (block_index > 0) {
                    block_index--;
                } else {
//                    block_index = bbs.size() - 1;
                    block_index = random() % bbs.size();
                }
                break;
            case SWITCH_BLOCK_DOWN:
                if (block_index < bbs.size() - 1) {
                    block_index++;
                } else {
//                    block_index = 0;
                    block_index = random() % bbs.size();
                }
                break;
            case SWITCH_BLOCK_RANDOM:
                block_index = random() % bbs.size();
                break;
        }
    }
    SemanticFixer fixer(bbs);
    fixer.fixUninitializedRegister(this);
    module->addBasicBlocks(bbs);
    BytecodeData bytecode = module->CodeGen();
    std::stringstream stream;
    stream << *module;
    return {bytecode, stream.str()};
}

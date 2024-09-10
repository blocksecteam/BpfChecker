#include "uBPFGenerator.h"
#include "ir.h"
#include "Module.h"
#include "Instruction.h"
#include "SemanticFixer.h"
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>

using namespace std;

UBPFGenerator::UBPFGenerator() {
    action_randomizer_ = std::make_unique<Randomizer<GeneratorAction>>(weightedGeneratorAction_); // ubpf
    branch_opcode_randomizer_ = std::make_unique<Randomizer<BranchOpcode>>(weightedBranchOpcode_);
    alu_opcode_randomizer_ = std::make_unique<Randomizer<AluOpcode>>(weightedAluOpcode_); // ubpf
    variable_randomizer_ = std::make_unique<Randomizer<VariableType>>(weightedVariable_);

    trivial_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedTrivialBitWidth_);
    endian_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedEndianBitWidth_);
    limited_bw_randomizer_ = std::make_unique<Randomizer<BitWidth>>(weightedLimitedBitWidth_);

    trivial_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialRegister_);
    trivial_dst_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialDstRegister_);
    trivial_src_reg_randomizer_ = std::make_unique<Randomizer<Register>>(weightedTrivialRegister_); // unused
}

TestCase UBPFGenerator::generateProgram(size_t action_size) {
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
                                                      trivial_reg_randomizer_->getRandomizedChoice(),
                                                      this->createRandomVariable(),
                            // drop it as the next block
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
    // We want to initialize register since all eBPF engine either reject uninitialized, or initialize the register it manaully
    // Hence we are free to write to the register in the initial program stage
    fixer.fixUninitializedRegister(this);
    
    #ifdef ENABLE_ADVANCED_FIXER
    std::vector<std::function<void()>> fixerFunctions = {
        // NOTE: some fixer rules are aggresive, remove it if necessary
        [&]() { fixer.fixUninitializedMemory(this); },
        [&]() { fixer.fixUnusedRegisters(this); },
        [&]() { fixer.fixDeadCode(this); },
        [&]() { fixer.fixUninitializedRegisterAggressively(this); },
        [&]() { fixer.fixDivByZero(); },
        [&]() { fixer.fixOutOfBounds(); },
        [&]() { fixer.fixBasicVerifierRules(); }
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, fixerFunctions.size());
    
    int numFunctionsToCall = dis(gen);
    
    std::shuffle(fixerFunctions.begin(), fixerFunctions.end(), gen);
    
    for (int i = 0; i < numFunctionsToCall; ++i) {
        fixerFunctions[i]();
    }
    #endif
    
    module->addBasicBlocks(bbs);
    BytecodeData bytecode = module->CodeGen();
    std::stringstream stream;
    stream << *module;
    return {bytecode, stream.str()};
}



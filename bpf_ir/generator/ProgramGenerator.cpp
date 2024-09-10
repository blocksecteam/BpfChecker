#include "ProgramGenerator.h"
#include "Util.h"
#include <Module.h>

#include <sstream>

using namespace std;


std::vector<WeightedType<GeneratorAction>> weightedGeneratorAction = { // NOLINT(cert-err58-cpp)
       {GeneratorAction::CREATE_ALU,          20},
       {GeneratorAction::CREATE_MOV,          20},
       {GeneratorAction::CREATE_LOAD,         20},
       {GeneratorAction::CREATE_LOAD_IMM,     20},
       {GeneratorAction::CREATE_LOAD_PACKET,  20},
       {GeneratorAction::CREATE_STORE,        20},
       {GeneratorAction::CREATE_CALL,         20},
       {GeneratorAction::SET_BLOCK_JMP,       30},
       {GeneratorAction::SET_BLOCK_EXIT,      20},
       {GeneratorAction::ADD_BLOCK,           30},
       {GeneratorAction::SWITCH_BLOCK_UP,     20},
       {GeneratorAction::SWITCH_BLOCK_DOWN,   20},
       {GeneratorAction::SWITCH_BLOCK_RANDOM, 20},
};

std::vector<WeightedType<GeneratorAction>> weightedKernelGeneratorAction = { // NOLINT(cert-err58-cpp)
       {GeneratorAction::CREATE_ALU,          20},
       {GeneratorAction::CREATE_MOV,          20},
//        {GeneratorAction::CREATE_LOAD,         20},
//        {GeneratorAction::CREATE_LOAD_IMM,     20},
//        {GeneratorAction::CREATE_LOAD_PACKET,  20},
//        {GeneratorAction::CREATE_STORE,        20},
       {GeneratorAction::CREATE_CALL,         20},
       {GeneratorAction::SET_BLOCK_JMP,       30},
       {GeneratorAction::SET_BLOCK_EXIT,      20},
       {GeneratorAction::ADD_BLOCK,           30},
       {GeneratorAction::SWITCH_BLOCK_UP,     20},
       {GeneratorAction::SWITCH_BLOCK_DOWN,   20},
       {GeneratorAction::SWITCH_BLOCK_RANDOM, 20},
};

GeneratorAction getRandomGeneratorAction() {
   static bool isInitialized = false;
   static std::vector<size_t> weights;
   static std::unique_ptr<RandomEngine> re = nullptr;
   if (!isInitialized) {
       for (auto const &imap: weightedGeneratorAction)
           weights.push_back(imap.weight);
       re = std::make_unique<RandomEngine>(weights);
       isInitialized = true;
   }
   auto randomIdx = re->randomChoice();
   assert(0 <= randomIdx && randomIdx < weightedGeneratorAction.size());
   auto selectedType = weightedGeneratorAction[randomIdx].type;
   return selectedType;
}

GeneratorAction getRandomKernelGeneratorAction() {
   static bool isInitialized = false;
   static std::vector<size_t> weights;
   static std::unique_ptr<RandomEngine> re = nullptr;
   if (!isInitialized) {
       for (auto const &imap: weightedKernelGeneratorAction)
           weights.push_back(imap.weight);
       re = std::make_unique<RandomEngine>(weights);
       isInitialized = true;
   }
   auto randomIdx = re->randomChoice();
   assert(0 <= randomIdx && randomIdx < weightedKernelGeneratorAction.size());
   auto selectedType = weightedKernelGeneratorAction[randomIdx].type;
   return selectedType;
}

// TestCase generateExtremeCallProgram(size_t action_size) {
//    auto *module = new Module(defaultReservedRegisters, 3, false);
//    vector<BasicBlockPtr> bbs;
//    bbs.push_back(createBasicBlock());
//    bbs.push_back(createBasicBlock());
//    bbs[0]->setExitTerminator();
//    bbs[1]->setExitTerminator();
//    size_t block_index = 0;
// //    bbs[1]->add(std::make_unique<MovInst>(Register::REG_1, 1, BitWidth::bit64));
//    bbs[1]->add(std::make_unique<LoadImm64Inst>(Register::REG_1, 0));
//    while (action_size--) {
//        assert(block_index >= 0 && block_index < bbs.size());
//        auto block_cursor = bbs.at(block_index).get();
// //        block_cursor->add(std::make_unique<CallInst>(Register::REG_1));
//    }
//    module->addBasicBlocks(bbs);
//    BytecodeData bytecode = module->CodeGen();
//    std::stringstream stream;
//    stream << *module;
//    return {bytecode, stream.str()};
// }


// TestCase generateProgram(size_t action_size, GeneratorType generator_type) {
//    if (generator_type == ALU_ORIENTED) {
//        auto *module = new Module(defaultReservedRegisters, 3, false);
//        vector<BasicBlockPtr> bbs;
//        bbs.push_back(createBasicBlock());
//        bbs.push_back(createBasicBlock());
//        bbs.push_back(createBasicBlock());
// //        bbs[0]->setBranchTerminator(BranchOpcode::JSLT,Register::REG_5,Register::REG_0,bbs[1].get(),bbs[2].get(),BitWidth::bit64);
//        bbs[0]->setBranchTerminator(BranchOpcode::JSLT, Register::REG_5, 0, bbs[1].get(), bbs[2].get(),
//                                    BitWidth::bit64);

// //        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_5, 2104983039));
// //        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::SDIV,Register::REG_5, -505290271,BitWidth::bit32));
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_5, 0x10000000c));
//        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::SDIV, Register::REG_5, -4, BitWidth::bit32));
//        bbs[1]->setExitTerminator();
//        bbs[1]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 1));
//        bbs[2]->setExitTerminator();
//        module->addBasicBlocks(bbs);
//        BytecodeData bytecode = module->CodeGen();
//        std::stringstream stream;
//        stream << *module;
//        return {bytecode, stream.str()};
//    }
//    if (generator_type == UBPF_ORIENTED) {
//        return generateUBPFProgram(action_size);
//    }

//    auto *module = new Module(defaultReservedRegisters, 3, false);
//    vector<BasicBlockPtr> bbs;
//    bbs.push_back(createBasicBlock());
//    bbs.push_back(createBasicBlock());
//    bbs[0]->setExitTerminator();
//    bbs[1]->setExitTerminator();
//    size_t block_index = 0;
//    while (action_size--) {
//        assert(block_index >= 0 && block_index < bbs.size());
//        auto block_cursor = bbs.at(block_index).get();
//        GeneratorAction next_action;
//        assert(generator_type == GENERIC);
//        next_action = getRandomGeneratorAction();
//        switch (next_action) {
//            case CREATE_ALU:
//                block_cursor->add(createRandomAluInstruction());
//                break;
//            case CREATE_MOV:
//                block_cursor->add(createRandomMovInstruction());
//                break;
//            case CREATE_LOAD:
//                block_cursor->add(createRandomLoadInstruction());
//                break;
//            case CREATE_LOAD_IMM:
//                block_cursor->add(createRandomLoadImm64Instruction());
//                break;
//            case CREATE_LOAD_PACKET:
//                block_cursor->add(createRandomLoadPacketInstruction());
//                break;
//            case CREATE_STORE:
//                block_cursor->add(createRandomStoreInstruction());
//                break;
//            case CREATE_CALL:
//                block_cursor->add(createRandomCallInstruction());
//                break;
//            case SET_BLOCK_JMP:
//                if (bbs.size() > 1 && block_index < bbs.size() - 1) {
//                    block_cursor->setBranchTerminator(createRandomBranchOpcode(),
//                                                      createRandomRegister(),
//                                                      createRandomVariable(),//createRandomRegister()
//                            // As we have difficulty handling specific next block address,
//                            // drop it as the next block
//                                                      bbs.at(block_index + 1).get(),
//                                                      bbs.at(random() % bbs.size()).get(),
//                            // disable createRandomBitWidth() since rbpf doesn't support jmp32
//                                                      BitWidth::bit64);
//                }
//                break;
//            case SET_BLOCK_EXIT:
//                block_cursor->setExitTerminator();
//                break;
//            case ADD_BLOCK:
//                bbs.push_back(createBasicBlock());
//                bbs[bbs.size() - 1]->setExitTerminator();
//                break;
//            case SWITCH_BLOCK_UP:
//                if (block_index > 0) {
//                    block_index--;
//                } else {
//                    block_index = bbs.size() - 1;
//                }
//                break;
//            case SWITCH_BLOCK_DOWN:
//                if (block_index < bbs.size() - 1) {
//                    block_index++;
//                } else {
//                    block_index = 0;
//                }
//                break;
//            case SWITCH_BLOCK_RANDOM:
//                block_index = random() % bbs.size();
//                break;
//        }
//    }
//    module->addBasicBlocks(bbs);
//    BytecodeData bytecode = module->CodeGen();
//    std::stringstream stream;
//    stream << *module;
//    return {bytecode, stream.str()};
// }

// TestCase generateKernelProgram(size_t action_size) {
//    // all possible instructions:
//    // (suppose 100 magic number)
//    //  alu: 14*( 4*9*8 + 100 * 9) = 16632
//    //  mov: 110 * 9 * 2 = 1980
//    //  load: 4 * 10 * 10 = 400
//    //  load_packet: 4 * 100 = 400
//    //  load_imm64: 9 * 100 = 900
//    //  load_map:
//    //  store: 9 * 9 * 100 * 4 = 32400
//    //  memx: 9 * 9 * 100 * 4 = 32400
//    //  call : program_size
//    //  exit
//    auto *module = new Module(defaultReservedRegisters, 3, false);
//    vector<BasicBlockPtr> bbs;
//    bbs.push_back(createBasicBlock());
//    bbs.push_back(createBasicBlock());
//    bbs[0]->setExitTerminator();
//    bbs[1]->setExitTerminator();
//    size_t block_index = 0;
//    while (action_size--) {
//        assert(block_index >= 0 && block_index < bbs.size());
//        auto block_cursor = bbs.at(block_index).get();
//        switch (getRandomKernelGeneratorAction()) {
//            case CREATE_ALU:
//                block_cursor->add(createRandomAluInstruction());
//                break;
//            case CREATE_MOV:
//                block_cursor->add(createRandomMovInstruction());
//                break;
//            case CREATE_LOAD:
//                block_cursor->add(createRandomLoadInstruction());
//                break;
//            case CREATE_LOAD_IMM:
//                block_cursor->add(createRandomLoadImm64Instruction());
//                break;
//            case CREATE_LOAD_PACKET:
//                block_cursor->add(createRandomLoadPacketInstruction());
//                break;
//            case CREATE_STORE:
//                block_cursor->add(createRandomStoreInstruction());
//                break;
//            case CREATE_CALL:
//                block_cursor->add(createRandomCallInstruction());
//                break;
//            case SET_BLOCK_JMP:
//                if (bbs.size() > 1 && block_index < bbs.size() - 1) {
//                    block_cursor->setBranchTerminator(createRandomBranchOpcode(),
//                                                      createRandomRegister(),
//                                                      createRandomVariable(),//createRandomRegister()
//                            // As we have difficulty handling specific next block address,
//                            // drop it as the next block
//                                                      bbs.at(block_index + 1).get(),
//                                                      bbs.at(random() % bbs.size()).get(),
//                            // disable createRandomBitWidth() since rbpf doesn't support jmp32
//                                                      BitWidth::bit64);
//                }
//                break;
//            case SET_BLOCK_EXIT:
//                block_cursor->setExitTerminator();
//                break;
//            case ADD_BLOCK:
//                bbs.push_back(createBasicBlock());
//                bbs[bbs.size() - 1]->setExitTerminator();
//                break;
//            case SWITCH_BLOCK_UP:
//                if (block_index > 0) {
//                    block_index--;
//                } else {
//                    block_index = bbs.size() - 1;
//                }
//                break;
//            case SWITCH_BLOCK_DOWN:
//                if (block_index < bbs.size() - 1) {
//                    block_index++;
//                } else {
//                    block_index = 0;
//                }
//                break;
//            case SWITCH_BLOCK_RANDOM:
//                block_index = random() % bbs.size();
//                break;
//        }
//    }
//    module->addBasicBlocks(bbs);
//    BytecodeData bytecode = module->CodeGen();
//    std::stringstream stream;
//    stream << *module;
//    return {bytecode, stream.str()};
// }

TestCase ProgramGenerator::generatePoC(GeneratorType generator_type) {
    if (generator_type == GeneratorType::UBPF_OOB_POC) {
        auto *module = new Module(defaultReservedRegisters, 3, false);
        vector<BasicBlockPtr> bbs;
        bbs.push_back(createBasicBlock());
        bbs.push_back(createBasicBlock());

//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_5, 2104983039));
//        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::SDIV,Register::REG_5, -505290271,BitWidth::bit32));
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, -1));// 0xdeadbeef

//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0, BitWidth::bit32));// 0xdeadbeef
//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit32));// 0xdeadbeef

//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 2801250481, BitWidth::bit32));
//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0xdead0000, BitWidth::bit32));
        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0xdead0000, BitWidth::bit32));
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_4, 0x1004020000));
        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 0xdeadbeef));// 0xdeadbeef
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 0));
        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::ADD,Register::REG_0, Register::REG_0, BitWidth::bit32));
        bbs[0]->add(std::make_unique<StoreInst>(Register::REG_4, Register::REG_4, 0x1234, BitWidth::bit16));
//        bbs[0]->add(std::make_unique<StoreInst>(Register::REG_0, 1450724545, 19594, BitWidth::bit8));
        bbs[0]->setExitTerminator();
        bbs[1]->setExitTerminator();
        module->addBasicBlocks(bbs);
        BytecodeData bytecode = module->CodeGen();
        std::stringstream stream;
        stream << *module;
        return {bytecode, stream.str()};
    }else if(generator_type == GeneratorType::UBPF_INTEGER_OVERFLOW_ADDR_POC){
        auto *module = new Module(defaultReservedRegisters, 3, false);
        vector<BasicBlockPtr> bbs;
        bbs.push_back(createBasicBlock());
        bbs.push_back(createBasicBlock());

//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_5, 2104983039));
//        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::SDIV,Register::REG_5, -505290271,BitWidth::bit32));
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, -1));// 0xdeadbeef

//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0, BitWidth::bit32));// 0xdeadbeef
//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit32));// 0xdeadbeef

//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 2801250481, BitWidth::bit32));
//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0xdead0000, BitWidth::bit32));
//        bbs[0]->add(std::make_unique<MovInst>(Register::REG_4, 0xFFFFFFFF, BitWidth::bit32));
        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_4, 0xFFFFFFFFFFFFFFFF));
//        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 0xdeadbeef));// 0xdeadbeef
        bbs[0]->add(std::make_unique<LoadImm64Inst>(Register::REG_0, 0));
        bbs[0]->add(std::make_unique<AluInst>(AluOpcode::ADD,Register::REG_0, Register::REG_0, BitWidth::bit32));
        bbs[0]->add(std::make_unique<StoreInst>(Register::REG_4, Register::REG_4, 0, BitWidth::bit32));
//        bbs[0]->add(std::make_unique<StoreInst>(Register::REG_0, 1450724545, 19594, BitWidth::bit8));
        bbs[0]->setExitTerminator();
        bbs[1]->setExitTerminator();
        module->addBasicBlocks(bbs);
        BytecodeData bytecode = module->CodeGen();
        std::stringstream stream;
        stream << *module;
        return {bytecode, stream.str()};
    }
    assert(false);
}

GeneratorAction ProgramGenerator::getRandomGeneratorAction() {
    assert(action_randomizer_);
    return action_randomizer_->getRandomizedChoice();
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomAluInstruction() {
    return std::move(createAluInstruction(alu_opcode_randomizer_->getRandomizedChoice()));
}

std::unique_ptr<Instruction> ProgramGenerator::createAluInstruction(AluOpcode opcode) {

    if (opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE) {
        return createDetailedAluInstruction(opcode, createRandomTrivialDstRegister().getReg(), nullopt,
                                            {endian_bw_randomizer_->getRandomizedChoice()});
    }
    if (opcode == AluOpcode::NEG) {
        return createDetailedAluInstruction(opcode, createRandomTrivialDstRegister().getReg(),
                                            {createRandomImm32(INT32_MAX)},
                                            {limited_bw_randomizer_->getRandomizedChoice()});

    }
    return createDetailedAluInstruction(opcode, createRandomTrivialDstRegister().getReg(), {createRandomVariable()},
                                        {limited_bw_randomizer_->getRandomizedChoice()});
}

std::unique_ptr<Instruction>
ProgramGenerator::createDetailedAluInstruction(AluOpcode opcode, Register dstRegister, optional<Variable> candidateSrc,
                                               optional<BitWidth> candidateBitWidth) {
    // We shall let semantic fixer to fix wrong semantic instruction.
    if (opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE) {
        if (!candidateBitWidth.has_value()) {
            candidateBitWidth = {endian_bw_randomizer_->getRandomizedChoice()};
        }
        return std::make_unique<AluInst>(opcode, dstRegister, candidateBitWidth.value());
    }
    if (opcode == AluOpcode::NEG) {
        if (!candidateBitWidth.has_value()) {
            candidateBitWidth = {limited_bw_randomizer_->getRandomizedChoice()};
        }
        return std::make_unique<AluInst>
                (opcode, dstRegister, candidateSrc.value(), candidateBitWidth.value());
    }
    if (!candidateBitWidth.has_value()) {
        candidateBitWidth = {limited_bw_randomizer_->getRandomizedChoice()};
    }
    return std::make_unique<AluInst>(opcode, dstRegister, candidateSrc.value(), candidateBitWidth.value());
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomMovInstruction() {
    return std::make_unique<MovInst>(createRandomTrivialDstRegister(),
                                     createRandomVariable(),
                                     limited_bw_randomizer_->getRandomizedChoice());
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomLoadInstruction() {
    return std::make_unique<LoadInst>
            (createRandomTrivialDstRegister(), createRandomTrivialRegister(), MagicNumber::getRandomOffset16(),
             trivial_bw_randomizer_->getRandomizedChoice());
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomLoadImm64Instruction() {
    return std::make_unique<LoadImm64Inst>(createRandomTrivialDstRegister(), MagicNumber::getRandomInt64());
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomLoadPacketInstruction() {
    if (shouldDo(50)) {
        return std::make_unique<LoadPacketInst>
                (MagicNumber::getRandomOffset16(),
                 trivial_bw_randomizer_->getRandomizedChoice());
    } else {
        return std::make_unique<LoadPacketInst>
                (createRandomTrivialRegister(), MagicNumber::getRandomOffset32(),
                 trivial_bw_randomizer_->getRandomizedChoice());
    }
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomStoreInstruction() {
    if (shouldDo(50)) {
        return std::make_unique<StoreInst>
                (createRandomTrivialRegister(), createRandomTrivialRegister(), MagicNumber::getRandomOffset16(),
                 trivial_bw_randomizer_->getRandomizedChoice());
    } else {
        return std::make_unique<StoreInst>
                (createRandomTrivialRegister(), createRandomImm32(INT32_MAX), MagicNumber::getRandomOffset16(),
                 trivial_bw_randomizer_->getRandomizedChoice());
    }
}

std::unique_ptr<Instruction> ProgramGenerator::createRandomCallInstruction() {
    return std::make_unique<CallInst>
            (createRandomVariable());
}

Variable ProgramGenerator::createRandomVariable() {
    VariableType selectedType = variable_randomizer_->getRandomizedChoice();
    switch (selectedType) {
        case VariableType::Register:
            return trivial_reg_randomizer_->getRandomizedChoice();
        case VariableType::Imm32:
            return createRandomImm32(INT32_MAX);
        case VariableType::Imm64:
            assert(false && "variable is not allowed to use imm64 currently.");
    }
}

// Basic Functions:

Variable ProgramGenerator::createRandomImm32(int32_t maxImm) {
    auto rand_value = MagicNumber::getRandomInt32();
    if (maxImm != INT32_MAX) {
        return {static_cast<bpf_imm32_type>( rand_value % (maxImm + 1))}; // contains maxImm
    } else {
        return {static_cast<bpf_imm32_type>( rand_value )}; // contains maxImm
    }
}

Variable ProgramGenerator::createRandomTrivialRegister() {
    assert(trivial_reg_randomizer_);
    return {trivial_reg_randomizer_->getRandomizedChoice()};
}

Variable ProgramGenerator::createRandomTrivialDstRegister() {
    assert(trivial_dst_reg_randomizer_);
    return {trivial_dst_reg_randomizer_->getRandomizedChoice()};
}

// common written-usage-instruction creation for semantic fixer
std::unique_ptr<Instruction>
ProgramGenerator::generateWriteUsageInstruction(Register writtenRegister, Registers &initializedRegisters) {
    Variable candidate_src = createRandomImm32(INT32_MAX);
    if (!initializedRegisters.empty()) {
        candidate_src = initializedRegisters[RAND_POSITIVE_BELOW(initializedRegisters.size())];
    }

    if (shouldDo(50)) {
        auto target_alu_op = alu_opcode_randomizer_->getRandomizedChoice();
        if (target_alu_op == AluOpcode::NEG && candidate_src.isRegister()) {
            candidate_src = createRandomImm32(INT32_MAX);
        }
        createDetailedAluInstruction(target_alu_op, writtenRegister, candidate_src,
                                     nullopt);
    }
    auto target_random = MagicNumber::getRandomInt64();
    while (!target_random) {
        target_random = MagicNumber::getRandomInt64();;
    }
    if (shouldDo(50)) {

        return std::make_unique<LoadImm64Inst>(writtenRegister, target_random);
    }
    return std::make_unique<MovInst>(writtenRegister, static_cast<int32_t>(target_random),
                                     limited_bw_randomizer_->getRandomizedChoice());
}


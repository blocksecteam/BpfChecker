#include "mutator.h"
#include "ir.h"
#include "Module.h"
#include "config.h"
#include "common.h"
#include "randomEngine.h"

#include <limits>

#define RAND_BELOW(limit) (generator() % (limit))

#define COMBINE_TWO_NUMBER(a, b) ()

void IRMutationStrategy::mutate(Module &M) {

}

void IRMutationStrategy::mutate(BasicBlock &BB) {

}

BitWidth createRandomEndianBitWidth() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedEndianBitWidth)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedEndianBitWidth.size());
    auto selectedType = weightedEndianBitWidth[randomIdx].type;
    return selectedType;
}


BitWidth createRandomTrivialBitWidth() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedTrivialBitWidth)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedTrivialBitWidth.size());
    auto selectedType = weightedTrivialBitWidth[randomIdx].type;
    return selectedType;
}


BitWidth createRandomBitWidth() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedBitWidth)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedBitWidth.size());
    auto selectedType = weightedBitWidth[randomIdx].type;
    return selectedType;
}


AluOpcode createRandomPointerAluOpcode() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedPointerAluOpcode)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedPointerAluOpcode.size());
    auto selectedType = weightedPointerAluOpcode[randomIdx].type;
    return selectedType;
}

AluOpcode createRandomAluOpcode() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedAluOpcode)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedAluOpcode.size());
    auto selectedType = weightedAluOpcode[randomIdx].type;
    return selectedType;
}

BranchOpcode createRandomBranchOpcode() {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedBranchOpcode)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedBranchOpcode.size());
    return weightedBranchOpcode[randomIdx].type;
}

void mutateAluInstruction(AluInst *aluInst) {
    defaultReservedRegisters.getMapPtrRegister();
    auto &&aluSrc = aluInst->getSrc();
    if (aluSrc.isRegister() && aluSrc.getReg() == defaultReservedRegisters.getMapPtrRegister()) {
        aluInst->setOpcode(createRandomPointerAluOpcode());
    } else {
        aluInst->setOpcode(createRandomAluOpcode());
    }
    aluInst->setBitWidth(createRandomBitWidth());
}

// reservedRegisters could be nullptr
Register createRandomRegister(ReservedRegisters *reservedRegisters) {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    // we should ignore some reserved register to keep semantics
    static std::vector<WeightedType<Register>> innerWeightedRegister;
    if (!isInitialized) {
        for (auto const &reg: weightedRegister) {
            if (reservedRegisters && reservedRegisters->isReservedRegister(reg.type)) {
                continue;
            }
            innerWeightedRegister.push_back(reg);
        }

        for (auto const &reg: innerWeightedRegister) {
            weights.push_back(reg.weight);
        }
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < innerWeightedRegister.size());
    auto selectedType = innerWeightedRegister[randomIdx].type;
    return selectedType;
}

Register createRandomTrivialDstRegister(ReservedRegisters *reservedRegisters = nullptr) {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    // we should ignore some reserved register to keep semantics
    static std::vector<WeightedType<Register>> innerWeightedRegister;
    if (!isInitialized) {
        for (auto const &reg: weightedTrivialDstRegister) {
            if (reservedRegisters && reservedRegisters->isReservedRegister(reg.type)) {
                continue;
            }
            innerWeightedRegister.push_back(reg);
        }

        for (auto const &reg: innerWeightedRegister) {
            weights.push_back(reg.weight);
        }
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < innerWeightedRegister.size());
    auto selectedType = innerWeightedRegister[randomIdx].type;
    return selectedType;
}

Register createRandomTrivialRegister(ReservedRegisters *reservedRegisters = nullptr) {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    // we should ignore some reserved register to keep semantics
    static std::vector<WeightedType<Register>> innerWeightedRegister;
    if (!isInitialized) {
        for (auto const &reg: weightedTrivialRegister) {
            if (reservedRegisters && reservedRegisters->isReservedRegister(reg.type)) {
                continue;
            }
            innerWeightedRegister.push_back(reg);
        }

        for (auto const &reg: innerWeightedRegister) {
            weights.push_back(reg.weight);
        }
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < innerWeightedRegister.size());
    auto selectedType = innerWeightedRegister[randomIdx].type;
    return selectedType;
}

Variable createRandomImm32() {
    if (shouldDo(50)) {
        auto rand_value = RAND_BELOW(INT32_MAX);
        return {static_cast<bpf_imm32_type>( rand_value)};
    } else {
        auto rand_value = MagicNumber::getRandomInt32();
        return {static_cast<bpf_imm32_type>( rand_value)};
    }

}

Variable createRandomImm32(int32_t maxImm) {
    auto rand_value = MagicNumber::getRandomInt32();
    if (maxImm != INT32_MAX) {
        return {static_cast<bpf_imm32_type>( rand_value % (maxImm + 1))}; // contains maxImm
    } else {
        return {static_cast<bpf_imm32_type>( rand_value )}; // contains maxImm
    }
}

Variable createRandomPositiveImm32() {
    auto rand_value = static_cast<uint32_t>(abs(MagicNumber::getRandomInt32()));
    return {static_cast<bpf_imm32_type>( rand_value)};
}

Variable createRandomPositiveImm32(uint32_t minImm, uint32_t maxImm) {
    auto rand_value = static_cast<uint32_t>(MagicNumber::getRandomInt32());
    if (maxImm != UINT32_MAX) {
        return {static_cast<bpf_imm32_type>( minImm + (rand_value % (maxImm - minImm + 1)))};
    } else {
        return {static_cast<bpf_imm32_type>( minImm + abs((int) rand_value))};
    }
}


// default parameters defined in header
// Variable createRandomVariable(ReservedRegisters *reservedRegisters = nullptr, int64_t maxImm = INT64_MAX,
//                              bool isPositive = true)
Variable createRandomVariable(ReservedRegisters *reservedRegisters, int64_t maxImm,
                              bool isPositive) {
    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedVariable)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedVariable.size());
    VariableType selectedType = weightedVariable[randomIdx].type;
    switch (selectedType) {
        case VariableType::Register:
            return {createRandomRegister(reservedRegisters)};
        case VariableType::Imm32:
            // TODO : fix bug here
            if (isPositive) {
                if (maxImm == INT64_MAX)
                    return createRandomPositiveImm32(0, maxImm);
                else
                    return createRandomPositiveImm32();
            } else {
                if (maxImm == INT64_MAX)
                    return createRandomImm32(maxImm);
                else
                    return createRandomImm32();
            }
        case VariableType::Imm64:
            assert(false && "variable is not allowed to use imm64 currently.");
    }
}

Variable tryRemoveZeroImmOfVariable(Variable variable) {
    if (variable.isImm32() && variable.getImm32() == 0) {
        variable.setImm32(abs(MagicNumber::getRandomInt32()) + 1);
    }
    return variable;
}

std::unique_ptr<Instruction> createAluInstruction(AluOpcode opcode) {
    if (opcode == AluOpcode::ARSH || opcode == AluOpcode::RSH || opcode == AluOpcode::LSH) {
        // shift dst reg self.
        auto src = createRandomVariable(nullptr, MAX_SHIFT_BIT, true);
        if (src.isImm32()) { // TODO: remove manual fix here
            src.setImm32(abs((int) src.getImm32()) % MAX_SHIFT_BIT);
        }

        return std::make_unique<AluInst>
                (opcode, createRandomTrivialDstRegister(), src,
                 createRandomBitWidth());
    } else if (opcode == AluOpcode::NEG) {
        return std::make_unique<AluInst>
                (opcode, createRandomTrivialDstRegister(), createRandomImm32(INT32_MAX),
                 createRandomBitWidth());
    } else if (opcode == AluOpcode::DIV || opcode == AluOpcode::SDIV) {
        // TODO : remove it to achieve higher coverage
        // avoid div by zero
        Variable src = createRandomVariable();
        return std::make_unique<AluInst>
                (opcode, createRandomTrivialDstRegister(),
                 tryRemoveZeroImmOfVariable(src), // createRandomImm32(INT32_MAX)
                 createRandomBitWidth());
    } else if (opcode == AluOpcode::MOD) {
        // avoid mod zero
        return std::make_unique<AluInst>
                (opcode, createRandomTrivialDstRegister(),
                 tryRemoveZeroImmOfVariable(createRandomVariable()),
                 createRandomBitWidth());
    } else if (opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE) {
        return std::make_unique<AluInst>
                (opcode, createRandomTrivialDstRegister(),
                 createRandomEndianBitWidth());
    }
    return std::make_unique<AluInst>
            (opcode, createRandomTrivialDstRegister(), createRandomVariable(),
             createRandomBitWidth());
}

std::unique_ptr<Instruction> createRandomAluInstruction() {
    auto opcode = createRandomAluOpcode();
    return std::move(createAluInstruction(opcode));
}

std::unique_ptr<Instruction> createRandomMovInstruction() {
    return std::make_unique<MovInst>
            (createRandomTrivialDstRegister(), createRandomVariable(),
             createRandomBitWidth());
}


std::unique_ptr<Instruction> createRandomLoadImm64Instruction() {
    return std::make_unique<LoadImm64Inst>
            (createRandomTrivialDstRegister(), MagicNumber::getRandomInt64());
}

std::unique_ptr<Instruction> createRandomLoadInstruction() {
    return std::make_unique<LoadInst>
            (createRandomTrivialDstRegister(), createRandomTrivialRegister(), MagicNumber::getRandomOffset16(),
             createRandomTrivialBitWidth());
}

std::unique_ptr<Instruction> createRandomLoadPacketInstruction() {
    if (shouldDo(50)) {
        return std::make_unique<LoadPacketInst>
                (MagicNumber::getRandomOffset16(),
                 createRandomTrivialBitWidth());
    } else {
        return std::make_unique<LoadPacketInst>
                (createRandomTrivialRegister(), MagicNumber::getRandomOffset32(),
                 createRandomTrivialBitWidth());
    }
}

std::unique_ptr<Instruction> createRandomStoreInstruction() {
    if (shouldDo(50)) {
        return std::make_unique<StoreInst>
                (createRandomTrivialRegister(), createRandomTrivialRegister(), MagicNumber::getRandomOffset16(),
                 createRandomTrivialBitWidth());
    } else {
        return std::make_unique<StoreInst>
                (createRandomTrivialRegister(), createRandomImm32(), MagicNumber::getRandomOffset16(),
                 createRandomTrivialBitWidth());
    }
}

std::unique_ptr<Instruction> createRandomCallInstruction() {
    return std::make_unique<CallInst>
            (createRandomVariable()); // TODO: minimize this callee offset to achieve better semantics
}

std::unique_ptr<Instruction> createRandomTrivialInstruction() {

    static bool isInitialized = false;
    static std::vector<size_t> weights;
    static std::unique_ptr<RandomEngine> re = nullptr;
    if (!isInitialized) {
        for (auto const &imap: weightedTrivialInst)
            weights.push_back(imap.weight);
        re = std::make_unique<RandomEngine>(weights);
        isInitialized = true;
    }
    auto randomIdx = re->randomChoice();
    assert(0 <= randomIdx && randomIdx < weightedTrivialInst.size());
    auto selectedType = weightedTrivialInst[randomIdx].type;
    switch (selectedType) {

        case InstructionType::AluInst: {
            return createRandomAluInstruction();
        }
        case InstructionType::MovInst:
            return createRandomMovInstruction();
        case InstructionType::LoadInst:
            // TODO : connect the offset
            return createRandomLoadInstruction();
        case InstructionType::LoadImm64Inst:
            return createRandomLoadImm64Instruction();
        case InstructionType::LoadMapInst:
//            break;
        case InstructionType::StoreInst:
//            break;
        case InstructionType::MemXAddInst:
//            break;
        case InstructionType::BranchInst:
        case InstructionType::ExitInst:
            assert(false && "error in random engine.");
        default :
            assert(false && "SHOULDN'T BE HERE. This instruction type is an invalid trivial instruction type.");
    }
}

void InstInjectorStrategy::mutate(Module &module) {
    // TODO : init it in the other places
    srand(time(0));

    auto &blocks = module.getBasicBlocks();
    if (blocks.empty()) {
        // empty module, we should add basic blocks to it.
        auto base = createBasicBlock();
        base->add(std::make_unique<MovInst>(Register::REG_0, 0, BitWidth::bit64));
        base->setExitTerminator();
        module.addBasicBlock(std::move(base));
        return;
    }
    // choose the interesting basic block

    auto &targetBlocks = blocks[RAND_BELOW(blocks.size())];
    targetBlocks->add(createRandomTrivialInstruction());



//    IRMutationStrategy::mutate(module);
}

void InstInjectorStrategy::mutate(BasicBlock &BB) {
//    IRMutationStrategy::mutate(BB);
}

void InstDeleterStrategy::mutate(Module &M) {
    IRMutationStrategy::mutate(M);
}

void InstDeleterStrategy::mutate(BasicBlock &BB) {
    IRMutationStrategy::mutate(BB);
}

ModulePtr mutateTemplateModule(ModulePtr module) {
    auto &&bbs = module->getBasicBlocks();

    if (bbs.size() < 3) {
        // not a template
        return std::move(module);
    }

    // first block should be cond block
//    auto &&condBlock = bbs[0];
    // if(condBlock->isBranchTerminator()){
    //     auto inst = (BranchInst *) condBlock->getTerminator();
    //     inst->getOpcode()
    // }

    for (int index = 0; index < bbs.size() - 1; ++index) {
        auto &&instructions = bbs[index]->getInstructions();
        for (auto &&inst: instructions) {
            if (inst->instType == InstructionType::AluInst) {
                mutateAluInstruction((AluInst *) inst.get());
            }
        }
        // mutate branch
        if (bbs[index]->isBranchTerminator() &&
            !bbs[index]->getInstructions().empty() &&
            bbs[index]->getInstructions().back()->instType == InstructionType::LoadImm64Inst) {
            auto &&loadImmInst = (LoadImm64Inst *) bbs[index]->getInstructions().back().get();
            loadImmInst->setImm64(MagicNumber::getRandomInt64());
        }

    }
    // mutate footer
    auto &&footer = bbs[bbs.size() - 1];
    auto &&instructions = footer->getInstructions();
    size_t aluInstNumber = 0;
    for (auto &&inst: instructions) {
        if (inst->instType == InstructionType::AluInst) {
            aluInstNumber++;
            mutateAluInstruction((AluInst *) inst.get());
        }
    }
    return std::move(module);
}

ModulePtr havocMutateTemplateModule(ModulePtr module) {
    auto &&simpleMutatedModule = std::move(mutateTemplateModule(std::move(module)));
    auto &&bbs = simpleMutatedModule->getBasicBlocks();
    auto &&footer = bbs[bbs.size() - 1];
    auto &&instructions = footer->getInstructions();
    size_t aluInstNumber = 0;
    for (auto &&inst: instructions) {
        if (inst->instType == InstructionType::AluInst) {
            aluInstNumber++;
            if (shouldDo(60)) {
                mutateAluInstruction((AluInst *) inst.get());
            }
        }
    }

    // delete an alu inst
    if (shouldDo(80) && aluInstNumber > 2) {
        for (auto instIndex = 0; instIndex < instructions.size(); instIndex++) {
            if (instructions[instIndex]->instType == InstructionType::AluInst) {
                if (shouldDo(200 / aluInstNumber)) {
                    footer->remove(instIndex);
                    break;
                }
            }
        }

        // we might need to add another alu inst:
        if (shouldDo(80) && aluInstNumber < 6) {
            footer->insert(0, std::make_unique<AluInst>(createRandomAluOpcode(), createRandomRegister(),
                                                        createRandomRegister(), createRandomBitWidth()));
        }
    }

    if (shouldDo(80) && aluInstNumber < 6) {
        footer->insert(0, std::make_unique<AluInst>(createRandomAluOpcode(), createRandomRegister(),
                                                    createRandomRegister(), createRandomBitWidth()));
    }

    return std::move(module);
}

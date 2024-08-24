#include "Lifter.h"
#include <algorithm>

// debug only
//#include <iostream>

bool isValidRegister(uint8_t reg) {
    return to_underlying(Register::REG_0) <= reg && reg < to_underlying(Register::MAX_REG);
}

BitWidth parseBitWidth(uint8_t code) {
    switch (BPF_SIZE(code)) {
        case BPF_SIZE(BPF_B):
            return BitWidth::bit8;
        case BPF_SIZE(BPF_H):
            return BitWidth::bit16;
        case BPF_SIZE(BPF_W):
            return BitWidth::bit32;
        case BPF_SIZE(BPF_DW):
            return BitWidth::bit64;
        default:
            assert(false && "Invalid code");
    }
}

bool isValidTrivialBitWidth(uint8_t code) {
    code = BPF_SIZE(code);
    return code == BPF_SIZE(BPF_B) ||
           code == BPF_SIZE(BPF_H) ||
           code == BPF_SIZE(BPF_W) ||
           code == BPF_SIZE(BPF_DW);
}

bool isValidBitWidth(uint8_t code) {
    code = BPF_SIZE(code);
    return code == BPF_SIZE(BPF_W) ||
           code == BPF_SIZE(BPF_DW);
}

Register parseRegister(uint8_t reg) {
    assert(isValidRegister(reg));
    return static_cast<Register>(reg);
}

ReservedRegisters quickSearchReservedReg(BytecodeData &bytecodeData) {

    // search for BPF_LD_MAP_FD

    uint8_t ldMapFdFeature[] = {
            BPF_LD | BPF_DW | BPF_IMM,
            0
    };

    Register map_fd_register = Register::MAX_REG;
    for (unsigned int i = 0; i + 1 < bytecodeData.size(); ++i) {
        if (bytecodeData[i].code == ldMapFdFeature[0]
            && bytecodeData[i + 1].code == ldMapFdFeature[1]) {
            if (isValidRegister(bytecodeData[i].dst_reg)) {
                map_fd_register = static_cast<Register>(bytecodeData[i].dst_reg);
                break;
            }
        }
    }
    assert(map_fd_register != Register::MAX_REG);

    // TODO : search for the real map pointer
    return ReservedRegisters(map_fd_register, defaultReservedRegisters.getMapPtrRegister(),
                             defaultReservedRegisters.getBoundRegister());
}


bool isControlFlowInstruction(uint8_t opcode) {
    static uint8_t jmpFeatures[] = {
            BPF_JMP32 | BPF_K,
            BPF_JMP32 | BPF_X,
            BPF_JMP | BPF_K,
            BPF_JMP | BPF_X,
    };

    static std::vector<uint8_t> opcodeFeature;
    if (opcodeFeature.empty()) {
        for (const auto &jmpFeature: jmpFeatures) {
            for (const auto &bOpcode: allBranchOpcode) {
                opcodeFeature.push_back(jmpFeature | to_underlying(bOpcode));
            }
        }
        opcodeFeature.push_back(BPF_JMP | BPF_EXIT);
    }

    return std::find(opcodeFeature.begin(), opcodeFeature.end(), opcode) != opcodeFeature.end();
}

InstPtr LiftInstruction(bpf_insn insn) {
    return nullptr;
}


static bool isSameBytecode(bpf_insn *first, bpf_insn *second) {
    return !memcmp(first, second, sizeof(bpf_insn));
}

static InstPtr
smallInstructionLift(BytecodeData &bytecodeData, size_t startIdx, size_t remainingSize, size_t &consumedSize) {

    static const uint8_t DUMMY_REG = 0;
    static const bpf_imm32_type DUMMY_IMM = 0;
    static bpf_insn ldImm64ByteCode[] = {((struct bpf_insn) {
            .code  = BPF_LD | BPF_DW | BPF_IMM,
            .dst_reg = DUMMY_REG,
            .src_reg = DUMMY_REG,
            .off   = 0,
            .imm   = (__u32) (DUMMY_IMM)}),
                                         ((struct bpf_insn) {
                                                 .code  = 0, /* zero is reserved opcode */
                                                 .dst_reg = 0,
                                                 .src_reg = 0,
                                                 .off   = 0,
                                                 .imm   = ((__u64) (DUMMY_IMM)) >> 32})};
    static const size_t minSize = 2;
    if (remainingSize < minSize) {
        return nullptr;
    }
    if (bytecodeData[startIdx].code != ldImm64ByteCode[0].code ||
        bytecodeData[startIdx + 1].code != ldImm64ByteCode[1].code)
        return nullptr;

    if (bytecodeData[startIdx].off != 0 ||
        bytecodeData[startIdx + 1].code != 0 ||
        bytecodeData[startIdx + 1].dst_reg != 0 ||
        bytecodeData[startIdx + 1].src_reg != 0 ||
        bytecodeData[startIdx + 1].off != 0) {
        printf("warning: unlikely ld imm64 case\n");
        return nullptr;
    }
    Register dst = parseRegister(bytecodeData[startIdx].dst_reg);
    assert(bytecodeData[startIdx].off == 0);
    bpf_imm32_type imm_low = bytecodeData[startIdx].imm;
    bpf_imm32_type imm_high = bytecodeData[startIdx + 1].imm;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshift-count-overflow"
    bpf_imm64_type imm64 = imm_low + (imm_high << 32U);
#pragma clang diagnostic pop
    consumedSize = minSize;
    return std::make_unique<LoadImm64Inst>(dst, imm64);
}

static InstPtr
largeInstructionLift(BytecodeData &bytecodeData, size_t startIdx, size_t remainingSize, Register map_fd_reg,
                     size_t &consumedSize) {

    static const uint8_t DUMMY_REG = 0;
    static bpf_insn LoadMapAddressByteCode[] = {BPF_MOV64_REG(BPF_REG_1, DUMMY_MAP_FD),
                                                BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                                                BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
                                                BPF_ST_MEM(BPF_W, BPF_REG_10, -4, DUMMY_OFFSET),
                                                BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                                                BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
                                                BPF_EXIT_INSN(),
                                                BPF_MOV64_REG((DUMMY_REG), BPF_REG_0),
                                                BPF_MOV64_IMM(BPF_REG_0, 0)};

    static bpf_insn LoadMapByteCode[] = {BPF_MOV64_REG(BPF_REG_1, DUMMY_MAP_FD),
                                         BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                                         BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
                                         BPF_ST_MEM(BPF_W, BPF_REG_10, -4, DUMMY_OFFSET),
                                         BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                                         BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
                                         BPF_EXIT_INSN(),
                                         BPF_LDX_MEM(BPF_DW, DUMMY_REG, BPF_REG_0, 0),
                                         BPF_MOV64_IMM(BPF_REG_0, 0)};

    static const size_t minSize = 9;
    if (remainingSize < minSize) {
        return nullptr;
    }

//    size_t cursor = startIdx;
//    while (cursor + minSize <= startIdx + remainingSize) {
    bool misMatch[] = {false, false};
    bool found = true;
    for (int i = 0; i < 9; ++i) {
        if (LoadMapAddressByteCode[i].code != bytecodeData[startIdx + i].code) {
            misMatch[0] = true;
        }
        if (LoadMapByteCode[i].code != bytecodeData[startIdx + i].code) {
            misMatch[1] = true;
        }
        if (misMatch[0] & misMatch[1]) {
            found = false;
            break;
        }
    }
    if (found) {
        assert(misMatch[0] ^ misMatch[1]);
        // validate generic form
        if (!isSameBytecode(&LoadMapAddressByteCode[1], &bytecodeData[startIdx + 1])) {
            return nullptr;
        }
        if (!isSameBytecode(&LoadMapAddressByteCode[2], &bytecodeData[startIdx + 2])) {
            return nullptr;
        }
        if (!isSameBytecode(&LoadMapAddressByteCode[4], &bytecodeData[startIdx + 4])) {
            return nullptr;
        }
        if (!isSameBytecode(&LoadMapAddressByteCode[5], &bytecodeData[startIdx + 5])) {
            return nullptr;
        }
        if (!isSameBytecode(&LoadMapAddressByteCode[6], &bytecodeData[startIdx + 6])) {
            return nullptr;
        }

        bool isAddress = false;
        if (!misMatch[0]) {
            // address load, assume some instructions are in same form.
            if (LoadMapAddressByteCode[7].src_reg != bytecodeData[startIdx + 7].src_reg) {
                return nullptr;
            }
            isAddress = true;
        } else {
            assert(!misMatch[1]);
            if (LoadMapAddressByteCode[7].src_reg != bytecodeData[startIdx + 7].src_reg
                || LoadMapAddressByteCode[7].off != bytecodeData[startIdx + 7].off) {
                return nullptr;
            }
            isAddress = false;
        }
        bpf_imm32_type offset = bytecodeData[startIdx + 3].imm;
        assert(isValidRegister(bytecodeData[startIdx + 7].dst_reg));
        auto dst = static_cast<Register>(bytecodeData[startIdx + 7].dst_reg);
        consumedSize = minSize;
        return std::make_unique<LoadMapInst>(offset, dst, map_fd_reg, isAddress);
    }
    return nullptr;
//    }
}

static InstPtr controlFlowInstructionList(BytecodeData &bytecodeData, size_t index) {
    assert(isControlFlowInstruction(bytecodeData[index].code));

    auto &&insn = bytecodeData[index];
    auto &opcode = insn.code;
    BitWidth width;

    // ExitInst
    if (opcode == (BPF_JMP | BPF_EXIT)) {
        assert(insn.imm == 0 && insn.src_reg == 0 && insn.dst_reg == 0 && insn.off == 0);
        return std::make_unique<ExitInst>();
    }

    // TODO : BranchInst

    if (opcode & (BPF_JMP | BPF_X)) {
        width = BitWidth::bit64;
        auto pureOpcode = opcode & (~(BPF_JMP | BPF_X));
        assert(isValidBranchOpcode(pureOpcode));
        auto branchOpcode = static_cast<BranchOpcode>(pureOpcode);
        return std::make_unique<BranchInst>(branchOpcode, parseRegister(insn.dst_reg), parseRegister(insn.src_reg),
                                            insn.off, width);
    } else if (opcode & (BPF_JMP32 | BPF_X)) {
        width = BitWidth::bit32;
        auto pureOpcode = opcode & (~(BPF_JMP32 | BPF_X));
        assert(isValidBranchOpcode(pureOpcode));
        auto branchOpcode = static_cast<BranchOpcode>(pureOpcode);
        return std::make_unique<BranchInst>(branchOpcode, parseRegister(insn.dst_reg), parseRegister(insn.src_reg),
                                            insn.off, width);
    } else if (opcode & (BPF_JMP | BPF_K)) {
        width = BitWidth::bit64;
        auto pureOpcode = opcode & (~(BPF_JMP | BPF_K));
        assert(insn.src_reg == 0);

        assert(isValidBranchOpcode(pureOpcode));
        auto branchOpcode = static_cast<BranchOpcode>(pureOpcode);
        return std::make_unique<BranchInst>(branchOpcode, parseRegister(insn.dst_reg), insn.imm,
                                            insn.off, width);
    } else if (opcode & (BPF_JMP32 | BPF_K)) {
        width = BitWidth::bit32;
        auto pureOpcode = opcode & (~(BPF_JMP32 | BPF_K));
        assert(insn.src_reg == 0);
        assert(isValidBranchOpcode(pureOpcode));
        auto branchOpcode = static_cast<BranchOpcode>(pureOpcode);
        return std::make_unique<BranchInst>(branchOpcode, parseRegister(insn.dst_reg), insn.imm,
                                            insn.off, width);
    }
    assert(false && "No valid control instruction is found.");
    return nullptr;
}

static InstPtr normalInstructionLift(BytecodeData &bytecodeData, size_t index) {
    auto &&insn = bytecodeData[index];
    auto &opcode = insn.code;
    BitWidth width;

    // mov instruction
    // BPF_ALU64
    if (opcode == (BPF_ALU64 | BPF_MOV | BPF_X)) {
        width = BitWidth::bit64;
        assert(insn.off == 0 && insn.imm == 0);
        return std::make_unique<MovInst>(parseRegister(insn.dst_reg), parseRegister(insn.src_reg), width);
    } else if (opcode == (BPF_ALU | BPF_MOV | BPF_X)) {
        width = BitWidth::bit32;
        assert(insn.off == 0 && insn.imm == 0);
        return std::make_unique<MovInst>(parseRegister(insn.dst_reg), parseRegister(insn.src_reg), width);
    } else if (opcode == (BPF_ALU64 | BPF_MOV | BPF_K)) {
        width = BitWidth::bit64;
        assert(insn.off == 0 && insn.src_reg == 0);
        return std::make_unique<MovInst>(parseRegister(insn.dst_reg), insn.imm, width);
    } else if (opcode == (BPF_ALU | BPF_MOV | BPF_K)) {
        width = BitWidth::bit32;
        assert(insn.off == 0 && insn.src_reg == 0);
        return std::make_unique<MovInst>(parseRegister(insn.dst_reg), insn.imm, width);
    }

    // Alu instruction
    if ((opcode & (BPF_ALU64 | BPF_X)) && insn.off == 0 && insn.imm == 0) {
        width = BitWidth::bit64;
        assert(insn.off == 0 && insn.imm == 0);
        auto pureOpcode = opcode & (~(BPF_ALU64 | BPF_X));
        assert(isValidAluOpcode(pureOpcode));
        auto aluOpcode = static_cast<AluOpcode>(pureOpcode);
        return std::make_unique<AluInst>(aluOpcode, parseRegister(insn.dst_reg), parseRegister(insn.src_reg), width);
    } else if ((opcode & (BPF_ALU | BPF_X)) && insn.off == 0 && insn.imm == 0) {
        width = BitWidth::bit32;
        assert(insn.off == 0 && insn.imm == 0);
        auto pureOpcode = opcode & (~(BPF_ALU | BPF_X));
        assert(isValidAluOpcode(pureOpcode));
        auto aluOpcode = static_cast<AluOpcode>(pureOpcode);
        return std::make_unique<AluInst>(aluOpcode, parseRegister(insn.dst_reg), parseRegister(insn.src_reg), width);
    } else if ((opcode & (BPF_ALU64 | BPF_K)) && insn.off == 0 && insn.src_reg == 0) {
        width = BitWidth::bit64;
        assert(insn.off == 0 && insn.src_reg == 0);
        auto pureOpcode = opcode & (~(BPF_ALU64 | BPF_K));
        assert(isValidAluOpcode(pureOpcode));
        auto aluOpcode = static_cast<AluOpcode>(pureOpcode);
        return std::make_unique<AluInst>(aluOpcode, parseRegister(insn.dst_reg), insn.imm, width);
    } else if ((opcode & (BPF_ALU | BPF_K)) && insn.off == 0 && insn.src_reg == 0) {
        width = BitWidth::bit32;
        assert(insn.off == 0 && insn.src_reg == 0);
        auto pureOpcode = opcode & (~(BPF_ALU | BPF_K));
        assert(isValidAluOpcode(pureOpcode));
        auto aluOpcode = static_cast<AluOpcode>(pureOpcode);
        return std::make_unique<AluInst>(aluOpcode, parseRegister(insn.dst_reg), insn.imm, width);
    }

    // StoreInst
    if ((opcode & (BPF_STX | BPF_MEM)) || opcode & (BPF_ST | BPF_MEM)) {
        width = BitWidth::bit64;

        if ((opcode & (BPF_STX | BPF_MEM)) && insn.imm == 0) {
            auto regSizeOpcode = opcode & (~(BPF_STX | BPF_MEM));
            if (isValidTrivialBitWidth(regSizeOpcode)) {
                width = parseBitWidth(regSizeOpcode);
//                assert(insn.imm == 0);
                return std::make_unique<StoreInst>(parseRegister(insn.dst_reg), parseRegister(insn.src_reg), insn.off,
                                                   width);

            }
        } else if ((opcode & (BPF_ST | BPF_MEM)) && insn.src_reg == 0) {
            auto immSizeOpcode = opcode & (~(BPF_ST | BPF_MEM));
            if (isValidTrivialBitWidth(immSizeOpcode)) {
                width = parseBitWidth(immSizeOpcode);
//                assert(insn.src_reg == 0);
                return std::make_unique<StoreInst>(parseRegister(insn.dst_reg), insn.imm, insn.off,
                                                   width);
            }
        }
    }

    // load memory instruction
    if (opcode & (BPF_LDX | BPF_MEM)) {
        width = BitWidth::bit64;
        assert(insn.imm == 0);
        auto sizeOpcode = opcode & (~(BPF_LDX | BPF_MEM));
        bool valid = true;
        switch (sizeOpcode) {
            case BPF_B:
                width = BitWidth::bit8;
                break;
            case BPF_H:
                width = BitWidth::bit16;
                break;
            case BPF_W:
                width = BitWidth::bit32;
                break;
            case BPF_DW:
                width = BitWidth::bit64;
                break;
            default:
//                assert(false && "Unknown bit width.");
                valid = false;
                break;
        }
        if (valid)
            return std::make_unique<LoadInst>(parseRegister(insn.dst_reg), parseRegister(insn.src_reg), insn.off,
                                              width);
    }

    // TODO : LoadImm64Inst
//    if (opcode & ())

    // MemXAddInst
    if (opcode & (BPF_STX | BPF_XADD)) {
        width = BitWidth::bit64;
        assert(insn.imm == 0);
        auto sizeOpcode = opcode & (~(BPF_STX | BPF_XADD));
        bool valid = true;
        switch (sizeOpcode) {
            case BPF_B:
                width = BitWidth::bit8;
                break;
            case BPF_H:
                width = BitWidth::bit16;
                break;
            case BPF_W:
                width = BitWidth::bit32;
                break;
            case BPF_DW:
                width = BitWidth::bit64;
                break;
            default:
//                assert(false && "Unknown bit width.");
                valid = false;
                break;
        }
        if (valid)
            return std::make_unique<MemXAddInst>(parseRegister(insn.dst_reg), parseRegister(insn.src_reg), insn.off,
                                                 width);
    }

    assert(false && "Unknown instruction found");
    return nullptr;
}


bool LiftBasicBlock(BytecodeData &bytecodeData, Module *module) {

    size_t lastBlockEndAddress = 0;
    auto reservedReg = module->getReservedRegisters().getMapFdRegister();

    class BranchBlockInfo {
    public:
        BranchBlockInfo(size_t targetAddress, BranchOpcode opcode, const Variable &dst, const Variable &src,
                        BitWidth bitWidth) : targetAddress(targetAddress), opcode(opcode), dst(dst), src(src),
                                             bitWidth(bitWidth) {}

        size_t targetAddress;
        BranchOpcode opcode;
        Variable dst;
        Variable src;
        BitWidth bitWidth;
    };
    std::vector<BasicBlockPtr> cachedBlocks;
    std::map<BasicBlock *, std::shared_ptr<BranchBlockInfo>> fastBlockAddressMap;
    std::map<size_t, BasicBlock *> fastAddressBlockMap;

    assert(isControlFlowInstruction(bytecodeData.back().code));
    assert(bytecodeData.size() > 2);
    // identify header:
    size_t headerSize = 0;
    auto ldImm64Inst = smallInstructionLift(bytecodeData, 0, bytecodeData.size(), headerSize);
//    assert(ldImm64Inst && "Header is needed!");
    if (ldImm64Inst) {
        module->set_header_status(true);
    }
    if (ldImm64Inst) {
        assert(ldImm64Inst->instType == InstructionType::LoadImm64Inst);
        auto casted = dynamic_cast<LoadImm64Inst *>(ldImm64Inst.get());
//        printf("found header\n");
        module->getReservedRegisters().setMapFdRegister(casted->getDst().getReg());
//        cursor += consumedSize;
//        currentBlock->add(std::move(ldImm64Inst));
//        continue;
    }

    lastBlockEndAddress = headerSize;
    for (unsigned int i = headerSize; i < bytecodeData.size(); ++i) {
        size_t consumedSize = -1;
        // look ahead the large instruction ( avoid splitting control flow )
        if (largeInstructionLift(bytecodeData, i, bytecodeData.size() - i, reservedReg, consumedSize)) {
            i += consumedSize - 1;
            continue;
        }

        if (isControlFlowInstruction(bytecodeData[i].code)) {
            auto currentBlock = createBasicBlock();
            // lift non-terminator
            auto cursor = lastBlockEndAddress;
            consumedSize = -1;
            size_t remainingSizeWithoutTerm = i - cursor;
            while (cursor < i) {
                auto loadMapInst = largeInstructionLift(bytecodeData, cursor, remainingSizeWithoutTerm, reservedReg,
                                                        consumedSize);
                if (loadMapInst) {
//                    printf("found loadMapInst\n");
                    cursor += consumedSize;
                    currentBlock->add(std::move(loadMapInst));
                    continue;
                }
                auto ldImm64Inst = smallInstructionLift(bytecodeData, cursor, remainingSizeWithoutTerm, consumedSize);
                if (ldImm64Inst) {
//                    printf("found ldImm64Inst\n");
                    cursor += consumedSize;
                    currentBlock->add(std::move(ldImm64Inst));
                    continue;
                }

                // normal instruction parse:
                {
                    assert(!isControlFlowInstruction(bytecodeData[cursor].code));
                    auto inst = normalInstructionLift(bytecodeData, cursor);
//                    std::cout << *inst.get() << std::endl;
                    assert(inst);
                    currentBlock->add(std::move(inst));
                    cursor++;
                }
            }
            assert(cursor == i);
            // parse terminator
//            auto terminator = normalInstructionLift(bytecodeData, i);
            auto terminator = controlFlowInstructionList(bytecodeData, i);
            assert(terminator);
            if (terminator->instType == InstructionType::ExitInst) {
//                printf("exit inst\n");
                currentBlock->setExitTerminator();
            } else {
                assert(terminator->instType == InstructionType::BranchInst);
//                printf("branch inst\n");
                auto branchTerm = dynamic_cast<BranchInst *>(terminator.get());
                assert(fastBlockAddressMap.find(currentBlock.get()) == fastBlockAddressMap.end());
//                BranchBlockInfo info = {
//                        .targetAddress = i + 1 + branchTerm->getOffset(),
//                        .opcode = branchTerm->getOpcode(),
//                        .dst = branchTerm->getDst(),
//                        .src = branchTerm->getSrc(),
//                        .bitWidth = branchTerm->getBitWidth(),
//                };
                fastBlockAddressMap[currentBlock.get()] = std::make_shared<BranchBlockInfo>(
                        i + 1 + branchTerm->getOffset(), branchTerm->getOpcode(), branchTerm->getDst(),
                        branchTerm->getSrc(),
                        branchTerm->getBitWidth());
            }

            assert(fastAddressBlockMap.find(lastBlockEndAddress) == fastAddressBlockMap.end());
            fastAddressBlockMap[lastBlockEndAddress] = currentBlock.get();


            currentBlock->setAddress(lastBlockEndAddress);

            cachedBlocks.push_back(std::move(currentBlock));

            lastBlockEndAddress = i + 1;
        }
    }

    assert(lastBlockEndAddress == bytecodeData.size());

    for (auto &block: cachedBlocks) {
        if (block->isExitTerminator()) {
            // TODO : memory ref problem maybe
            module->addBasicBlock(std::move(block));
        } else {
            assert(fastBlockAddressMap.find(block.get()) != fastBlockAddressMap.end());
            auto targetInfo = fastBlockAddressMap[block.get()];
            assert(fastAddressBlockMap.find(targetInfo->targetAddress) != fastAddressBlockMap.end());
            auto targetBlock = fastAddressBlockMap[targetInfo->targetAddress];
            block->setBranchTerminator(targetInfo->opcode, targetInfo->dst, targetInfo->src, nullptr, targetBlock,
                                       targetInfo->bitWidth);
            module->addBasicBlock(std::move(block));
        }
    }
    return true;
}

std::unique_ptr<Module> Lift(unsigned char *data, size_t size) {
//    if (size % sizeof(bpf_insn)) {
//        return nullptr;
//    }
    assert(!(size % sizeof(bpf_insn)));
    BytecodeData bytecodeData;

    size_t insn_size = size / sizeof(bpf_insn);
    auto insn_ptr = (bpf_insn *) data;
    for (unsigned int i = 0; i < insn_size; ++i) {
        bytecodeData.push_back(insn_ptr[i]);
    }

    ReservedRegisters reservedRegisters = quickSearchReservedReg(bytecodeData);
    auto module = std::make_unique<Module>(reservedRegisters, DUMMY_MAP_FD, false);

    LiftBasicBlock(bytecodeData, module.get());
    return std::move(module);
}

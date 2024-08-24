#include "Instruction.h"

BasicBlock *Instruction::getBasicBlock() const {
    return basicBlock;
}

void Instruction::setBasicBlock(BasicBlock *block) {
    Instruction::basicBlock = block;
}

bool isValidAluOpcode(uint8_t opcode) {
    if (opcode > 0xa0U) {
        return false;
    }
    if (opcode % 0x10U) {
        return false;
    }
    return true;
}

bool isValidBranchOpcode(uint8_t opcode) {
    if (opcode > 0xd0U) {
        return false;
    }
    if (opcode % 0x10U) {
        return false;
    }
    if (opcode == BPF_CALL) {
        return false;
    }
    return true;
}

bool operator==(const bpf_insn &lhs, const bpf_insn &rhs) {
    return lhs.code == rhs.code
           && lhs.src_reg == rhs.src_reg
           && lhs.dst_reg == rhs.dst_reg
           && lhs.off == rhs.off
           && lhs.imm == rhs.imm;
}

std::string getAluName(AluOpcode opcode) {
    switch (opcode) {
        case AluOpcode::ADD:
            return "+";
        case AluOpcode::SUB:
            return "-";
        case AluOpcode::MUL:
            return "*";
        case AluOpcode::DIV:
            return "/";
        case AluOpcode::SDIV:
            return "(sdiv)/";
        case AluOpcode::OR:
            return "|";
        case AluOpcode::AND:
            return "&";
        case AluOpcode::LSH:
            return "<<";
        case AluOpcode::ARSH:
            return "(asrh)>>";
        case AluOpcode::RSH:
            return ">>";
        case AluOpcode::NEG:
            return "~";
        case AluOpcode::MOD:
            return "%";
        case AluOpcode::XOR:
            return "^";
        case AluOpcode::TO_LE:
            return "(htole)";
        case AluOpcode::TO_BE:
            return "(htobe)";
    }
}

std::string getRegName(Register reg) {
    return "r" + std::to_string(to_underlying(reg));
}

std::string getBranchOpcodeName(BranchOpcode opcode) {
    switch (opcode) {
        case BranchOpcode::JA:
            assert(false && "jmp should parsed individually.");
        case BranchOpcode::JEQ:
            return "==";
        case BranchOpcode::JGT:
            return ">";
        case BranchOpcode::JGE:
            return ">=";
        case BranchOpcode::JNE:
            return "!=";
        case BranchOpcode::JLT:
            return "<";
        case BranchOpcode::JLE:
            return "<=";
        case BranchOpcode::JSET:
            return "&";
        case BranchOpcode::JSGT:
            return ">(signed)";
        case BranchOpcode::JSGE:
            return ">=(signed)";
        case BranchOpcode::JSLT:
            return "<(signed)";
        case BranchOpcode::JSLE:
            return "<=(signed)";
    }
}

std::string getBitWidthName(BitWidth width) {
    switch (width) {
        case BitWidth::bit8:
            return "(int8_t)";
        case BitWidth::bit16:
            return "(int16_t)";
        case BitWidth::bit32:
            return "(int32_t)";
        case BitWidth::bit64:
            return "(int64_t)";
    }
}

std::string getUnsignedBitWidthName(BitWidth width) {
    switch (width) {
        case BitWidth::bit8:
            return "(uint8_t)";
        case BitWidth::bit16:
            return "(uint16_t)";
        case BitWidth::bit32:
            return "(uint32_t)";
        case BitWidth::bit64:
            return "(uint64_t)";
    }
}

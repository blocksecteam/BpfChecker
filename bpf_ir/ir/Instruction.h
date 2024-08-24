#ifndef BPF_IR_INSTRUCTION_H
#define BPF_IR_INSTRUCTION_H

#include "bpf-instruction.h"
#include <cstdint>
#include <cassert>
#include <type_traits>
#include <cstdio>
#include <memory>
#include <string>
#include "ir.h"

bool operator==(const struct bpf_insn &lhs, const struct bpf_insn &rhs);

template<typename E>
constexpr typename std::underlying_type<E>::type to_underlying(E e) noexcept {
    return static_cast<typename std::underlying_type<E>::type>(e);
}

using bpf_insn_type = struct bpf_insn;
using bpf_macro_ele = unsigned char;

using bpf_map_fd_type = uint32_t;
using bpf_imm64_type = uint64_t;
using bpf_imm32_type = uint32_t;
using bpf_offset_type = int16_t;

enum class Register : unsigned char {
    REG_0 = 0,
    REG_1,
    REG_2,
    REG_3,
    REG_4,
    REG_5,
    REG_6,
    REG_7,
    REG_8,
    REG_9,
    REG_10,
    MAX_REG,
//    REG_0 = BPF_REG_0,
//    REG_1 = BPF_REG_1,
//    REG_2 = BPF_REG_2,
//    REG_3 = BPF_REG_3,
//    REG_4 = BPF_REG_4,
//    REG_5 = BPF_REG_5,
//    REG_6 = BPF_REG_6,
//    REG_7 = BPF_REG_7,
//    REG_8 = BPF_REG_8,
//    REG_9 = BPF_REG_9,
//    REG_10 = BPF_REG_10,
//    MAX_REG = __MAX_BPF_REG,
};

typedef std::vector<Register> Registers;

std::string getRegName(Register reg);

enum class AluOpcode {
    ADD = BPF_ADD,
    SUB = BPF_SUB,
    MUL = BPF_MUL,
    DIV = BPF_DIV,
    SDIV = BPF_SDIV,
    OR = BPF_OR,
    AND = BPF_AND,
    LSH = BPF_LSH,
    ARSH = BPF_ARSH,
    RSH = BPF_RSH,
    NEG = BPF_NEG,
    MOD = BPF_MOD,
    XOR = BPF_XOR,
    TO_LE = BPF_TO_LE | BPF_END,
    TO_BE = BPF_TO_BE | BPF_END,
};

std::string getAluName(AluOpcode opcode);

bool isValidAluOpcode(uint8_t opcode);

/// https://blog.csdn.net/qq_14978113/article/details/80488711

enum class BranchOpcode {
    JA = BPF_JA, // always pc += k
    JEQ = BPF_JEQ, // ==
    JGT = BPF_JGT, // >
    JGE = BPF_JGE, // >=
    JNE = BPF_JNE, // !=
    JLT = BPF_JLT, // <
    JLE = BPF_JLE, // <=
    JSET = BPF_JSET, // signed ==
    JSGT = BPF_JSGT, // signed >
    JSGE = BPF_JSGE, // signed >=
    JSLT = BPF_JSLT, // signed <
    JSLE = BPF_JSLE, // signed <=
//    CALL = BPF_CALL,
};

std::string getBranchOpcodeName(BranchOpcode opcode);

constexpr std::initializer_list<BranchOpcode> allBranchOpcode = {
        BranchOpcode::JA,
        BranchOpcode::JEQ,
        BranchOpcode::JGT,
        BranchOpcode::JGE,
        BranchOpcode::JNE,
        BranchOpcode::JLT,
        BranchOpcode::JLE,
        BranchOpcode::JSET,
        BranchOpcode::JSGT,
        BranchOpcode::JSGE,
        BranchOpcode::JSLT,
        BranchOpcode::JSLE,
};


bool isValidBranchOpcode(uint8_t opcode);

enum class VariableType {
    Register,
    Imm32,
    Imm64
};

enum class InstructionType {
    AluInst,
    MovInst,
    LoadInst,
    LoadImm64Inst,
    LoadPacketInst,
    LoadMapInst,
    StoreInst,
    MemXAddInst,
    BranchInst,
    CallInst,
    ExitInst,

};

enum class BitWidth {
    bit8,
    bit16,
    bit32,
    bit64,
};

std::string getBitWidthName(BitWidth width);

std::string getUnsignedBitWidthName(BitWidth width);

class Variable {
public:
    Variable(Register reg) : reg(reg), type(VariableType::Register) {

    }

//    Variable(bpf_imm64_type imm64) : imm64(imm64), type(VariableType::Imm64) {}

    Variable(bpf_imm32_type imm32) : imm32(imm32), type(VariableType::Imm32) {
//        printf("\ntrigger imm32 %d\n",imm32);
    }

    [[nodiscard]] bool isRegister() const {
        return type == VariableType::Register;
    }

    [[nodiscard]] bool isImmediate() const {
        return this->isImm32() || this->isImm64();
    }

    [[nodiscard]] bool isImm32() const {
        return type == VariableType::Imm32;
    }

    void setImm32(bpf_imm32_type target_imm) {
        assert(this->isImm32());
        imm32 = target_imm;
    }

    [[nodiscard]] bool isImm64() const {
        return type == VariableType::Imm64;
    }

    [[nodiscard]] Register getReg() const {
        assert(this->isValid());
        assert(this->isRegister());
        assert(this->isValid());
        return reg;
    }

    [[nodiscard]] bpf_imm64_type getImm64() const {
        assert(this->isValid());
        assert(this->isImm64());
        return imm64;
    }

    [[nodiscard]] bpf_imm32_type getImm32() const {
        assert(this->isValid());
        assert(this->isImm32());
        return imm32;
    }

    [[nodiscard]] bpf_imm64_type getGenericImmValue() const {
        assert(this->isImm64() || this->isImm32());
        if (isImm32()) {
            return imm32;
        } else {
            return imm64;
        }
    }


    void setAsInvalid() {
        this->isInvalidVariable = true;
    }

    void setAsValid() {
        this->isInvalidVariable = false;
    }

    [[nodiscard]] bool isInvalid() const {
        return this->isInvalidVariable;
    }

    [[nodiscard]] bool isValid() const {
        return !this->isInvalidVariable;
    }

    [[nodiscard]] std::string toString() const {
        assert(this->isValid());
        if (this->isRegister()) {
            return getRegName(this->getReg());
        } else {
            return std::to_string(this->getGenericImmValue());
        }
    }

    friend std::ostream &operator<<(std::ostream &os, const Variable &variable) {
        assert(variable.isValid());
        os << variable.toString();
        return os;
    }

private:
    VariableType type;
    union {
        Register reg;
        bpf_imm64_type imm64;
        bpf_imm32_type imm32;
    };
    bool isInvalidVariable = false;
};

class Instruction {
public:
    virtual BytecodeData CodeGen() = 0;

    virtual ~Instruction() = default;

    InstructionType instType;

    [[nodiscard]] BasicBlock *getBasicBlock() const;

    void setBasicBlock(BasicBlock *block);

    virtual size_t getBytecodeSize() {
        return 1;
    }

    virtual void dump(std::ostream &stream) const = 0;

    friend std::ostream &operator<<(std::ostream &os, const Instruction &variable) {
        variable.dump(os);
        return os;
    }

protected:
    BasicBlock *basicBlock;


};

class AluInst : public Instruction {
public:
    AluInst(AluOpcode opcode, Variable dst, Variable src, BitWidth width) : opcode(opcode), src(src),
                                                                            dst(dst),
                                                                            bitWidth(width) {
//        assert(!(opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE));
        // NOTE: another constructor handles TO_BE || TO_LE specifically
        if (opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE) {
            // same logic with another constructor
            assert(dst.isRegister());
            assert(width != BitWidth::bit8);
            src.setAsInvalid();
            // note that only endianness related opcode doesn't require src variable.
            assert(opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE);
            instType = InstructionType::AluInst;
            return;
        }
        assert(dst.isRegister());
        assert(src.isRegister() || src.isImm32());
        assert(width == BitWidth::bit64 || width == BitWidth::bit32);
        // note that BPF_NEG only support imm.
        assert(!(opcode == AluOpcode::NEG && src.isRegister()));

        instType = InstructionType::AluInst;
    }

    AluInst(AluOpcode opcode, Variable dst, BitWidth width) : opcode(opcode),
                                                              src(0),
                                                              dst(dst),
                                                              bitWidth(width) {
        assert(dst.isRegister());
        assert(width != BitWidth::bit8);
        src.setAsInvalid();
        // note that only endianness related opcode doesn't require src variable.
        assert(opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE);
        instType = InstructionType::AluInst;
    }

//    virtual bpf_insn_type CodeGen() override;
//    bpf_insn_type CodeGen();
    BytecodeData CodeGen() override {

        __u8 macro_opcode = to_underlying(opcode);

        if (opcode == AluOpcode::TO_BE || opcode == AluOpcode::TO_LE) {
            assert(bitWidth != BitWidth::bit8);
            /* dst = htole(dst) */
            /* dst = htobe(dst) */
//            case BPF_ALU | BPF_END | BPF_FROM_LE:
//            case BPF_ALU | BPF_END | BPF_FROM_BE:
            __u8 macro_dst = to_underlying(dst.getReg());
            // see
            // https://elixir.bootlin.com/linux/latest/source/kernel/bpf/verifier.c#L8241
            // actually we should ensure that
            //      insn->src_reg == BPF_REG_0 && insn->off == 0
            // anyway, BPF_ALU32_IMM meets that requirements.
            bpf_imm32_type bit_width_as_imm = -1;
            switch (bitWidth) {
                case BitWidth::bit8:
                    assert(false && "doesn't support 8 bit width.");
                    break;
                case BitWidth::bit16:
                    bit_width_as_imm = 16;
                    break;
                case BitWidth::bit32:
                    bit_width_as_imm = 32;
                    break;
                case BitWidth::bit64:
                    bit_width_as_imm = 64;
                    break;
            }
            // This is a hacky way to integrate these opcodes to normal alu code gen
            // as BPF_K itself is 0.
            return {((struct bpf_insn) {
                    .code  = BPF_ALU | macro_opcode | BPF_K,
                    .dst_reg = macro_dst,
                    .src_reg = 0,
                    .off   = 0,
                    .imm   = bit_width_as_imm})};
//            return {BPF_ALU32_IMM(macro_opcode, macro_dst, bit_width_as_imm)};
        }


        // note that BPF_NEG only support imm.

        if (src.isRegister()) {
            __u8 macro_dst = to_underlying(dst.getReg());
            __u8 macro_src = to_underlying(src.getReg());
            if (this->bitWidth == BitWidth::bit64) {
                return {BPF_ALU64_REG(macro_opcode, macro_dst, macro_src)};
            } else {
                return {BPF_ALU32_REG(macro_opcode, macro_dst, macro_src)};
            }
        } else {
            assert(src.isImm32() && "Only 32bit integer is supported in bpf.");

            __u8 macro_dst = to_underlying(dst.getReg());
            bpf_imm32_type macro_src = src.getImm32();
            if (this->bitWidth == BitWidth::bit64) {
                return {BPF_ALU64_IMM(macro_opcode, macro_dst, macro_src)};
            } else {
                return {BPF_ALU32_IMM(macro_opcode, macro_dst, macro_src)};
            }
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const AluInst &inst) {
        if (inst.opcode == AluOpcode::TO_LE) {
            stream << inst.dst << " " << "=" << getBitWidthName(inst.bitWidth) << " htole(" << inst.dst << ")";
            return stream;
        } else if (inst.opcode == AluOpcode::TO_BE) {
            stream << inst.dst << " " << "=" << getBitWidthName(inst.bitWidth) << " htobe(" << inst.dst << ")";
            return stream;
        }

        stream << inst.dst << " " << getAluName(inst.opcode) << "=" << getBitWidthName(inst.bitWidth) << inst.src;
//        stream << inst.dst << " " << getAluName(inst.opcode) << "=" << inst.src;
        return stream;
    }

    void setOpcode(AluOpcode targetOpcode) {
        if (targetOpcode == AluOpcode::TO_BE || targetOpcode == AluOpcode::TO_LE) {
            this->src.setAsInvalid();
        } else {
            this->src.setAsValid();
        }
        this->opcode = targetOpcode;
    }

    void setBitWidth(BitWidth targetBitWidth) {
        this->bitWidth = targetBitWidth;
    }

    Variable &getSrc() {
        return this->src;
    }

    Variable &getDst() {
        return this->dst;
    }

private:
    AluOpcode opcode;
    Variable src;
    Variable dst;
    BitWidth bitWidth;
};

class MovInst : public Instruction {
public:
    MovInst(Variable dst, Variable src, BitWidth width) : src(src),
                                                          dst(dst),
                                                          bitWidth(width) {
        assert(dst.isRegister());
        assert(src.isRegister() || src.isImm32());
        assert(width == BitWidth::bit64 || width == BitWidth::bit32);
        instType = InstructionType::MovInst;
    }

    BytecodeData CodeGen() override {
        if (src.isRegister()) {
            __u8 macro_dst = to_underlying(dst.getReg());
            __u8 macro_src = to_underlying(src.getReg());
            if (this->bitWidth == BitWidth::bit64) {
                return {BPF_MOV64_REG(macro_dst, macro_src)};
            } else {
                return {BPF_MOV32_REG(macro_dst, macro_src)};
            }
        } else {
            assert(src.isImm32() && "Only 32bit integer is supported in bpf.");

            __u8 macro_dst = to_underlying(dst.getReg());
            bpf_imm32_type macro_src = src.getImm32();
            if (this->bitWidth == BitWidth::bit64) {
                return {BPF_MOV64_IMM(macro_dst, macro_src)};
            } else {
                return {BPF_MOV32_IMM(macro_dst, macro_src)};
            }
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const MovInst &inst) {
        stream << inst.dst << "=" << getBitWidthName(inst.bitWidth) << inst.src;
        return stream;
    }

    Variable &getSrc() {
        return this->src;
    }

    Variable &getDst() {
        return this->dst;
    }

private:
    Variable src;
    Variable dst;
    BitWidth bitWidth;
};

class LoadInst : public Instruction {
public:
    // dst = [src + offset] with 64bit value
    LoadInst(Variable dst, Variable src, bpf_offset_type offset, BitWidth bitWidth) : src(src),
                                                                                      dst(dst),
                                                                                      offset(offset),
                                                                                      bitWidth(bitWidth) {
        assert(dst.isRegister());
        assert(src.isRegister());
        instType = InstructionType::LoadInst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        __u8 macro_src = to_underlying(src.getReg());
        switch (bitWidth) {
            case BitWidth::bit8:
                return {BPF_LDX_MEM(BPF_B, macro_dst, macro_src, offset)};
            case BitWidth::bit16:
                return {BPF_LDX_MEM(BPF_H, macro_dst, macro_src, offset)};
            case BitWidth::bit32:
                return {BPF_LDX_MEM(BPF_W, macro_dst, macro_src, offset)};
            case BitWidth::bit64:
                return {BPF_LDX_MEM(BPF_DW, macro_dst, macro_src, offset)};
        }

    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const LoadInst &inst) {
        stream << inst.dst << "=" << "*" << getUnsignedBitWidthName(inst.bitWidth) <<
               "(" << inst.src << " + " << inst.offset << ")";
        return stream;
    }

    Variable &getSrc() {
        return this->src;
    }

    Variable &getDst() {
        return this->dst;
    }

private:
    Variable src;
    Variable dst;
    bpf_offset_type offset;
    BitWidth bitWidth;
};

class LoadPacketInst : public Instruction {
public:
    /* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

    [[maybe_unused]] LoadPacketInst(bpf_imm32_type imm32, BitWidth bitWidth) : src(0),
                                                                               imm32(imm32),
                                                                               bitWidth(bitWidth),
                                                                               isIndirect(false) {
        src.setAsInvalid();
        instType = InstructionType::LoadPacketInst;
    }

    /* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
    LoadPacketInst(Variable src, bpf_imm32_type imm32, BitWidth bitWidth)
            : src(src),
              imm32(imm32),
              bitWidth(bitWidth),
              isIndirect(true) {
        instType = InstructionType::LoadPacketInst;
    }

    BytecodeData CodeGen() override {


        if (!this->isIndirect) {
            assert(src.isInvalid());
            switch (bitWidth) {
                case BitWidth::bit8:
                    return {BPF_LD_ABS(BPF_B, imm32)};
                case BitWidth::bit16:
                    return {BPF_LD_ABS(BPF_H, imm32)};
                case BitWidth::bit32:
                    return {BPF_LD_ABS(BPF_W, imm32)};
                case BitWidth::bit64:
                    return {BPF_LD_ABS(BPF_DW, imm32)};
            }
        } else {
            assert(!src.isInvalid());
            __u8 macro_src = to_underlying(src.getReg());
            switch (bitWidth) {
                case BitWidth::bit8:
                    return {BPF_LD_IND(BPF_B, macro_src, imm32)};
                case BitWidth::bit16:
                    return {BPF_LD_IND(BPF_H, macro_src, imm32)};
                case BitWidth::bit32:
                    return {BPF_LD_IND(BPF_W, macro_src, imm32)};
                case BitWidth::bit64:
                    return {BPF_LD_IND(BPF_DW, macro_src, imm32)};
            }
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const LoadPacketInst &inst) {
        if (inst.isIndirect) {
            stream << "R0 =" << "*" << getUnsignedBitWidthName(inst.bitWidth) <<
                   "( PACKET_BUFFER + " << inst.src << " + " << inst.imm32 << ")";
            return stream;
        } else {
            assert(inst.src.isInvalid());
            stream << "R0 =" << "*" << getUnsignedBitWidthName(inst.bitWidth) <<
                   "( PACKET_BUFFER + " << inst.imm32 << ")";
            return stream;
        }
    }


    Variable &getSrc() {
        return this->src;
    }

private:
    Variable src;
    bpf_imm32_type imm32;
    BitWidth bitWidth;
    bool isIndirect;
};

class LoadImm64Inst : public Instruction {
public:
    // dst = imm64 (currently only imm64 is supported)
    LoadImm64Inst(Variable dst, bpf_imm64_type imm64) : dst(dst), imm64(imm64) {
        assert(dst.isRegister());
        instType = InstructionType::LoadImm64Inst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        return {BPF_LD_IMM64(macro_dst, imm64)};
    }

    // bug fix here: load imm64 occupy 2 byte size.
    size_t getBytecodeSize() override {
        return 2;
    }

    const Variable &getDst() const {
        assert(dst.isRegister());
        return dst;
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const LoadImm64Inst &inst) {
        stream << inst.dst << "=" << "(int64_t) " << std::to_string(inst.imm64);
        return stream;
    }

    void setImm64(bpf_imm64_type imm64) {
        this->imm64 = imm64;
    }

private:
    Variable dst;
    bpf_imm64_type imm64;
};

class LoadMapInst : public Instruction {
public:
    // load map offset content to dst
    LoadMapInst(bpf_imm32_type offset, Variable dst, Variable map_fd_reg, bool loadAddress) :
            dst(dst), map_fd_reg(map_fd_reg), offset(offset), loadAddress(loadAddress) {
        assert(dst.isRegister());
        assert(map_fd_reg.isRegister());
        instType = InstructionType::LoadMapInst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        __u8 macro_map_fd = to_underlying(map_fd_reg.getReg());

        if (loadAddress) {
            // TODO: load map fd to fixed reg1
            return {BPF_MOV64_REG(BPF_REG_1, macro_map_fd),
                    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
                    BPF_ST_MEM(BPF_W, BPF_REG_10, -4, offset),
                    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
                    BPF_EXIT_INSN(),
                    BPF_MOV64_REG((macro_dst), BPF_REG_0),
                    BPF_MOV64_IMM(BPF_REG_0, 0)};
        } else {
            return {
                    BPF_MOV64_REG(BPF_REG_1, macro_map_fd),
                    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
                    BPF_ST_MEM(BPF_W, BPF_REG_10, -4, offset),
                    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
                    BPF_EXIT_INSN(),
                    BPF_LDX_MEM(BPF_DW, macro_dst, BPF_REG_0, 0),
                    BPF_MOV64_IMM(BPF_REG_0, 0)
            };
        }
    }

    size_t getBytecodeSize() override {
        return 9;
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const LoadMapInst &inst) {
//        std::string suffix;
//        if (inst.loadAddress) {
//            suffix = " (load address : true) ";
//        } else {
//            suffix = " (load address : false) ";
//        }
//        stream << inst.dst << "=" << " map[" << inst.offset << "] " << "(map_fd: " << inst.map_fd_reg << " )" << suffix;
//        return stream;
        if (inst.loadAddress) {
            stream << inst.dst << "=" << " &map[" << inst.offset << "] " << "(map_fd: " << inst.map_fd_reg << " )";
        } else {
            stream << inst.dst << "=" << " *map[" << inst.offset << "] " << "(map_fd: " << inst.map_fd_reg << " )";
        }
        return stream;
    }

private:
    Variable dst;
    Variable map_fd_reg;
    bpf_imm32_type offset;
    bool loadAddress;
};

class StoreInst : public Instruction {
public:
    // *(uint *) (dst_reg + off16) = src_reg
    // or
    // *(uint *) (dst_reg + off16) = imm32
    StoreInst(Variable dst, Variable src, bpf_offset_type offset, BitWidth bitWidth) : src(src),
                                                                                       dst(dst),
                                                                                       offset(offset),
                                                                                       bitWidth(bitWidth) {
        assert(dst.isRegister());
        assert(src.isRegister() || src.isImm32());
        instType = InstructionType::StoreInst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        if (src.isRegister()) {
            __u8 macro_src = to_underlying(src.getReg());
            switch (bitWidth) {
                case BitWidth::bit8:
                    return {BPF_STX_MEM(BPF_B, macro_dst, macro_src, offset)};
                case BitWidth::bit16:
                    return {BPF_STX_MEM(BPF_H, macro_dst, macro_src, offset)};
                case BitWidth::bit32:
                    return {BPF_STX_MEM(BPF_W, macro_dst, macro_src, offset)};
                case BitWidth::bit64:
                    return {BPF_STX_MEM(BPF_DW, macro_dst, macro_src, offset)};
            }
        } else {
            assert(src.isImm32());
            bpf_imm32_type imm32 = src.getImm32();
            switch (bitWidth) {
                case BitWidth::bit8:
                    return {BPF_ST_MEM(BPF_B, macro_dst, offset, imm32)};
                case BitWidth::bit16:
                    return {BPF_ST_MEM(BPF_H, macro_dst, offset, imm32)};
                case BitWidth::bit32:
                    return {BPF_ST_MEM(BPF_W, macro_dst, offset, imm32)};
                case BitWidth::bit64:
                    return {BPF_ST_MEM(BPF_DW, macro_dst, offset, imm32)};
            }
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const StoreInst &inst) {
        stream << "*" << getUnsignedBitWidthName(inst.bitWidth) <<
               "(" << inst.dst << " + " << inst.offset << ")" <<
               "=" << inst.src;
        return stream;
    }

    Variable &getSrc() {
        return this->src;
    }

    Variable &getDst() {
        return this->dst;
    }

private:
    Variable src;
    Variable dst;
    bpf_offset_type offset;
    BitWidth bitWidth;
};

class MemXAddInst : public Instruction {
public:
    // Atomic memory add, *(uint *)(dst_reg + off16) += src_reg
    MemXAddInst(Variable dst, Variable src, bpf_offset_type offset, BitWidth bitWidth) : src(src),
                                                                                         dst(dst),
                                                                                         offset(offset),
                                                                                         bitWidth(bitWidth) {
        assert(dst.isRegister());
        assert(src.isRegister());
        instType = InstructionType::MemXAddInst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        __u8 macro_src = to_underlying(src.getReg());
        switch (bitWidth) {
            case BitWidth::bit8:
                return {BPF_STX_XADD(BPF_B, macro_dst, macro_src, offset)};
            case BitWidth::bit16:
                return {BPF_STX_XADD(BPF_H, macro_dst, macro_src, offset)};
            case BitWidth::bit32:
                return {BPF_STX_XADD(BPF_W, macro_dst, macro_src, offset)};
            case BitWidth::bit64:
                return {BPF_STX_XADD(BPF_DW, macro_dst, macro_src, offset)};
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const MemXAddInst &inst) {
        stream << "*" << getUnsignedBitWidthName(inst.bitWidth) <<
               "(" << inst.dst << " + " << inst.offset << ")" <<
               "+=" << inst.src << " (atom add)";
        return stream;
    }

    Variable &getSrc() {
        return this->src;
    }

    Variable &getDst() {
        return this->dst;
    }

private:
    Variable src;
    Variable dst;
    bpf_offset_type offset;
    BitWidth bitWidth;
};

class BranchInst : public Instruction {
public:
    BranchInst(BranchOpcode opcode, Variable dst, Variable src, bpf_offset_type offset, BitWidth bitWidth) :
            opcode(opcode), src(src), dst(dst), offset(offset), bitWidth(bitWidth) {
        assert(dst.isRegister());
        assert(src.isRegister() || src.isImm32());
        assert(bitWidth == BitWidth::bit64 || bitWidth == BitWidth::bit32);
        instType = InstructionType::BranchInst;
    }

    BytecodeData CodeGen() override {
        __u8 macro_dst = to_underlying(dst.getReg());
        __u8 macro_opcode = to_underlying(opcode);
        if (opcode == BranchOpcode::JA) { // should handle direct jmp here.
            return {BPF_JMP_DIRECT(offset)};
        }

        if (src.isRegister()) {
            __u8 macro_src = to_underlying(src.getReg());
            switch (bitWidth) {
                case BitWidth::bit32:
                    return {BPF_JMP32_REG(macro_opcode, macro_dst, macro_src, offset)};
                case BitWidth::bit64:
                    return {BPF_JMP_REG(macro_opcode, macro_dst, macro_src, offset)};
                default:
                    assert(false && "Unknown bit width for branch instruction.");
            }
        } else {
            bpf_imm32_type imm32 = src.getImm32();
            switch (bitWidth) {
                case BitWidth::bit32:
                    return {BPF_JMP32_IMM(macro_opcode, macro_dst, imm32, offset)};
                case BitWidth::bit64:
                    return {BPF_JMP_IMM(macro_opcode, macro_dst, imm32, offset)};
                default:
                    assert(false && "Unknown bit width for branch instruction.");
            }
        }
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const BranchInst &inst) {

        if (inst.opcode == BranchOpcode::JA) {
            stream << "goto " << inst.offset;
        } else {
            std::string bitWidth32;
            if (inst.bitWidth == BitWidth::bit32) {
                bitWidth32 = getBitWidthName(inst.bitWidth);
            }
            stream << "if ( " << inst.dst << getBranchOpcodeName(inst.opcode) << bitWidth32 << inst.src << " )"
                   << " goto pc+" << inst.offset;
        }
        return stream;
    }

    void updateOffset(bpf_offset_type offset) {
        this->offset = offset;
    }

    bpf_offset_type getOffset() {
        return this->offset;
    }

    const Variable &getDst() const {
        return dst;
    }

    BranchOpcode getOpcode() const {
        return opcode;
    }

    void setOpcode(BranchOpcode targetOpcode) {
        this->opcode = targetOpcode;
    }

    const Variable &getSrc() const {
        return src;
    }

    BitWidth getBitWidth() const {
        return bitWidth;
    }

private:
    BranchOpcode opcode;
    Variable src;
    Variable dst;
    bpf_offset_type offset;
    BitWidth bitWidth;
};


class CallInst : public Instruction {
public:
    CallInst(Variable target) : target(target) {
        // if target variable is imm, delegate it to syscall
        instType = InstructionType::CallInst;
    }

    BytecodeData CodeGen() override {
        ///* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
        // * offset to another bpf function
        // */
        //#define BPF_PSEUDO_CALL		1
        ///* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
        // * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel

        // call register:
        if (target.isImm32()) {
            bpf_imm32_type imm32 = target.getImm32();
            return {((struct bpf_insn) {
                    .code  = BPF_JMP | BPF_CALL,
                    .dst_reg = 0,
                    .src_reg = BPF_PSEUDO_CALL,
                    .off   = 0,
                    .imm   = imm32})};
        } else {
            assert(target.isRegister());
            __u8 macro_src = to_underlying(target.getReg());
            return {BPF_RAW_INSN(BPF_JMP | BPF_X | BPF_CALL,
                                 0, // dst.
                                 0, // src. not sure whether src should be in documentation.
                                 0, // offset.
                                 macro_src // imm.
                    )};
        }

    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const CallInst &inst) {
        stream << "call " << inst.target;
        return stream;
    }

    Variable getTarget() const{
        return target;
    }

private:
    Variable target;
};

class ExitInst : public Instruction {
public:
    ExitInst() {
        instType = InstructionType::ExitInst;
    }

    BytecodeData CodeGen() override {
        return {BPF_EXIT_INSN()};
    }

    void dump(std::ostream &stream) const override {
        stream << *this;
    }

    friend std::ostream &operator<<(std::ostream &stream, const ExitInst &inst) {
        stream << "exit";
        return stream;
    }

};

#endif //BPF_IR_INSTRUCTION_H

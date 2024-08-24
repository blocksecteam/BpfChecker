#ifndef BPF_IR_BPF_INSTRUCTION_H
#define BPF_IR_BPF_INSTRUCTION_H

// Force use predefined header
//#if __APPLE__
#include "util/bpf_header.h"

//#else
//
//#include <linux/bpf.h>
//#include <linux/bpf_common.h>
//#endif

// taken partly from samples/bpf/bpf_insn.h

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))
struct bpf_insn;

// from include/uapi/linux/bpf.h
/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1
/* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
 * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel
 */
#define BPF_PSEUDO_KFUNC_CALL	2


// call instruction from filter.h
#define BPF_CALL_REL(TGT)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = BPF_PSEUDO_CALL,			\
		.off   = 0,					\
		.imm   = TGT })

/* Convert function address to BPF immediate */

#define BPF_CALL_IMM(x)	((void *)(x) - (void *)__bpf_call_base)



/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

// To fix the warning of c++11-narrowing, static cast it.
//        .code  = static_cast<unsigned char>(BPF_ALU64 | BPF_OP(OP) | BPF_X),

#define BPF_ALU64_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(OP) | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)                    \
    BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_DW | BPF_IMM,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = (__u32) (IMM) }),            \
    ((struct bpf_insn) {                    \
        .code  = 0, /* zero is reserved opcode */    \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD    1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })


/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

#define BPF_JMP_DIRECT(OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(BPF_JA),        \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)            \
    ((struct bpf_insn) {                    \
        .code  = CODE,                    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()                        \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_EXIT,            \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = 0 })

#endif //BPF_IR_BPF_INSTRUCTION_H

#include <cstdint>
#include "irDump.h"
//#include <linux/filter.h>



struct internalInsn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

#include <cstdio>

void printInstruction(int i, struct bpf_insn *in_data) {
    i++;
    struct internalInsn *in = reinterpret_cast<internalInsn *>(in_data);
    switch (in->code) {
        case BPF_LD | BPF_IMM:
            printf("LD\tA, %d\n", in->k);
            break;

        case BPF_LD | BPF_W | BPF_ABS:
            printf("LD\tA, pkt[%d:4]\n", in->k);
            break;

        case BPF_LD | BPF_H | BPF_ABS:
            printf("LD\tA, pkt[%d:2]\n", in->k);
            break;

        case BPF_LD | BPF_B | BPF_ABS:
            printf("LD\tA, pkt[%d:1]\n", in->k);
            break;

        case BPF_LD | BPF_W | BPF_IND:
            printf("LD\tA, pkt[X+%d:4]\n", in->k);
            break;

        case BPF_LD | BPF_H | BPF_IND:
            printf("LD\tA, pkt[X+%d:2]\n", in->k);
            break;

        case BPF_LD | BPF_B | BPF_IND:
            printf("LD\tA, pkt[X+%d:1]\n", in->k);
            break;

        case BPF_LD | BPF_MEM:
            printf("LD\tA, M[%d]\n", in->k);
            break;

        case BPF_LD | BPF_W | BPF_LEN:
            printf("LD\tA, pktlen\n");
            break;

        case BPF_LDX | BPF_W | BPF_IMM:
            printf("LDX\tX, %d\n", in->k);
            break;

        case BPF_LDX | BPF_W | BPF_MEM:
            printf("LDX\tX, M[%d]\n", in->k);
            break;

        case BPF_LDX | BPF_W | BPF_LEN:
            printf("LDX\tX, pktlen\n");
            break;

        case BPF_LDX | BPF_B | BPF_MSH:
            printf("LDX\tX, 4 * (pkt[%d:1] & 0x0f)\n", in->k);
            break;

        case BPF_ST:
            printf("ST\tM[%d], A\n", in->k);
            break;

        case BPF_STX:
            printf("STX\tM[%d], X\n", in->k);
            break;

        case BPF_ALU | BPF_ADD | BPF_K:
            printf("ADD\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_SUB | BPF_K:
            printf("SUB\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_MUL | BPF_K:
            printf("MUL\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_DIV | BPF_K:
            printf("DIV\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_OR | BPF_K:
            printf("OR\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_AND | BPF_K:
            printf("AND\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_LSH | BPF_K:
            printf("LSH\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_RSH | BPF_K:
            printf("RSH\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_NEG:
            printf("NEG\tA\n");
            break;

        case BPF_ALU | BPF_MOD | BPF_K:
            printf("MOD\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_XOR | BPF_K:
            printf("XOR\tA, %d\n", in->k);
            break;

        case BPF_ALU | BPF_ADD | BPF_X:
            printf("ADD\tA, X\n");
            break;

        case BPF_ALU | BPF_SUB | BPF_X:
            printf("SUB\tA, X\n");
            break;

        case BPF_ALU | BPF_MUL | BPF_X:
            printf("MUL\tA, X\n");
            break;

        case BPF_ALU | BPF_DIV | BPF_X:
            printf("DIV\tA, X\n");
            break;

        case BPF_ALU | BPF_OR | BPF_X:
            printf("OR\tA, X\n");
            break;

        case BPF_ALU | BPF_AND | BPF_X:
            printf("AND\tA, X\n");
            break;

        case BPF_ALU | BPF_LSH | BPF_X:
            printf("LSH\tA, X\n");
            break;

        case BPF_ALU | BPF_RSH | BPF_X:
            printf("RSH\tA, X\n");
            break;

        case BPF_ALU | BPF_MOD | BPF_X:
            printf("MOD\tA, X\n");
            break;

        case BPF_ALU | BPF_XOR | BPF_X:
            printf("XOR\tA, X\n");
            break;

        case BPF_ALU64 | BPF_ADD | BPF_K:
            printf("ADD64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_SUB | BPF_K:
            printf("SUB64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_MUL | BPF_K:
            printf("MUL64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_DIV | BPF_K:
            printf("DIV64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_OR | BPF_K:
            printf("OR64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_AND | BPF_K:
            printf("AND64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_LSH | BPF_K:
            printf("LSH64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_RSH | BPF_K:
            printf("RSH64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_NEG:
            printf("NEG64\tA\n");
            break;

        case BPF_ALU64 | BPF_MOD | BPF_K:
            printf("MOD64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_XOR | BPF_K:
            printf("XOR64\tA, %d\n", in->k);
            break;

        case BPF_ALU64 | BPF_ADD | BPF_X:
            printf("ADD64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_SUB | BPF_X:
            printf("SUB64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_MUL | BPF_X:
            printf("MUL64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_DIV | BPF_X:
            printf("DIV64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_OR | BPF_X:
            printf("OR64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_AND | BPF_X:
            printf("AND64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_LSH | BPF_X:
            printf("LSH64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_RSH | BPF_X:
            printf("RSH64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_MOD | BPF_X:
            printf("MOD64\tA, X\n");
            break;

        case BPF_ALU64 | BPF_XOR | BPF_X:
            printf("XOR64\tA, X\n");
            break;

        case BPF_JMP | BPF_JA:
            printf("JA\t%d\n", i + in->k);
            break;

        case BPF_JMP | BPF_JEQ | BPF_K:
            printf("JEQ\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JGT | BPF_K:
            printf("JGT\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JGE | BPF_K:
            printf("JGE\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JSET | BPF_K:
            printf("JSET\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JEQ | BPF_X:
            printf("JEQ\tX, %d, %d\n", i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JGT | BPF_X:
            printf("JGT\tX, %d, %d\n", i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JGE | BPF_X:
            printf("JGE\tX, %d, %d\n", i + in->jt, i + in->jf);
            break;

        case BPF_JMP | BPF_JSET | BPF_X:
            printf("JSET\tX, %d, %d\n", i + in->jt, i + in->jf);
            break;

        case BPF_RET | BPF_K:
            printf("RET\t%d\n", in->k);
            break;

        case BPF_RET | BPF_A:
            printf("RET\tA\n");
            break;

//        case BPF_MISC | BPF_TAX:
//            printf("MOV\tX, A\n");
//            break;
//
//        case BPF_MISC | BPF_TXA:
//            printf("MOV\tA, X\n");
//            break;

        default:
            printf("unknown insn %.2x\n", in->code);
            break;
    }
}


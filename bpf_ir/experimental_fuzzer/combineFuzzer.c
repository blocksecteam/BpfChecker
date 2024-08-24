
#include "fuzzer.h"
#include "fuzzerConfig.h"
#include <stdint.h>

int sockets[2] = {0};

#define PRODUCTION_MODE

const size_t MAP_VALUE_SIZE = 8192;

int lookup_key = 0;
unsigned char first_lookup_value_buffer[MAP_VALUE_SIZE];
unsigned char second_lookup_value_buffer[MAP_VALUE_SIZE];

char test_run_buff[128] = {0};

extern int ebpfVerifyData(const uint8_t *data, size_t size);

__AFL_FUZZ_INIT();


void init_lookup_buffer() {
    memset(first_lookup_value_buffer, 0xFF, sizeof(first_lookup_value_buffer));
    memset(second_lookup_value_buffer, 0xFF, sizeof(second_lookup_value_buffer));
    *((int64_t *) first_lookup_value_buffer) = 8;
    *((int64_t *) first_lookup_value_buffer + 1) = 8;
    *((int64_t *) second_lookup_value_buffer) = 8;
    *((int64_t *) second_lookup_value_buffer + 1) = 8;
}

void init_lookup_buffer_with_value(int64_t first, int64_t second) {
    memset(first_lookup_value_buffer, 0xFF, sizeof(first_lookup_value_buffer));
    *((int64_t *) first_lookup_value_buffer) = first;
    *((int64_t *) first_lookup_value_buffer + 1) = second;
    memcpy(second_lookup_value_buffer, first_lookup_value_buffer, sizeof(first_lookup_value_buffer));
}


void dump_lookup_buffer() {
    printf("first buffer:\n");
    for (int i = 0; i < MAP_VALUE_SIZE; ++i) {
        printf("%02x", first_lookup_value_buffer[i]);
    }
    printf("\n");
    printf("second buffer:\n");
    for (int i = 0; i < MAP_VALUE_SIZE; ++i) {
        printf("%02x", second_lookup_value_buffer[i]);
    }
    printf("\n");
}

int diff_buffer() {
    for (int i = 0; i < MAP_VALUE_SIZE; ++i) {
        if (first_lookup_value_buffer[i] != second_lookup_value_buffer[i])
            return i;
    }
    return -1;
}


void run_batch(int map_fd, int bpf_fd) {
    int firstOverflowBound = 0;
    int secondOverflowBound = 0;

    unsigned int secondUpperIndex = sizeof(CANDIDATE_BUFFER);

    int cntInBound = 0;
    int cntFailed = 0;
    int cntTotal = 0;
    for (unsigned long long firstMagicIndex = 0;
         firstMagicIndex < sizeof(CANDIDATE_BUFFER) && (!firstOverflowBound); ++firstMagicIndex) {
        secondOverflowBound = 0;
        int64_t firstMagic = CANDIDATE_BUFFER[firstMagicIndex];

        for (unsigned long long secondMagicIndex = 0;
             secondMagicIndex < sizeof(CANDIDATE_BUFFER) && secondMagicIndex < secondUpperIndex &&
             (!secondOverflowBound); ++secondMagicIndex) {
            lkl_u32 retval, duration;

            int64_t secondMagic = CANDIDATE_BUFFER[secondMagicIndex];


            init_lookup_buffer_with_value(firstMagic, secondMagic);

            int ret = update_elem(map_fd, 0, first_lookup_value_buffer);
            if (ret) {
//                printf("bpf update elem failed '%s'\n", LKL_STRERROR(ret));
                continue;
            }


            int err = lkl_bpf_prog_test_run(bpf_fd, 1, test_run_buff, sizeof(test_run_buff), 0, &duration, &retval,
                                            NULL);

            if (err < 0) {
                cntFailed++;
//                printf("Fail to test run :%s\n", LKL_STRERROR(err));
                continue;
            } else {
                cntTotal++;
//                success("Successfully test run\n");
//                success("ret val from test run : %d\n", retval);
            }

            ret = lookup_elem(map_fd, 0, second_lookup_value_buffer);
            if (ret) {
//                error("bpf lookup elem failed '%s'\n", LKL_STRERROR(ret));
                continue;
            }

//#ifndef PRODUCTION_MODE
//            dump_lookup_buffer();
//#endif

#ifdef PRODUCTION_MODE
            if (!memcmp(first_lookup_value_buffer, second_lookup_value_buffer, MAP_VALUE_SIZE)) {
#else
                int diff_pos = diff_buffer();
        if (diff_pos == -1) {
#endif
//                printf("Map remains unchanged!\n");
                if (retval == FINISH_RUN) {
                    printf("[+] Map remains unchanged! Will crash myself.\n");
                    lkl_sys_halt();
                    // We should trigger crash here
                    char *BAD_POINTER = 0;
                    *BAD_POINTER = 0;
                    abort();
                } else if (retval == FAIL_SECOND_REG_OVER_UPPER_BOUND) {
                    secondUpperIndex = secondMagicIndex < secondUpperIndex ? secondMagicIndex : secondUpperIndex;
                    secondOverflowBound = 1;
                    //                    printf("[*] Seems the return value from bpf program is abnormal.\n");
                    continue;
                } else if (retval == FAIL_FIRST_REG_OVER_UPPER_BOUND) {
                    firstOverflowBound = 1;
                    continue;
                }
            }

#ifndef PRODUCTION_MODE
            printf("[+] Buffer diff at %d\n", diff_pos);
#else
//            printf("[+] Map writes in bound.\n");
            cntInBound++;
#endif
        }
    }

    printf("[+] Map writes in bound with %d exec.\n", cntInBound);
    printf("[+] Successfully run %d exec.\n", cntTotal);
    if (cntFailed) {
        printf("[+] bpf fail to run with %d exec.\n", cntFailed);
    }
}


char *getVerifierStatusString(int verifierPassStatus) {
    static char PASS_STRING[] = "ACCEPT";
    static char REJECT_STRING[] = "REJECT";
    if (verifierPassStatus == 1) {
        return PASS_STRING;
    } else if (verifierPassStatus == 0) {
        return REJECT_STRING;
    } else {
        printf("[!] INVALID verifierPassStatus pass to getVerifierStatusString");
        return REJECT_STRING;
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"
int main() {
    lkl_start_kernel(&lkl_host_ops, "");

    int ret = LKL_SAFE_SYSCALL(setreuid, 0, 0, 0);
#ifdef ENABLE_LOG
    lkl_printf("setreuid result: %d\n", ret);
#endif

    int map_fd = lkl_bpf_create_map(LKL_BPF_MAP_TYPE_ARRAY, sizeof(int), MAP_VALUE_SIZE, 1);
    if (map_fd < 0) {
        error("failed to create map '%s'\n", LKL_STRERROR(map_fd));
        exit(-1);
    } else {

        success("map fd : %d \n", map_fd);

    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1)) {

        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        if (len % sizeof(struct lkl_bpf_insn)) continue;

        unsigned int instruction_cnt = len / sizeof(struct lkl_bpf_insn);

        if (instruction_cnt == 0) continue;

        if (!fix_map_fd(buf, map_fd)) {
#ifdef ENABLE_LOG
            lkl_printf("Can't fix the map fd of the byte code\n");
#endif
            continue;
        }

        char *crabBuffer = (char *) malloc(len);
        size_t crabBufferLength = len;
        memcpy(crabBuffer, buf, crabBufferLength);

        load_attr.insns = (__lkl__u64) buf;
        load_attr.insn_cnt = instruction_cnt;
        lkl_printf("inst cnt: %d\n", instruction_cnt);
        int bpf_fd = LKL_SAFE_SYSCALL(bpf, LKL_BPF_PROG_LOAD, (long) &load_attr, sizeof(load_attr));
        lkl_printf("bpf fd:%d\n", bpf_fd);
        int lklVerifierPass = 0;
        if (bpf_fd < 0) {
            lkl_printf("[+] Linux Verifier reject this eBPF program: %s\n%s\n", LKL_STRERROR(bpf_fd), bpf_log_buf);
        } else {
            lklVerifierPass = 1;
            lkl_printf("[+] Linux Verifier: Pass.\n");
        }

        lkl_printf("will verify it using crab verifier\n");
        int crabVerifierPass = ebpfVerifyData(crabBuffer, len);
        free(crabBuffer);
        crabBuffer = NULL;

        if (crabVerifierPass == 2) {
//            lkl_printf("crab verifier accept it.\n");
            crabVerifierPass = 1;
        } else if (crabVerifierPass == 3) {
//            lkl_printf("crab verifier reject it.\n");
            crabVerifierPass = 0;
        } else {
            lkl_printf("crab ebpf verifier doesn't work on this program..");
            continue;
        }

        if (crabVerifierPass != lklVerifierPass) {
            lkl_printf("Different verifier status found:\n\t[+] Linux verifier: %s\n\t[+] Crab  verifier: %s\n",
                       getVerifierStatusString(lklVerifierPass), getVerifierStatusString(crabVerifierPass));
        }


#ifdef RUN_ONCE
        lkl_u32 retval, duration;

        init_lookup_buffer();

        ret = update_elem(map_fd, 0, first_lookup_value_buffer);
        if (ret) {
            printf("bpf update elem failed '%s'\n", LKL_STRERROR(ret));
            continue;
        }


        int err = lkl_bpf_prog_test_run(bpf_fd, 1, test_run_buff, sizeof(test_run_buff), 0, &duration, &retval, NULL);

        if (err < 0) {
            printf("Fail to test run :%s\n", LKL_STRERROR(err));
            continue;
        } else {
            success("Successfully test run\n");
            success("ret val from test run : %d\n", retval);
        }

        ret = lookup_elem(map_fd, 0, second_lookup_value_buffer);
        if (ret) {
            error("bpf lookup elem failed '%s'\n", LKL_STRERROR(ret));
            continue;
        }

#ifndef PRODUCTION_MODE
        dump_lookup_buffer();
#endif

#ifdef PRODUCTION_MODE
        if (!memcmp(first_lookup_value_buffer, second_lookup_value_buffer, MAP_VALUE_SIZE)) {
#else
        int diff_pos = diff_buffer();
        if (diff_pos == -1) {
#endif
            printf("Map remains unchanged!\n");
            if (retval == FINISH_RUN) {
                printf("[+] Map remains unchanged! Will crash myself.\n");
                lkl_sys_halt();
                // We should trigger crash here
                char *BAD_POINTER = 0;
                *BAD_POINTER = 0;
                abort();
            } else {
                printf("[*] Seems the return value from bpf program is abnormal.\n");
                continue;
            }
        }

#ifndef PRODUCTION_MODE
        printf("[+] Buffer diff at %d\n", diff_pos);
#else
        printf("[+] Map writes in bound.\n");
#endif

#else // RUN_ONCE not defined
#ifdef ENABLE_LKL_RUN_TEST
        run_batch(map_fd, bpf_fd);
#endif
#endif // end RUN_ONCE


    }
    return 0;
}
#pragma clang diagnostic pop
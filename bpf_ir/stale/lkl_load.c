#include <lkl.h>
#include <lkl_host.h>
#include <syscall.h>
#include <lkl/linux/bpf.h>
//#include <linux/bpf.h>

//struct lkl_host_operations lkl_host_ops;

#define INPUT_LEN (1 << 16)
#define BPF_LOG_BUF_LEN (1 << 16)
static unsigned char input_buf[INPUT_LEN];
static char bpf_log_buf[BPF_LOG_BUF_LEN];

static char data_in[1024];
static char data_out[1024];

//const size_t insn_count = 0;
#define insn_count  (0)
//const int bpf_log_level = 2;
#define bpf_log_level  (2)

union lkl_bpf_attr load_attr = {
        .prog_type = LKL_BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt  = insn_count,
        .insns     = (uint64_t) input_buf,
        .license   = (uint64_t) "GPL",
        .log_level = (uint32_t) bpf_log_level,
        .log_size  = bpf_log_level ? BPF_LOG_BUF_LEN : 0,
        .log_buf   = (uint64_t) (bpf_log_level ? bpf_log_buf : 0),
};

static inline void compiler_enter_lkl(void) {

}

static inline void compiler_exit_lkl(void) {

}

static inline long lkl_exit_wrapper(long result) {
    compiler_exit_lkl();
    return result;
}

#define LKL_SAFE_SYSCALL(name, ...) \
    (compiler_enter_lkl(), lkl_exit_wrapper( \
        lkl_syscall(__lkl__NR_##name, (long[]){__VA_ARGS__, 0, 0, 0, 0, 0, 0})))

#define INVOKE_SYSCALL(syscall_name, ...) \
        LKL_SAFE_SYSCALL(syscall_name, __VA_ARGS__)));

#define LKL_ERRNO(retval) (retval)
#define LKL_STRERROR(retval) lkl_strerror((retval))

int main() {
    lkl_start_kernel(&lkl_host_ops, "");

    int res = LKL_SAFE_SYSCALL(setreuid, 0, 0, 0);
    lkl_printf("setreuid result: %d\n", res);
    unsigned int instruction_cnt = 0;
//    load_attr.insns = (__lkl__aligned_u64) get_test_bpf_program(&instruction_cnt);
//    load_attr.insn_cnt = instruction_cnt;
    lkl_printf("inst cnt: %d\n", instruction_cnt);
    int bpffd = LKL_SAFE_SYSCALL(bpf, LKL_BPF_PROG_LOAD, (long) &load_attr, sizeof(load_attr));
//    int bpffd = LKL_SAFE_SYSCALL(bpf, LKL_BPF_PROG_LOAD, (long) &load_attr, sizeof(load_attr));
//    int bpffd = INVOKE_SYSCALL(bpf, LKL_BPF_PROG_LOAD, (long) &load_attr, sizeof(load_attr));
    lkl_printf("bpf fd:%d\n", bpffd);
    if (bpffd < 0) {
        lkl_printf("[+] Cannot load eBPF program: %s\n%s\n", LKL_STRERROR(bpffd), bpf_log_buf);
    }
    return 0;
}
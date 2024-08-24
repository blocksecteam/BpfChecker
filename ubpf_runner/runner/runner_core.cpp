#include "runner_core.h"
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include "utils/utils.h"

using namespace
        std;
extern "C" {
#include "ubpf.h"

uint64_t unwind(uint64_t i) {
    return i;
}

}


//static void register_functions(struct ubpf_vm *vm) {
//    ubpf_register(vm, 0, "gather_bytes", gather_bytes);
//    ubpf_register(vm, 1, "memfrob", memfrob);
//    ubpf_register(vm, 2, "trash_registers", trash_registers);
//    ubpf_register(vm, 3, "sqrti", sqrti);
//    ubpf_register(vm, 4, "strcmp_ext", strcmp);
//    ubpf_register(vm, 5, "unwind", static_cast<void *>(unwind));
//    ubpf_set_unwind_function_index(vm, 5);
//}

static void *readfile(const char *path, size_t maxlen, size_t *len) {
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == nullptr) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return nullptr;
    }

    auto *data = (uint8_t *) calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return nullptr;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned) maxlen);
        fclose(file);
        free(data);
        return nullptr;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

void run_with_interpreted(const char *data, size_t data_size, RunResult &result) {
    struct ubpf_vm *vm_interpreted = ubpf_create();
    if (!vm_interpreted) {
        fprintf(stderr,
                "Failed to create VM\n");
        return;
    }
// here we choose NOT to pre-register function
//    register_functions(vm_interpreted);
    char *errmsg_interpreted;
    int rv_interpreted = ubpf_load(vm_interpreted, data, data_size, &errmsg_interpreted);
    if (rv_interpreted < 0) {
        auto error_msg = string("Failed to load code: ");
        error_msg.append(errmsg_interpreted);
        result.err_reason = ErrorReason(error_msg, false);
//        fprintf(stderr, "Failed to load code: %s\n", errmsg_interpreted);
        free(errmsg_interpreted);
        ubpf_destroy(vm_interpreted);
        return;
    }
    char *mem = nullptr;
    size_t mem_len = 0;
    uint64_t ret_interpreted;
// PATCH WORK:
// set initial register value as 0.
    if (ubpf_exec(vm_interpreted, mem, mem_len, &ret_interpreted) < 0) {
        auto error_msg = string("Runtime Error in Interpreted mode,");
        result.err_reason = ErrorReason(error_msg, true);
// trigger error in Interpreted mode
        fprintf(stderr,
                "Error execution in Interpreted mode, ret_interpreted maybe not accurate.\n");
        ret_interpreted = UINT64_MAX;
    }
//    cout << "Interpreted Result: " << "0x" << hex << ret_interpreted << endl;
    result.registers_value[0] = ret_interpreted;
    ubpf_destroy(vm_interpreted);
    free(mem);
}

void run_with_interpreted(const string &code_content, RunResult &result) {
    return run_with_interpreted(code_content.data(), code_content.length(), result);
}

void run_with_jit(const char *data, size_t data_size, RunResult &result) {
    struct ubpf_vm *vm_jit = ubpf_create();
    if (!vm_jit) {
        fprintf(stderr,
                "Failed to create VM\n");
        return;
    }
    char *errmsg_jit;
    int rv_jit = ubpf_load(vm_jit, data, data_size, &errmsg_jit);
    if (rv_jit < 0) {
        auto error_msg = string("Failed to load code: ");
        error_msg.append(errmsg_jit);
        result.err_reason = ErrorReason(error_msg, false);
//        fprintf(stderr,
//                "Failed to load code: %s\n", errmsg_jit);
        free(errmsg_jit);
        ubpf_destroy(vm_jit);
        return;
    }
    char *mem = nullptr;
    size_t mem_len = 0;
    uint64_t ret_jit;
// PATCH WORK:
// set initial register value as 0.
    char *errmsg;
    ubpf_jit_fn fn = ubpf_compile(vm_jit, &errmsg);
    if (fn == nullptr) {
        fprintf(stderr,
                "Failed to compile: %s\n", errmsg);
        free(errmsg);
        free(mem);
        return;
    }
// TODO: maybe we should copy mem as backup.

    ret_jit = fn(mem, mem_len);
//    cout << "JIT Result: " << "0x" << hex << ret_jit << endl;
    result.registers_value[0] = ret_jit;
    ubpf_destroy(vm_jit);
    free(mem);
}

void run_with_jit(const string &code_content, RunResult &result) {
    return run_with_jit(code_content.data(), code_content.length(), result);
}
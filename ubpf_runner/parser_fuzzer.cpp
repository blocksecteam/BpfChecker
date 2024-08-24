#include <iostream>
#include <vector>

#include <boost/functional/hash.hpp>

#include "CLI11.hpp"

#include "ebpf_verifier.hpp"

#ifdef _WIN32
#include "memsize_windows.hpp"
#else

#include "memsize_linux.hpp"

#endif

#include "utils.hpp"

// Linux
#include "elfio/elfio.hpp"
#include "elfio/elfio_section.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using std::string;
using std::vector;
using namespace ELFIO;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantFunctionResult"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size % sizeof(ebpf_inst) != 0) {
        return 0;
    }
    try {
        ebpf_verifier_options_t ebpf_verifier_options = ebpf_verifier_default_options;
        ebpf_verifier_options.check_termination = true;
        ebpf_verifier_options.print_invariants = false;
        std::stringstream stream(std::string(reinterpret_cast<const char *>(data), size));
        const ebpf_platform_t *platform = &g_ebpf_platform_linux;
        auto raw_programs = read_elf(stream, "memory", "", &ebpf_verifier_options, platform);

    } catch (std::exception &e) {
//        std::cout << e.what() << std::endl;
        return 0;
    }
    return 0;
}
#pragma clang diagnostic pop

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

enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
};

#define PTYPE(name, descr, native_type, prefixes) \
    { name, descr, native_type, prefixes }
#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
    { name, descr, native_type, prefixes, true }
//const EbpfProgramType linux_socket_filter_program_type =
//        PTYPE("socket_filter", &g_socket_filter_descr, BPF_PROG_TYPE_SOCKET_FILTER, {"socket"});
//
//const EbpfProgramType linux_xdp_program_type = PTYPE("xdp", &g_xdp_descr, BPF_PROG_TYPE_XDP, {"xdp"});
//
//const EbpfProgramType cilium_lxc_program_type = PTYPE("lxc", &g_sched_descr, BPF_PROG_TYPE_SOCKET_FILTER, {});

template<typename T>
static vector<T> vector_of(ELFIO::section *sec) {
    if (!sec)
        return {};
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T *) data, (T *) (data + size)};
}

template<typename T>
static vector<T> vector_of(const uint8_t *data, size_t size) {
    if (!data)
        return {};
    assert(size % sizeof(T) == 0);
    return {(T *) data, (T *) (data + size)};
}

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
//    if (size < 40 || size % sizeof(ebpf_inst) != 0) {
//        return 0;
//    }
    if (size < 8 || size % sizeof(ebpf_inst) != 0) {
        return 0;
    }

    // Program Info
    const ebpf_platform_t *platform = &g_ebpf_platform_linux;

    // prepare program info
    program_info fuzz_info{.platform = platform};
    EbpfMapDescriptor arrayMapDescriptor{
            .original_fd = 0, .key_size = sizeof(int), .value_size = 8192, .max_entries = 1};
    fuzz_info.map_descriptors.push_back(arrayMapDescriptor);

    const EbpfProgramType fakeProgramType =
            PTYPE_PRIVILEGED("socket_filter", &g_socket_filter_descr, BPF_PROG_TYPE_SOCKET_FILTER, { "socket" });
    fuzz_info.type = fakeProgramType;

    // TODO : Support parse_maps_section_linux
    //    fuzz_info.type = linux_socket_filter_program_type;

    // path section_name
    raw_program raw_prog{"DUMMY", "fuzz", vector_of<ebpf_inst>(data, size), fuzz_info};

    std::variant<InstructionSeq, std::string> prog_or_error;
    try {
        prog_or_error = unmarshal(raw_prog);
        if (std::holds_alternative<string>(prog_or_error)) {
//            std::cout << "unmarshaling error at " << std::get<string>(prog_or_error) << "\n";
            return 0;
        } else {
//            std::cout << "unmarshaling successfully!\n";
        }

    } catch (exception &e) {
        //        cout << "catch unmarshal error\n";
//        std::cout << e.what() << std::endl;
        return 0;
    }

    auto &prog = std::get<InstructionSeq>(prog_or_error);

//    cout << "will ebpf_verify_program\n ";
    //    ebpf_verify_program(std::cout, prog, fuzz_info, nullptr);
    try {
        ebpf_verifier_stats_t verifier_stats{};
        ebpf_verifier_options_t ebpf_verifier_options = ebpf_verifier_default_options;
        ebpf_verifier_options.check_termination = true;
        ebpf_verifier_options.print_invariants = false;
        //        ebpf_verifier_options.check_termination = false;
        // ebpf_verifier_options.strict
        // for verbose:
        //  ebpf_verifier_options.print_invariants = ebpf_verifier_options.print_failures = true;

        //        cfg_t cfg = prepare_cfg(prog, fuzz_info, false);
        //        auto stats = collect_stats(cfg);
        //        for (const string& h : stats_headers()) {
        //            std::cout << "," << stats.at(h);
        //        }
        //        std::cout << "\n";
        //        print_dot(cfg, "cfg_graph.dot");
        // print instructions
        const auto [res, seconds] = timed_execution([&] {
            return ebpf_verify_program(std::cout, prog, raw_prog.info, &ebpf_verifier_options, &verifier_stats);
        });
        if (ebpf_verifier_options.check_termination &&
            (ebpf_verifier_options.print_failures || ebpf_verifier_options.print_invariants)) {
//            std::cout << "Program terminates within " << verifier_stats.max_instruction_count << " instructions\n";
        }
//        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
//        print(prog, std::cout, nullopt);
//        const auto [result, seconds] = timed_execution(
//                [&] { return ebpf_verify_program(std::cout, prog, fuzz_info, &ebpf_verifier_options, &verifier_stats); });
//
//        std::cout << "Finish verify. Program terminates within " << verifier_stats.max_instruction_count
//                  << " instructions\n";
//        //        std::cout << "Analyze it in " << seconds << "s, with " << resident_set_size_kb() << " kb resident set
//        //        size.\n";
//        std::cout << "Analyzed it in " << seconds << "s\n";
//        if (result) {
//            std::cout << "verifier pass it\n";
//        } else {
//            std::cout << "verifier reject it\n";
//        }

    } catch (exception &e) {
        return 0;
    }

    return 1;
}


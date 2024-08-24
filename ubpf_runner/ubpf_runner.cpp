#include <iostream>
#include <vector>

#include <boost/functional/hash.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

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

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <filesystem>

// argparse related
#include "utils/argparse.hpp"

// ubpf engine runner
#include "runner_core.h"

using namespace std;
using namespace std::chrono_literals;
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

#include <iostream>

using namespace std;

enum LogReason {
    CASE_FOUND,
};

class RunnerLog {
public:

    RunnerLog &operator()(enum LogReason reason) {
        if (reason == LogReason::CASE_FOUND) {
            cout << "[DIFFERENTIAL FOUND] ";
        }
        return *this;
    }

    template<class T>
    RunnerLog &operator<<(T t) {
        cout << t;
        return *this;
    }

    RunnerLog &operator<<(ostream &(*f)(ostream &o)) {
        cout << f;
        return *this;
    };
} g_runner_log;

struct RunnerOption {
    bool should_log_unmarshal = false;
    bool should_log_runtime_exception = false;
    bool should_log_verify_result = false;
    bool should_log_disassemble = false;
    std::chrono::seconds exec_timeout;
};


bool is_program_verified(const uint8_t *data, size_t size, RunnerOption &run_option) {
    if (size % sizeof(ebpf_inst) != 0) {
        return false;
    }

    // Program Info
    const ebpf_platform_t *platform = &g_ebpf_platform_linux;

    // prepare program info
    program_info fuzz_info{.platform = platform};
    EbpfMapDescriptor arrayMapDescriptor{.original_fd = 0, .key_size = sizeof(int), .value_size = 8192, .max_entries = 1};
    fuzz_info.map_descriptors.push_back(arrayMapDescriptor);

    // BPF_PROG_TYPE_SOCKET_FILTER
    // BPF_PROG_TYPE_XDP
//    const EbpfProgramType fakeProgramType =
//            PTYPE_PRIVILEGED("socket_filter", &g_socket_filter_descr, 0, { "socket" });
// non-privileged type
    const EbpfProgramType fakeProgramType =
            PTYPE("socket_filter", &g_socket_filter_descr, 0, { "socket" });
//            PTYPE_PRIVILEGED("socket_filter", &g_socket_filter_descr, BPF_PROG_TYPE_SOCKET_FILTER, { "socket" });
    fuzz_info.type = fakeProgramType;

    // TODO : Support parse_maps_section_linux
    //    fuzz_info.type = linux_socket_filter_program_type;

    // path section_name
    raw_program raw_prog{"DUMMY", "fuzz", vector_of<ebpf_inst>(data, size), fuzz_info};

    std::variant<InstructionSeq, std::string> prog_or_error;
    try {
        prog_or_error = unmarshal(raw_prog);
        if (std::holds_alternative<string>(prog_or_error)) {
            if (run_option.should_log_unmarshal)
                std::cout << "unmarshaling error at " << std::get<string>(prog_or_error) << "\n";
            return false;
        } else {

            if (run_option.should_log_unmarshal)
                std::cout << "unmarshaling successfully!\n";
            if (run_option.should_log_disassemble) {
                auto &prog = std::get<InstructionSeq>(prog_or_error);
                cout << endl;
                print(prog, cout, {});
            }
        }

    } catch (exception &e) {
        //        cout << "catch unmarshal error\n";
        if (run_option.should_log_runtime_exception)
            std::cout << e.what() << std::endl;
        return false;
    }

    auto &prog = std::get<InstructionSeq>(prog_or_error);
    try {
        ebpf_verifier_stats_t verifier_stats{};
        ebpf_verifier_options_t ebpf_verifier_options = ebpf_verifier_default_options;
        ebpf_verifier_options.check_termination = true;
        ebpf_verifier_options.print_invariants = false;
        ebpf_verifier_options.no_simplify = true; // TODO: DEBUG ONLY
        if (run_option.should_log_verify_result) {
            ebpf_verifier_options.print_failures = true;
            ebpf_verifier_options.print_line_info = true;
        }
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
        if (run_option.should_log_verify_result) {
            if (ebpf_verifier_options.check_termination) {
                std::cout << "Program terminates within " << verifier_stats.max_instruction_count << " instructions\n";
            }
            std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
        }
        return res == 1;

    } catch (exception &e) {
        if (run_option.should_log_runtime_exception) {
            cout << " catch verify exception\n" << e.what() << endl;
        }
        return false;
    }
}

char *read_file(const char *path, size_t *length) {
    FILE *pfile;
    char *data;

    pfile = fopen(path, "rb");
    if (!pfile) return nullptr;

    fseek(pfile, 0, SEEK_END);
    *length = ftell(pfile);
    data = (char *) malloc((*length + 1) * sizeof(char));
    rewind(pfile);
    *length = fread(data, 1, *length, pfile);
    data[*length] = '\0';
    fclose(pfile);
    return data;
}

string read_file_as_string(string &path) {
    std::ifstream inFile;
    inFile.open(path); //open the input file

    std::stringstream strStream;
    strStream << inFile.rdbuf(); //read the file
    std::string str = strStream.str(); //str holds the content of the file
    return str;
}

bool run_once(std::string program_path, RunnerOption &runner_option) {
    size_t size;
    assert(std::filesystem::exists(program_path));
    auto content = read_file_as_string(program_path);
    cout << "[*] Program [" << program_path << "] Status: " << std::flush;
    auto status = is_program_verified(reinterpret_cast<const uint8_t *>(content.data()), content.size(), runner_option);
    cout << status << std::flush;
    if (!status) {
        // separate print in case of dead loop
        cout << endl;
        return false;
    }

    RunResult result_jit, result_interp;
//    run_with_jit(content, result_jit);
//    cout <<"\tJIT Finished." << std::flush;
//    if (strstr(program_path.c_str(), "118")) {
//        cout << "DEBUG ME" << endl;
//    }
    run_with_interpreted(content, result_interp);
    cout << "\tInterpreter Finished." << std::flush;
    return true;

    run_with_jit(content, result_jit);
    cout << "\tJIT Finished." << std::flush;
    cout << endl;
//    assert(result_jit.err_reason == result_interp.err_reason);

    if (result_jit.err_reason.has_value() != result_interp.err_reason.has_value() ||
        result_jit.err_reason != result_interp.err_reason) {
        if (!(result_jit.registers_value[0] == result_interp.registers_value[0] &&
              result_jit.registers_value[0] == -1)) {
            g_runner_log(LogReason::CASE_FOUND) << "Error State different:\n"
                                                << "\t Error State in JIT: " << result_jit.get_reason_content() << endl
                                                << "\t Error State in Interpreter: "
                                                << result_interp.get_reason_content()
                                                << endl
                                                << "\t Register0 in JIT: 0x" << hex << result_jit.registers_value[0]
                                                << endl
                                                << "\t Register0 in Interpreter: 0x" << hex
                                                << result_interp.registers_value[0]
                                                << endl;
            assert(false && "Different Error State Found");

        }
    }
    if (!result_interp.err_reason.has_value()) {
        if (result_jit.registers_value[0] != result_interp.registers_value[0]) {
//        cout << "[DIFFERENTIAL FOUND] register"
            g_runner_log(LogReason::CASE_FOUND) << "Register0 different:\n"
                                                << "\t Register0 in JIT: 0x" << hex << result_jit.registers_value[0]
                                                << endl
                                                << "\t Register0 in Interpreter: 0x" << hex
                                                << result_interp.registers_value[0]
                                                << endl;
            assert(false && "Different Register Found");
        }
    } else {
        cout << "Error State: " << result_interp.err_reason.value().content << endl;
    }

    return true;
}

int run_with_timeout(std::string program_path, RunnerOption &runner_option) {
    std::mutex m;
    std::condition_variable cv;
    int retValue;

    std::thread t([&cv, &retValue, &program_path, &runner_option]() {
        retValue = run_once(program_path, runner_option);
        cv.notify_one();
    });

    t.detach();
    {
        std::unique_lock<std::mutex> l(m);
        if (cv.wait_for(l, runner_option.exec_timeout) == std::cv_status::timeout) {
            std::cout << std::endl << "[!] Execution for " + program_path + " timeout (limit: 5s)." << std::endl;
        }
    }
    return retValue;
}


int main(int argc, char **argv) {

    argparse::ArgumentParser program("uBPF self-runner");

    program.add_argument("-i", "--input")
            .required()
            .help("specify the input file.");


    program.add_argument("-v", "--verbose")
            .help("enable verbose log")
            .default_value(false)
            .implicit_value(true);

    program.add_argument("-d", "--disassemble")
            .help("enable disassemble log")
            .default_value(true)
            .implicit_value(true);

    program.add_argument("-t", "--timeout")
            .help("timeout for each execution")
            .default_value(2)
            .scan<'i', int>();

    program.add_argument("--batch")
            .help("run in batch mode")
            .default_value(false)
            .implicit_value(true);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    auto input_path = program.get<std::string>("-i");
    auto is_batch_mode = program.get<bool>("--batch");
    auto is_verbose_log = program.get<bool>("--verbose");
    auto exec_timeout = program.get<int>("--timeout") * 1s;

    RunnerOption runner_option;
    runner_option.should_log_verify_result = is_verbose_log;
    runner_option.exec_timeout = exec_timeout;
    runner_option.should_log_disassemble = program.get<bool>("--disassemble");
    if (is_batch_mode) {
        set < std::filesystem::path > sorted_by_name;
        for (const auto &entry: std::filesystem::directory_iterator(input_path)) {
            sorted_by_name.insert(entry.path());
        }
        for (const auto &target: sorted_by_name) {
            run_with_timeout(target, runner_option);
        }
    } else {
        runner_option.should_log_disassemble = true;
        run_once(input_path, runner_option);
    }


    return 0;
}
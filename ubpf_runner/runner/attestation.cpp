#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include "utils/utils.h"
#include "utils/argparse.hpp"

using namespace std;

#include "runner_core.h"

int main(int argc, char *argv[]) {

    argparse::ArgumentParser program("uBPF self-runner");

    program.add_argument("-i", "--input")
            .required()
            .help("specify the input file.");

    program.add_argument("--verbose")
            .help("increase output verbosity")
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

    auto input_filename = program.get<std::string>("-i");
    std::cout << "Input filename: " << input_filename << std::endl;

//    if (program["--verbose"] == true) {
//        std::cout << "Verbosity enabled" << std::endl;
//    }
    auto code_content = read_file(input_filename);
    RunResult result;
    run_with_interpreted(code_content, result);
    run_with_jit(code_content, result);
}
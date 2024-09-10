#include "AluGenerator.h"
#include "MemGenerator.h"
#include "JmpGenerator.h"

#include "argparse.hpp"
#include "uBPFGenerator.h"
#include "rBPFGenerator.h"
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

string base_path;

void delete_directory_contents(const std::string &dir_path) {
    filesystem::create_directories(dir_path);
    for (const auto &entry: std::filesystem::directory_iterator(dir_path))
        std::filesystem::remove_all(entry.path());
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cppcoreguidelines-narrowing-conversions"

void write_cases(vector<TestCase> &testcases, const string &base_binary_path, const string &base_code_path) {
    delete_directory_contents(base_binary_path);
    delete_directory_contents(base_code_path);
    cout << testcases.size() << " cases generated." << endl;
    size_t index_name = 0;
    auto current_time = chrono::system_clock::to_time_t(chrono::system_clock::now());
    for (auto &testcase: testcases) {
        string timestamp = to_string(current_time);
        ofstream obj_file(base_binary_path + to_string(index_name) + "_" + timestamp);
        auto bytecode = testcase.data;
        obj_file.write(reinterpret_cast<const char *>(bytecode.data()),
                       static_cast<size_t>(bytecode.size()) * sizeof(struct bpf_insn));
        obj_file.close();
        ofstream code_file(base_code_path + to_string(index_name) + "_" + timestamp + ".txt");
        code_file.write(testcase.code.data(), testcase.code.size());
        code_file.close();
        index_name += 1;
    }
    cout << "[+] Written Finished:\n" <<
         "\tBytecode binary write to " << base_binary_path << "\n" <<
         "\tText code write to " << base_code_path << endl;
}

#pragma clang diagnostic pop

void generate_and_write_alu_cases() {
    string base_binary_path = base_path + "alu_set/";
    string base_code_path = base_path + "alu_code/";
//    vector<TestCase> testcases = {generate_div_by_zero_instruction(true)};
    vector<TestCase> testcases = generate_shift_instructions();
    write_cases(testcases, base_binary_path, base_code_path);
}


void generate_and_write_mem_cases() {
    string base_binary_path = base_path + "mem_set/";
    string base_code_path = base_path + "mem_code/";
    vector<TestCase> testcases = generate_random_mem_programs();
    write_cases(testcases, base_binary_path, base_code_path);
}

void generate_and_write_jmp_cases() {
    string base_binary_path = base_path + "jmp_set/";
    string base_code_path = base_path + "jmp_code/";
    vector<TestCase> testcases = generate_jmp_instructions();
    write_cases(testcases, base_binary_path, base_code_path);
}

void generate_and_write_program(size_t program_number, size_t action_size, unique_ptr<ProgramGenerator> program_generator) {
    fs::path base_output_path = base_path;
    auto base_binary_path = base_output_path / "program_set/";
    string base_code_path = base_output_path / "program_code/";

//    auto ubpf_generator = UBPFGenerator();
//    auto ubpf_generator = RBPFGenerator();

    // ideal config: 20 actions of 10000 cases.
    vector<TestCase> testcases = {};
//    while (program_number--) {
//        testcases.push_back(program_generator->generateProgram(action_size));
//    }
//    testcases.push_back(program_generator->generatePoC(ProgramGenerator::GeneratorType::UBPF_OOB_POC));
    testcases.push_back(program_generator->generatePoC(ProgramGenerator::GeneratorType::UBPF_INTEGER_OVERFLOW_ADDR_POC));
    write_cases(testcases, base_binary_path, base_code_path);
}

int main(int argc, char *argv[]) {
    argparse::ArgumentParser program("Bpf Program Generator", "1.1.0");
    program.add_argument("-o", "--output")
            .required()
            .help("specify the output directory.");

    program.add_argument("-n", "--number")
            .scan<'d', int>()
            .default_value(1000)
            .help("numbers of program to generate.");

    program.add_argument("--action_size")
            .scan<'d', int>()
            .default_value(10)
            .help("specify the action size.");

    program.add_argument("-g", "--generation_strategy")
            .default_value(std::string("program"))
            .help("specify the generation strategy (alu, mem, jmp, program, all).");

    program.add_argument("-t", "--generation_target")
            .default_value(std::string("rbpf"))
            .help("specify the generation target (rbpf, ubpf).");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    base_path = program.get<std::string>("--output");
    size_t program_number = program.get<int>("--number");
    size_t action_size = program.get<int>("--action_size");
    string generation_target = program.get<std::string>("--generation_target");
    string generation_strategy = program.get<std::string>("--generation_strategy");

    unique_ptr<ProgramGenerator> program_generator = nullptr;
    if (generation_target == "rbpf") {
        program_generator = make_unique<RBPFGenerator>();
    } else if (generation_target == "ubpf") {
        program_generator = make_unique<UBPFGenerator>();
    } else {
        assert(false && "Invalid mode found.");
    }

    if (generation_strategy == "alu" || generation_strategy == "all") {
        generate_and_write_alu_cases();
    }
    if (generation_strategy == "mem" || generation_strategy == "all") {
        generate_and_write_mem_cases();
    }
    if (generation_strategy == "jmp" || generation_strategy == "all") {
        generate_and_write_jmp_cases();
    }
    if (generation_strategy == "program" || generation_strategy == "all") {
        generate_and_write_program(program_number, action_size, std::move(program_generator));
    }
}
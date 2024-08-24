#ifndef BPF_IR_MEMGENERATOR_H
#define BPF_IR_MEMGENERATOR_H

#include "Util.h"
#include <Module.h>

TestCase generate_mem_program_example();
TestCase generate_random_mem_load();
std::vector<TestCase> generate_random_mem_programs(int num_operations = 5);
TestCase generate_random_mem_write_program();

// Used for testing
//TestCase generate_div_by_zero_instruction(bool use_32_bit_width);
#endif //BPF_IR_MEMGENERATOR_H

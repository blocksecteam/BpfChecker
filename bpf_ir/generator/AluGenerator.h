#ifndef BPF_IR_ALUGENERATOR_H
#define BPF_IR_ALUGENERATOR_H

#include "Util.h"
#include <Module.h>

std::vector<TestCase> generate_simple_alu_set();
std::vector<TestCase> generate_one_alu_program();

TestCase generate_div_by_zero_instruction(bool use_32_bit_width);
std::vector<TestCase> generate_shift_instructions();
#endif //BPF_IR_ALUGENERATOR_H

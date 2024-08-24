#ifndef BPF_IR_UTIL_H
#define BPF_IR_UTIL_H

#include <random>
#include "Instruction.h"

// workaround as the randomEngine in mutator has the same random_device
static std::random_device _generic_rd;

static std::mt19937 random_generator(_generic_rd());

struct TestCase {
    BytecodeData data;
    std::string code;
};

static Register getRandomRegister() {
    // Ignore generating R10 to avoid verifier failure (frame pointer is read only).
    return static_cast<Register>(random_generator() % 10);
}

#endif //BPF_IR_UTIL_H

#ifndef BPF_IR_LIFTER_H
#define BPF_IR_LIFTER_H

#include "Module.h"
#include <memory>
#include <cstring>

std::unique_ptr<Module> Lift(unsigned char *data, size_t size);

#endif //BPF_IR_LIFTER_H

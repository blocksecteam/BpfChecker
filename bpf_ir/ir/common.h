#ifndef BPF_IR_COMMON_H
#define BPF_IR_COMMON_H

#include <cstddef>

template<class T>
struct WeightedType {
    T type;
    size_t weight;
};

#endif //BPF_IR_COMMON_H

#ifndef BPF_IR_SEMANTICS_H
#define BPF_IR_SEMANTICS_H

#include <vector>
#include "Module.h"
class SemanticsReport {
public:
    SemanticsReport() = default;

private:
    std::vector<Register> use_before_init;
};

class SemanticsAnalyzer {
public:
    SemanticsAnalyzer() = default;

    SemanticsReport& analyseModule(Module& module){
        return report;
    }

private:
    SemanticsReport report;
};

#endif //BPF_IR_SEMANTICS_H

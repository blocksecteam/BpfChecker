#ifndef BPF_IR_SEMANTICFIXER_H
#define BPF_IR_SEMANTICFIXER_H


#include "BasicBlock.h"
#include "Instruction.h"
#include <vector>
#include <optional>

class ProgramGenerator;

class SemanticFixer {
public:
    explicit SemanticFixer(std::vector<std::unique_ptr<BasicBlock>> &bbs) : bbs_(bbs) {}

    void fixUninitializedRegister(ProgramGenerator* program_generator);
    void fixUninitializedMemory(ProgramGenerator *program_generator);
    void fixUnusedRegisters(ProgramGenerator *program_generator);
    void fixDeadCode(ProgramGenerator *program_generator);
    void fixUninitializedRegisterAggressively(ProgramGenerator *program_generator);
    void fixDivByZero();
    void fixOutOfBounds();
    void fixBasicVerifierRules();


private:
    static std::optional<Register> getInstWriteDstReg(Instruction* inst);
    std::vector<Register> getInstReadReg(Instruction* inst);

    std::vector<std::unique_ptr<BasicBlock>> &bbs_;

    void fixUninitializedRegisterAggressively(ProgramGenerator *program_generator, bool is_aggressive);
};

#endif //BPF_IR_SEMANTICFIXER_H

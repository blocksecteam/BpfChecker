#ifndef BPF_IR_MUTATOR_H
#define BPF_IR_MUTATOR_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <Instruction.h>

class BasicBlock;

class Function;

class Instruction;

class Module;

class ReservedRegisters;

/// Base class for describing how to mutate a module. mutation functions for
/// each IR unit forward to the contained unit.
class IRMutationStrategy {
public:

    const size_t MAX_WEIGHT = 100;
    const size_t TRIVIAL_WEIGHT = 10;

    virtual ~IRMutationStrategy() = default;

    /// Provide a weight to bias towards choosing this strategy for a mutation.
    ///
    /// The value of the weight is arbitrary, but a good default is "the number of
    /// distinct ways in which this strategy can mutate a unit". This can also be
    /// used to prefer strategies that shrink the overall size of the result when
    /// we start getting close to \c MaxSize.
    virtual uint64_t getWeight(size_t CurrentSize, size_t MaxSize,
                               uint64_t CurrentWeight) = 0;

    /// @{
    /// Mutators for each IR unit. By default these forward to a contained
    /// instance of the next smaller unit.
    virtual void mutate(Module &M);

    virtual void mutate(BasicBlock &BB);

//    virtual void mutate(Instruction &I) {
////        unreachable("Strategy does not implement any mutators");
//    }
    /// @}
};

/// Strategy that injects operations into the function.
class InstInjectorStrategy : public IRMutationStrategy {

public:
    InstInjectorStrategy() = default;

    uint64_t getWeight(size_t CurrentSize, size_t MaxSize,
                       uint64_t CurrentWeight) override {
        size_t currentPercent = CurrentSize * 100 / MaxSize;
        if (currentPercent >= SIZE_THRESHOLD_PERCENT) {
            return TRIVIAL_WEIGHT;
        } else {
            return MAX_WEIGHT - currentPercent;
        }
    }

    using IRMutationStrategy::mutate;

    void mutate(Module &M) override;

    void mutate(BasicBlock &BB) override;

private:
    const int SIZE_THRESHOLD_PERCENT = 80;
};

// TODO : shuffle instructions in this strategy
//class InstShuffleStrategy : public IRMutationStrategy {
//public:
//    uint64_t getWeight(size_t CurrentSize, size_t MaxSize,
//                       uint64_t CurrentWeight) override {
//        return 60;
//    }
//
//    using IRMutationStrategy::mutate;
//
//    void mutate(Module &F) override;
//
//    void mutate(BasicBlock &BB) override;
//
//};

class InstDeleterStrategy : public IRMutationStrategy {
public:
    uint64_t getWeight(size_t CurrentSize, size_t MaxSize,
                       uint64_t CurrentWeight) override {

        size_t currentPercent = CurrentSize * 100 / MaxSize;
        if (currentPercent < SIZE_THRESHOLD_PERCENT) {
            return TRIVIAL_WEIGHT;
        } else {
            return currentPercent * 0.8;
        }
    }

    using IRMutationStrategy::mutate;

    void mutate(Module &M) override;

    void mutate(BasicBlock &BB) override;

private:
    const int SIZE_THRESHOLD_PERCENT = 20; // lowest percent of the program
};

class InstModificationStrategy : public IRMutationStrategy {
public:
    uint64_t getWeight(size_t CurrentSize, size_t MaxSize,
                       uint64_t CurrentWeight) override {
        return 4;
    }

    using IRMutationStrategy::mutate;

    void mutate(Module &M) override;

    void mutate(BasicBlock &BB) override;

    // TODO : modify on the instructions
//    void mutate(Instruction &Inst) override;
};

enum class AluOperation {
    MutateSrc,
    MutateDst,
};

/// A description of some operation we can build while fuzzing IR.
struct OpDescriptor {
    unsigned Weight;
//    SmallVector<SourcePred, 2> SourcePreds;
//    std::function<Value *(ArrayRef<Value *>, Instruction *)> BuilderFunc;
};

AluOpcode createRandomAluOpcode();

BranchOpcode createRandomBranchOpcode();

BitWidth createRandomBitWidth();

AluOpcode createRandomPointerAluOpcode();

ModulePtr mutateTemplateModule(ModulePtr);

ModulePtr havocMutateTemplateModule(ModulePtr module);

std::unique_ptr<Instruction> createAluInstruction(AluOpcode opcode);

std::unique_ptr<Instruction> createRandomAluInstruction();

std::unique_ptr<Instruction> createRandomMovInstruction();

std::unique_ptr<Instruction> createRandomLoadImm64Instruction();

std::unique_ptr<Instruction> createRandomLoadInstruction();

std::unique_ptr<Instruction> createRandomLoadPacketInstruction();

std::unique_ptr<Instruction> createRandomStoreInstruction();

std::unique_ptr<Instruction> createRandomCallInstruction();

Variable createRandomVariable(ReservedRegisters *reservedRegisters = nullptr, int64_t maxImm = INT64_MAX,
                              bool isPositive = true);

Register createRandomRegister(ReservedRegisters *reservedRegisters = nullptr);

#endif //BPF_IR_MUTATOR_H

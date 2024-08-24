#ifndef BPF_IR_MODULE_H
#define BPF_IR_MODULE_H

#include "BasicBlock.h"
#include <map>


class ReservedRegisters {
public:
    explicit ReservedRegisters(Register mapFdRegister, Register mapPtrRegister, Register boundRegister) :
            mapFdRegister(mapFdRegister), mapPtrRegister(mapPtrRegister), boundRegister(boundRegister) {

    }

    bool isReservedRegister(Register reg) {
        return this->mapFdRegister == reg || this->mapPtrRegister == reg;
    }

    Register getMapFdRegister() const {
        return this->mapFdRegister;
    }

    Register getMapPtrRegister() const {
        return this->mapPtrRegister;
    }

    void setMapFdRegister(Register reg) {
        this->mapFdRegister = reg;
    }

    void setBoundRegister(Register reg) {
        this->boundRegister = reg;
    }

    Register getBoundRegister() {
        return this->boundRegister;
    }

private:
//    void setMapFdRegister(Register reg) {
//        this->mapFdRegister = reg;
//    }
    Register mapFdRegister;
    Register mapPtrRegister;
    Register boundRegister;
};

class Module {
public:

    explicit Module(ReservedRegisters reversed, size_t map_fd) :
            reservedRegisters(reversed), map_fd(map_fd), enable_header(true) {}

    explicit Module(ReservedRegisters reversed, size_t map_fd, bool enable_header) : reservedRegisters(reversed),
                                                                                     map_fd(map_fd),
                                                                                     enable_header(enable_header) {}

    virtual ~Module() = default;

    void set_header_status(bool enable_header){
        this->enable_header = enable_header;
    }

    void addBasicBlock(BasicBlockPtr blockPtr) {
        blockPtr->setModule(this);
        basicBlocks.push_back(std::move(blockPtr));
    }

    void addBasicBlocks(std::vector<BasicBlockPtr> &blockPtrs) {
        for (auto &blockPtr: blockPtrs) {
            this->addBasicBlock(std::move(blockPtr));
        }
    }

    [[nodiscard]] const std::vector<BasicBlockPtr> &getBasicBlocks() const {
        return this->basicBlocks;
    }

    void updateBlocks() {
        // TODO : sort the basic blocks to keep consistency between blocks
        size_t currentAddress = 0;
        // {requested block : origin blocks}
        std::map<BasicBlock *, std::vector<BasicBlock *>> requestedMap;
        // {block : address}
        std::map<BasicBlock *, size_t> cachedMap;
        for (auto &block: this->basicBlocks) {
            cachedMap.insert({block.get(), currentAddress});
            size_t blockSize = block->getBytecodeSize();
            block->setAddress(currentAddress);
            currentAddress += blockSize;
            if (block->isBranchTerminator()) {
                auto target = block->getTarget();
                if (cachedMap.find(target) != cachedMap.end()) {
                    block->setTargetAddress(cachedMap[target]);
                } else {
                    if (requestedMap.find(target) != requestedMap.end()) {
                        requestedMap[target].push_back(block.get());
                    } else {
                        requestedMap[target] = {block.get()};
                    }
                }
            }
        }
        // update it from request map
        for (auto &iter: requestedMap) {
            auto target = iter.first;
            auto requesters = iter.second;
            auto targetAddressIter = cachedMap.find(target);
            assert(targetAddressIter != cachedMap.end());
            size_t targetAddress = targetAddressIter->second;
            for (auto &requester: requesters) {
                requester->setTargetAddress(targetAddress);
            }
        }
    }

    [[nodiscard]] BytecodeData &CodeGen() {
        this->updateBlocks();
        data.clear();
//        manager = new BytecodeManager(this->_instructions.size());
        if (this->enable_header) {
            data = this->GenerateHeaderCode();
        }
        for (const auto &bb: this->basicBlocks) {
            auto gen = bb->CodeGen();
            data.insert(std::end(data), std::begin(gen), std::end(gen));
        }
        return data;
    }

    [[nodiscard]] ReservedRegisters &getReservedRegisters() {
        return reservedRegisters;
    }

    [[nodiscard]] BytecodeData &GenerateHeaderCode() {
        header.clear();
        __u8 macro_fd_reg = to_underlying(reservedRegisters.getMapFdRegister());

        // load map fd to reserved register
        bpf_insn_type load_fd[] = {BPF_LD_MAP_FD(macro_fd_reg, map_fd)};
        assert(sizeof(load_fd) / sizeof(bpf_insn_type) == 2);
        header.push_back(load_fd[0]);
        header.push_back(load_fd[1]);
        return header;
    }

    void updateMapFd(size_t new_map_fd) {
        this->map_fd = new_map_fd;
    }

    friend std::ostream &operator<<(std::ostream &stream, const Module &module) {
        for (auto &&bb: module.basicBlocks) {
            stream << *bb;
        }
        return stream;
    }

private:
    std::vector<BasicBlockPtr> basicBlocks;
    BytecodeData data;
    ReservedRegisters reservedRegisters;
    BytecodeData header;
    size_t map_fd;
    bool enable_header;
};

static ReservedRegisters defaultReservedRegisters(Register::REG_9, Register::REG_8, Register::REG_7);

#endif //BPF_IR_MODULE_H

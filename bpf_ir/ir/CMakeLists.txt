CMAKE_MINIMUM_REQUIRED(VERSION 3.10.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing -w")

add_library(ir SHARED
        Instruction.cpp util/irDump.h util/irDump.cpp BasicBlock.cpp BasicBlock.h Module.h Semantics.h ir.h Template.cpp Template.h
        Lifter.cpp Lifter.h util/bpf_header.h common.h) #

# target_link_directories(ir PRIVATE .)
# option(ENABLE_TEST "enable test for ir library" ON)

# if (${ENABLE_TEST})
#     include(FetchContent)
#     FetchContent_Declare(
#             googletest
#             URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
#     )
#     # For Windows: Prevent overriding the parent project's compiler/linker settings
#     set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
#     FetchContent_MakeAvailable(googletest)
#     add_subdirectory(test)
# endif ()

add_executable(selfInstructionTest ProgramTest.cpp)
target_link_libraries(selfInstructionTest ir)
target_include_directories(selfInstructionTest PRIVATE ./)

#add_executable(load_ir ../native_load.c)
#include_directories(./)
#target_link_libraries(load_ir ir)
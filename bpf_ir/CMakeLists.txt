CMAKE_MINIMUM_REQUIRED(VERSION 3.10.2)


project(bpf-ir)

option(USE_AFL "USE AFL CLANG" OFF)
if (USE_AFL)
    message(STATUS "USE AFL BUILD")
    set(CMAKE_C_COMPILER "/path/to/AFLplusplus/afl-clang-fast")
    set(CMAKE_CXX_COMPILER "/path/to/AFLplusplus/afl-clang-fast++")
endif ()

set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_CXX_FLAGS_DEBUG} -g")

include_directories(argparse)
add_subdirectory(ir)
add_subdirectory(mutator)
add_subdirectory(generator)
add_subdirectory(disassembler)

add_executable(load_ir native_load.c)
target_include_directories(load_ir PRIVATE ir)
target_link_libraries(load_ir ir)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lrt -lpthread")

add_executable(lkl_load lkl_load.c)
target_include_directories(lkl_load PRIVATE ir)
target_include_directories(lkl_load PRIVATE /path/to/lkl/tools/lkl/include)
target_link_libraries(lkl_load ir rt)
target_link_libraries(lkl_load /path/to/lkl/tools/lkl/lib/liblkl.so)


add_subdirectory(fuzzer)
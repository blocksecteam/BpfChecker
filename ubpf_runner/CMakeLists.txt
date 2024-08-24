cmake_minimum_required(VERSION 3.10)
project(ubpf_runner)
#set(CMAKE_CXX_STANDARD 20)

if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20")
elseif (APPLE)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
elseif (LINUX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -g")
    link_libraries(stdc++fs)
endif ()

add_subdirectory(runner)

option(ENABLE_FUZZER "enable fuzzers" OFF)
option(ENABLE_SANITIZE "enable sanitize" ON)
if (ENABLE_FUZZER)
    #    set(FUZZ_FLAG "-fsanitize=address,undefined")
    #    set(FUZZ_FLAG "-fsanitize=fuzzer,address") # undefined
    set(FUZZ_FLAG "-fsanitize=fuzzer,address -fno-sanitize=undefined") # undefined
    #    set(FUZZ_FLAG "-fsanitize=fuzzer") # undefined
    #    set(FUZZ_FLAG "-fsanitize=fuzzer,memory")
    #  set(FUZZ_FLAG "-fsanitize=fuzzer") # undefined
    #    set(FUZZ_FLAG "-fsanitize=address") # undefined
    set(COMMON_FLAGS "-g ") # -Wall
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAG} ${COMMON_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FUZZ_FLAG} ${COMMON_FLAGS}")
elseif (ENABLE_SANITIZE)
    set(COMMON_FLAGS "-g -fsanitize=address,undefined -fsanitize-recover=address") # -Wall
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")
endif ()

IF (UNIX AND NOT APPLE)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_WIN32_THREADS_INIT 0)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    #    fix on Linux
    #    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -D_HAS_AUTO_PTR_ETC=1")
ENDIF ()

#add_subdirectory(ubpf)
add_subdirectory(ebpf-verifier)
# from ebpf-verifier
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
        "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    find_package(yaml-cpp REQUIRED)
    find_package(Boost REQUIRED)
    set(CMAKE_CXX_STANDARD 17)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    find_program(NUGET nuget)
    if (NOT NUGET)
        message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
    else ()
        exec_program(${NUGET} ARGS install "Boost" -Version 1.78.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    endif ()
    set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
    # MSVC's C++17 standard option doesn't actually support all the C++17
    # features we use, but its "latest" option does.  However, cmake can't
    # deal with that here, so we set it below.

    set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/packages/yaml-cpp)
    include(ExternalProject)
    ExternalProject_Add(yaml-cpp
            GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
            GIT_TAG "yaml-cpp-0.7.0"
            GIT_SHALLOW true
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
            -DYAML_MSVC_SHARED_RT=ON
            -DYAML_CPP_BUILD_TESTS=OFF
            -DYAML_CPP_BUILD_TOOLS=OFF
            )
    set(YAML_CPP_LIBRARIES ${EXTERNAL_INSTALL_LOCATION}/lib/yaml-cpp$<$<CONFIG:DEBUG>:d>.lib)
    set(YAML_CPP_INCLUDE_DIRS ${EXTERNAL_INSTALL_LOCATION}/include/)
endif ()

# definition of all sorts of fuzzer/runner
set(BASIC_VERIFIER_HEADERS ebpf-verifier/src ebpf-verifier/src/main ebpf-verifier/external/ELFIO ebpf-verifier/external ${VERIFIER_HEADER_DIRS} ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS} ${Boost_LIBRARY_DIRS})
find_package(Threads REQUIRED)

function(basic_build my_target)
    target_include_directories(${my_target} PRIVATE ${BASIC_VERIFIER_HEADERS} ./runner)
    target_link_libraries(${my_target} PRIVATE ebpfverifier)
endfunction()

function(basic_runner_build my_target)
    basic_build(${my_target})
    target_link_libraries(${my_target} PRIVATE ubpf_runner_core)
endfunction()

add_executable(ubpf_runner ubpf_runner.cpp)
add_executable(prevail_fuzzer verifier_fuzzer.cpp)
add_executable(runner_fuzzer runner_fuzzer.cpp)
add_executable(parser_fuzzer parser_fuzzer.cpp)
add_executable(prevail_repro verifier_fuzzer.cpp verifier_fuzzer_repro.cpp)

basic_runner_build(ubpf_runner)
target_link_libraries(ubpf_runner PRIVATE Threads::Threads)

basic_runner_build(runner_fuzzer)
basic_build(prevail_fuzzer)
basic_build(parser_fuzzer)
basic_build(prevail_repro)

# ignore some targets
#set_target_properties(tests run_yaml PROPERTIES EXCLUDE_FROM_ALL 1 EXCLUDE_FROM_DEFAULT_BUILD 1)

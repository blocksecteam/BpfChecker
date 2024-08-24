file(GLOB UBPF_SRC_FILES ${PROJECT_SOURCE_DIR}/ubpf/vm/ubpf_*.c ${PROJECT_SOURCE_DIR}/ubpf/vm/*.h)
add_library(ubpf_eng ${UBPF_SRC_FILES})
target_include_directories(ubpf_eng PUBLIC ${PROJECT_SOURCE_DIR}/ubpf/vm/inc)
target_include_directories(ubpf_eng PUBLIC ./)

add_library(ubpf_runner_core runner_core.cpp)
target_link_libraries(ubpf_runner_core ubpf_eng)

# example only
#add_executable(runner_core_attestation attestation.cpp)
#target_link_libraries(runner_core_attestation ubpf_runner_core)
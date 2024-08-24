enable_testing()
include(GoogleTest)
add_executable(
        InstructionTest
        InstructionTest.cpp
)

target_link_libraries(
        InstructionTest
        gtest_main
        ir
)
target_include_directories(InstructionTest PRIVATE ../)
gtest_discover_tests(InstructionTest)
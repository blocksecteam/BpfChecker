set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing")
add_library(mutator SHARED operation.cpp mutator.cpp randomEngine.h config.h)
target_link_libraries(mutator ir)
target_include_directories(mutator PRIVATE ../ir)

add_executable(mutator_test mutatorTest.cpp )
target_include_directories(mutator_test PRIVATE ../ir)
target_include_directories(mutator_test PRIVATE ../experimental_fuzzer)
target_link_libraries(mutator_test mutator)

add_library(afl_mutator SHARED custom_mutator.cpp)
target_include_directories(afl_mutator PRIVATE ../ir)
target_link_libraries(afl_mutator mutator)
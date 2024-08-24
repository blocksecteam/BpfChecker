set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing")
add_library(randomizer Randomizer.hpp RandomizerConst.hpp)
target_include_directories(randomizer PRIVATE ../ir)
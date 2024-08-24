set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing")
add_executable(disassembler disassembler.cpp)
target_link_libraries(disassembler ir)
target_include_directories(disassembler PRIVATE ../ir)
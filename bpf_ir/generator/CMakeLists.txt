set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing")
add_executable(generator
        Generator.cpp include/Util.h AluGenerator.cpp AluGenerator.h MemGenerator.cpp MemGenerator.h JmpGenerator.cpp JmpGenerator.h ProgramGenerator.cpp include/ProgramGenerator.h uBPFGenerator.cpp include/uBPFGenerator.h SemanticFixer.cpp include/SemanticFixer.h include/rBPFGenerator.h rBPFGenerator.cpp
        )
target_link_libraries(generator ir)
#target_link_libraries(generator mutator)
target_include_directories(generator PRIVATE ../ir)
#target_include_directories(generator PRIVATE ../mutator)
target_include_directories(generator PRIVATE include)
target_include_directories(generator PRIVATE ../randomizer)

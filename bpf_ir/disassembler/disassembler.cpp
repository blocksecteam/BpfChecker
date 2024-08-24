#include <fstream>
#include <iostream>
#include "Lifter.h"

using namespace std;

int main(int argc, char **argv) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <object_file>\n";
        exit(-1);
    }
    char *filename = argv[1];
    ifstream file(filename, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    auto module = Lift(buffer.data(), buffer.size());
    cout << *module << endl;
}
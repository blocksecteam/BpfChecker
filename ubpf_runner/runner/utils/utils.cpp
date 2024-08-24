#include "util.h"
#include <string>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

string read_file(const string &fileName) {
    ifstream ifs(fileName.c_str(), ios::in | ios::binary | ios::ate);

    ifstream::pos_type fileSize = ifs.tellg();
    ifs.seekg(0, ios::beg);

    vector<char> bytes(fileSize);
    ifs.read(bytes.data(), fileSize);

    return string(bytes.data(), fileSize);
}

//std::vector<std::byte> load_file(std::string const& filepath)
//{
//    std::ifstream ifs(filepath, std::ios::binary|std::ios::ate);
//
//    if(!ifs)
//        throw std::runtime_error(filepath + ": " + std::strerror(errno));
//
//    auto end = ifs.tellg();
//    ifs.seekg(0, std::ios::beg);
//
//    auto size = std::size_t(end - ifs.tellg());
//
//    if(size == 0) // avoid undefined behavior
//        return {};
//
//    std::vector<std::byte> buffer(size);
//
//    if(!ifs.read((char*)buffer.data(), buffer.size()))
//        throw std::runtime_error(filepath + ": " + std::strerror(errno));
//
//    return buffer;
//}

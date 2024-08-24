#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern char *read_file(char *path, size_t *length);

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage %s filename\n", argv[0]);
        return -1;
    }
    size_t size;
    char *data = read_file(argv[1], &size);
    if (!data) {
        printf("invalid file.\n");
        return -1;
    }
    LLVMFuzzerTestOneInput((const uint8_t *const) data, size);
    free(data);
    data = nullptr;
    return 0;
}
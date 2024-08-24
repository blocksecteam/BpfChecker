#ifndef BPF_IR_PROGRAMTEST_H
#define BPF_IR_PROGRAMTEST_H


extern unsigned char *getInnerTestData(size_t *size);

#ifdef __cplusplus
extern "C" {
#endif

//unsigned char *getTestData(size_t *size){
//    return NULL;
//}
unsigned char *getTestData(size_t *size) {
//    Module module(defaultReservedRegisters, 3);
    return NULL;
//    return getInnerTestData(size);
}


#ifdef __cplusplus
};
#endif

#endif //BPF_IR_PROGRAMTEST_H

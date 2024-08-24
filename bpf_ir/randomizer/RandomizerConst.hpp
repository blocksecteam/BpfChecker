#pragma once

#ifndef BPF_IR_RANDOMIZERCONST_H
#define BPF_IR_RANDOMIZERCONST_H

#include <cstdint>
#include <cstddef>
#include <limits>
#define INTERESTING_8                                    \
  -128,    /* Overflow signed 8-bit when decremented  */ \
      -1,  /*                                         */ \
      0,   /*                                         */ \
      1,   /*                                         */ \
      16,  /* One-off with common buffer size         */ \
      32,  /* One-off with common buffer size         */ \
      64,  /* One-off with common buffer size         */ \
      100, /* One-off with common buffer size         */ \
      127                        /* Overflow signed 8-bit when incremented  */

//#define INTERESTING_8_LEN 9

#define INTERESTING_16                                    \
  -32768,   /* Overflow signed 16-bit when decremented */ \
      -129, /* Overflow signed 8-bit                   */ \
      128,  /* Overflow signed 8-bit                   */ \
      255,  /* Overflow unsig 8-bit when incremented   */ \
      256,  /* Overflow unsig 8-bit                    */ \
      512,  /* One-off with common buffer size         */ \
      1000, /* One-off with common buffer size         */ \
      1024, /* One-off with common buffer size         */ \
      4096, /* One-off with common buffer size         */ \
      32767                      /* Overflow signed 16-bit when incremented */

//#define INTERESTING_16_LEN 10

#define INTERESTING_32                                          \
  -2147483648LL,  /* Overflow signed 32-bit when decremented */ \
      -100663046, /* Large negative number (endian-agnostic) */ \
      -32769,     /* Overflow signed 16-bit                  */ \
      32768,      /* Overflow signed 16-bit                  */ \
      65535,      /* Overflow unsig 16-bit when incremented  */ \
      65536,      /* Overflow unsig 16 bit                   */ \
      100663045,  /* Large positive number (endian-agnostic) */ \
      2147483647                 /* Overflow signed 32-bit when incremented */

//#define INTERESTING_32_LEN 8

static int8_t interesting_8[] = {INTERESTING_8};
static  int16_t interesting_16[] = {INTERESTING_8, INTERESTING_16};

static int16_t interesting_offset[] = {-2, -1, 0, 1, 2, 3, 4, 8, 16, 32, 64, 127, 128,};

static int32_t interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};
static int64_t interesting_64[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32,
                            INT64_MAX,
                            INT64_MAX >> 1,
                            INT64_MAX - 1,
                            INT64_MIN,
                            INT64_MIN + 1,
                            INT64_MIN >> 1,
                            25769803777,
                            INT32_MAX + 1L,
                            INT32_MAX + 2L,
                            UINT32_MAX + 1L,
                            UINT32_MAX + 2L,
                            0x100000000, // rbpf memory address related
                            0x10000000 - 1,
                            0x10000000 + 1,
                            0x200000000 - 1,
                            0x200000000 + 1,
                            0x300000000 - 1,
                            0x300000000 + 1,
                            0x400000000 - 1,
                            0x400000000 + 1,
                            0x500000000,
};
static constexpr size_t interesting_8_length = sizeof(interesting_8) / sizeof(int8_t);
static constexpr size_t interesting_16_length = sizeof(interesting_16) / sizeof(int16_t);
static constexpr size_t interesting_offset_length = sizeof(interesting_offset) / sizeof(int16_t);
static constexpr size_t interesting_32_length = sizeof(interesting_32) / sizeof(int32_t);
static constexpr size_t interesting_64_length = sizeof(interesting_64) / sizeof(int64_t);
static_assert(sizeof interesting_32 == (9 + 10 + 8) * 4, "");

#endif //BPF_IR_RANDOMIZERCONST_H

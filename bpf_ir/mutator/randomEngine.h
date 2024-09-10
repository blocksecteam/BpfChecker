#ifndef BPF_IR_RANDOMENGINE_H
#define BPF_IR_RANDOMENGINE_H

// DEPRECATED, use randomizer instead.

#include <chrono>
#include <ctime>
#include <random>
#include "config.h"

std::random_device generic_rd;
std::mt19937 generator(generic_rd());
//// seed value is designed specifically to make initialization
//// parameters of std::mt19937 (instance of std::mersenne_twister_engine<>)
//// different across executions of application
//static std::mt19937::result_type seed = rd() ^ (
//        (std::mt19937::result_type)
//                std::chrono::duration_cast<std::chrono::seconds>(
//                        std::chrono::system_clock::now().time_since_epoch()
//                ).count() +
//        (std::mt19937::result_type)
//                std::chrono::duration_cast<std::chrono::microseconds>(
//                        std::chrono::high_resolution_clock::now().time_since_epoch()
//                ).count());
//std::mt19937 gen(seed);

class RandomEngine {
public:
    explicit RandomEngine(std::vector<size_t> &weights) {
        std::random_device rd;
        std::mt19937::result_type seed = rd() ^ (
                (std::mt19937::result_type)
                        std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch()
                        ).count() +
                (std::mt19937::result_type)
                        std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::high_resolution_clock::now().time_since_epoch()
                        ).count());
        gen = std::mt19937(seed);
        dist = std::discrete_distribution<int>(std::begin(weights), std::end(weights));
    }

    size_t randomChoice() {
        return dist(gen);
    }

private:
    std::discrete_distribution<int> dist;
    std::mt19937 gen;
};

bool shouldDo(unsigned int probablity) {
    if (probablity > 100) {
        probablity = 100;
    }
    unsigned int random_number = generator() % 100;
    return random_number <= probablity;
}

//#include "config.h"

#define RAND_BELOW(limit) (generator() % (limit))
#define RAND_LE(limit) (generator() % (limit) + 1)

class MagicNumber {
public:

    template<class T>
    static T combineTwoNumber(T a, T b) {
        enum INNER_OPERATE {
            ADD,
            SUB,
            MUL,
            END
        };
        uint8_t combine_operator = RAND_BELOW((uint8_t) INNER_OPERATE::END);
        switch (combine_operator) {
            case INNER_OPERATE::ADD:
                return (T) (a + b);
            case INNER_OPERATE::SUB:
                return (T) (a - b);
            case INNER_OPERATE::MUL:
                return (T) (a * b);
            default:
                return (T) (a + b);
        }
    }

    static bool should_combine() {
        return RAND_BELOW(2) == 1;
    }

    static int8_t getRandomInt8() {
        if (shouldDo(50))
//            return RAND_LE(INT8_MAX);
            return (int8_t) generator();
        if (!should_combine()) {
            return interesting_8[RAND_BELOW(interesting_8_length)];
        } else {
            return combineTwoNumber<int8_t>(interesting_8[RAND_BELOW(interesting_8_length)],
                                            interesting_8[RAND_BELOW(interesting_8_length)]);
        }
    }

    static int16_t getRandomInt16() {
        if (shouldDo(50))
//            return RAND_BELOW(INT16_MAX);
            return (int16_t) generator();
        if (!should_combine()) {
            return interesting_16[RAND_BELOW(interesting_16_length)];
        } else {
            return combineTwoNumber<int16_t>(interesting_16[RAND_BELOW(interesting_16_length)],
                                             interesting_16[RAND_BELOW(interesting_16_length)]);
        }
    }

    static int32_t getRandomInt32() {
        if (shouldDo(50))
//            return RAND_LE(INT32_MAX);
            return (int32_t) generator();
        if (!should_combine()) {
            return interesting_32[RAND_BELOW(interesting_32_length)];
        } else {
            return combineTwoNumber<int32_t>(interesting_32[RAND_BELOW(interesting_32_length)],
                                             RAND_BELOW(INT32_MAX));
        }
    }

    static int64_t getRandomInt64() {
        if (shouldDo(50))
            return (int64_t) generator();
        if (!should_combine()) {
            return interesting_64[RAND_BELOW(interesting_64_length)];
        } else {
            return combineTwoNumber<int64_t>(interesting_64[RAND_BELOW(interesting_64_length)],
                                             RAND_BELOW(INT64_MAX));
        }
    }

    static int16_t getRandomOffset16() {
        if (shouldDo(50))
//            return RAND_LE(INT16_MAX);
            return (int16_t) generator();
        return interesting_offset[RAND_BELOW(interesting_offset_length)];
    }

    static int32_t getRandomOffset32() {
        if (shouldDo(50)) {
            return interesting_offset[RAND_BELOW(interesting_offset_length)];
        } else {
            return getRandomInt32();
        }
    }

private:

};

#endif //BPF_IR_RANDOMENGINE_H

#include "ir.h"
#include "Lifter.h"
#include "Module.h"
#include "mutator.h"
#include "Template.h"
#include "randomEngine.h"
#include <cstdlib>

// This is an AFL mutator, we aim to generate havoc programs in the initial fuzzing stage.

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
extern "C"
void afl_custom_init(void *afl, unsigned int seed) {

    srand(seed);  // needed also by surgical_havoc_mutate()

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
extern "C"
size_t afl_custom_fuzz(void *custom_data, uint8_t *in_buf, size_t in_buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {

    // Make sure that the packet size does not exceed the maximum size expected by
    // the fuzzer
    std::unique_ptr<Module> module = Lift(in_buf, in_buf_size);

    if (shouldDo(50)) {
        module = mutateTemplateModule(std::move(module));
    } else {
        module = havocMutateTemplateModule(std::move(module));
    }

    auto result = module->CodeGen();
    size_t result_size = result.size() * sizeof(result[0]);
    auto mutated_out = (unsigned char *) malloc(result_size);

    // Randomly select a command string to add as a header to the packet
    memcpy(mutated_out, reinterpret_cast<const char *>(result.data()), result_size);

    *out_buf = mutated_out;
    return result_size;

}

/**
 * Perform a single custom mutation on a given input.
 * This mutation is stacked with the other muatations in havoc.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to the input data to be mutated and the mutated
 *     output
 * @param[in] buf_size Size of input data
 * @param[out] out_buf The output buffer. buf can be reused, if the content
 * fits. *out_buf = NULL is treated as error.
 * @param[in] max_size Maximum size of the mutated output. The mutation must
 *     not produce data larger than max_size.
 * @return Size of the mutated output.
 */
extern "C"
size_t afl_custom_havoc_mutation(void *custom_data, uint8_t *in_buf, size_t in_buf_size,
                                 uint8_t **out_buf, size_t max_size) {

    std::unique_ptr<Module> module = Lift(in_buf, in_buf_size);
    module = havocMutateTemplateModule(std::move(module));
    auto result = module->CodeGen();
    size_t result_size = result.size() * sizeof(result[0]);
    auto mutated_out = (unsigned char *) malloc(result_size);

    // Randomly select a command string to add as a header to the packet
    memcpy(mutated_out, reinterpret_cast<const char *>(result.data()), result_size);

    *out_buf = mutated_out;
    return result_size;

}

/**
 * Return the probability (in percentage) that afl_custom_havoc_mutation
 * is called in havoc. By default it is 6 %.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @return The probability (0-100).
 */
extern "C"
uint8_t afl_custom_havoc_mutation_probability(void *data) {

    return 50;

}

/**
 * Determine whether the fuzzer should fuzz the queue entry or not.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param filename File name of the test case in the queue entry
 * @return Return True(1) if the fuzzer will fuzz the queue entry, and
 *     False(0) otherwise.
 */
extern "C"
uint8_t afl_custom_queue_get(void *data, const uint8_t *filename) {

    return 1;

}

/**
 * Allow for additional analysis (e.g. calling a different tool that does a
 * different kind of coverage and saves this for the custom mutator).
 *
 * (Optional)
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param filename_new_queue File name of the new queue entry
 * @param filename_orig_queue File name of the original queue entry
 */
extern "C"
void afl_custom_queue_new_entry(void *data,
                                const uint8_t *filename_new_queue,
                                const uint8_t *filename_orig_queue) {

    /* Additional analysis on the original or new test case */

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
extern "C"
void afl_custom_deinit(void *data) {

//    free(data->post_process_buf);
//    free(data->havoc_buf);
//    free(data->data_buf);
//    free(data->fuzz_buf);
//    free(data->trim_buf);
//    free(data);

}

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

typedef uint64_t u64;

#ifndef ZEC_RUST_LIB
#define ZEC_RUST_LIB

#ifdef __cplusplus
extern "C" {
#endif

void librustzcash_sapling_generate_r(
        unsigned char *result
);

#ifdef __cplusplus
}
#endif

#endif /* ZEC_RUST_LIB */
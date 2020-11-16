#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

typedef uint64_t u64;

#ifndef ZAPLING_LIB
#define ZAPLING_LIB

#ifdef __cplusplus
extern "C" {
#endif

void librustzcash_sapling_generate_r(
        unsigned char *result
);

#ifdef __cplusplus
}
#endif

#endif /* ZAPLING_LIB */
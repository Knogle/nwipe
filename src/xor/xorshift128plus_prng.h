/*
 * xorshift128+ PRNG (Public Domain)
 *
 * This header declares:
 *   1) A state structure xorshift128plus_state_t (128-bit state + an unused 'p').
 *   2) xorshift128plus_init(...) to initialize the PRNG with up to 2 seeds.
 *   3) xorshift128plus_genrand_uint128_to_buf(...) to generate 128 bits (16 bytes).
 *
 * NOT FOR CRYPTOGRAPHIC USE.
 */

#ifndef XORSHIFT128PLUS_PRNG_H
#define XORSHIFT128PLUS_PRNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xorshift128plus_state_s:
 *  - 128-bit internal state stored in s[2].
 *  - 'p' is included per request but is not strictly used in xorshift128+.
 */
typedef struct xorshift128plus_state_s
{
    uint64_t s[2];   /* 128-bit state */
    int p;           /* not used by the core algorithm, but kept per request */
} xorshift128plus_state_t;

/**
 * Initializes the xorshift128+ state with up to 2 seed values.
 * If fewer than 2 seeds are provided, a fallback is used to fill the rest.
 */
void xorshift128plus_init( xorshift128plus_state_t* state,
                           uint64_t init_key[],
                           unsigned long key_length );

/**
 * Generates 128 bits (16 bytes) of random data and writes them into 'bufpos'.
 * The buffer must have space for 16 bytes.
 */
void xorshift128plus_genrand_uint128_to_buf( xorshift128plus_state_t* state,
                                             unsigned char* bufpos );

#ifdef __cplusplus
}
#endif

#endif /* XORSHIFT128PLUS_PRNG_H */

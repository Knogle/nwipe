/*
 * xorshift128+ PRNG Implementation (Public Domain)
 *
 * This file implements the xorshift128+ algorithm by Sebastiano Vigna:
 *   - 128-bit internal state (2 x 64-bit).
 *   - Period 2^128 - 1.
 *
 * Exposes exactly two functions requested by the user:
 *   1) xorshift128plus_init(...)
 *   2) xorshift128plus_genrand_uint128_to_buf(...)
 */

#include "xorshift128plus_prng.h"
#include <string.h> /* for memcpy */

/* 
 * A static inline function to produce one 64-bit xorshift128+ output.
 * xorshift128+ steps:
 *   s1 = s[0]
 *   s0 = s[1]
 *   s[0] = s0
 *   s1 ^= s1 << 23
 *   s1 ^= s1 >> 17
 *   s0 ^= s0 >> 26
 *   s[1] = s0 ^ s1
 *   return s[1] + s0
 */
static inline uint64_t xorshift128plus_next( xorshift128plus_state_t* state )
{
    uint64_t s1 = state->s[0];
    const uint64_t s0 = state->s[1];

    /* Move the second element into the first. */
    state->s[0] = s0;

    /* Scramble s1 with shifts and XOR. */
    s1 ^= s1 << 23;
    s1 ^= s1 >> 17;

    /* Scramble s0 with shift and XOR. */
    uint64_t s0_shifted = s0 ^ (s0 >> 26);

    /* Final new state. */
    state->s[1] = s1 ^ s0_shifted;

    /* xorshift128+ returns the sum of the two final 64-bit states. */
    return state->s[1] + s0;
}

void xorshift128plus_init( xorshift128plus_state_t* state,
                           uint64_t init_key[],
                           unsigned long key_length )
{
    /* If you provide 0, 1, or 2 seeds, we'll fill in the rest. */
    if (key_length > 0) {
        state->s[0] = init_key[0];
    } else {
        /* Some fallback seed if none is provided. */
        state->s[0] = 0x12345678ABCDEF01ULL;
    }

    if (key_length > 1) {
        state->s[1] = init_key[1];
    } else {
        /* Another fallback if only one seed was given (or none). */
        state->s[1] = state->s[0] ^ 0x9E3779B97F4A7C15ULL;
    }

    /* 'p' is not used by xorshift128+, but we set it to 0 anyway. */
    state->p = 0;
}

/*
 * Generates 128 bits (16 bytes) in one call by taking two consecutive 64-bit outputs 
 * from xorshift128plus_next(...) and storing them to 'bufpos'.
 */
void xorshift128plus_genrand_uint128_to_buf( xorshift128plus_state_t* state,
                                             unsigned char* bufpos )
{
    /* Produce two 64-bit outputs. */
    uint64_t r0 = xorshift128plus_next(state);
    uint64_t r1 = xorshift128plus_next(state);

    /* Copy them to the output buffer. */
    memcpy(bufpos,     &r0, sizeof(uint64_t));
    memcpy(bufpos + 8, &r1, sizeof(uint64_t));
}


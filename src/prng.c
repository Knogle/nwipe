/*
 *  prng.c: Pseudo Random Number Generator abstractions for nwipe.
 *
 *  Copyright Darik Horn <dajhorn-dban@vanadac.com>.
 *
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation, version 2.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "nwipe.h"
#include "prng.h"
#include "context.h"
#include "logging.h"

#include "mt19937ar-cok/mt19937ar-cok.h"
#include "isaac_rand/isaac_rand.h"
#include "isaac_rand/isaac64.h"
#include "alfg/add_lagg_fibonacci_prng.h"  //Lagged Fibonacci generator prototype
#include "xor/xoroshiro256_prng.h"  //XORoshiro-256 prototype
#include "aes/aes_ctr_prng.h"  // AES-NI prototype

nwipe_prng_t nwipe_twister = { "Mersenne Twister (mt19937ar-cok)", nwipe_twister_init, nwipe_twister_read };

nwipe_prng_t nwipe_isaac = { "ISAAC (rand.c 20010626)", nwipe_isaac_init, nwipe_isaac_read };
nwipe_prng_t nwipe_isaac64 = { "ISAAC-64 (isaac64.c)", nwipe_isaac64_init, nwipe_isaac64_read };

/* ALFG PRNG Structure */
nwipe_prng_t nwipe_add_lagg_fibonacci_prng = { "Lagged Fibonacci generator",
                                               nwipe_add_lagg_fibonacci_prng_init,
                                               nwipe_add_lagg_fibonacci_prng_read };
/* XOROSHIRO-256 PRNG Structure */
nwipe_prng_t nwipe_xoroshiro256_prng = { "XORoshiro-256", nwipe_xoroshiro256_prng_init, nwipe_xoroshiro256_prng_read };

/* AES-CTR-NI PRNG Structure */
nwipe_prng_t nwipe_aes_ctr_prng = { "AES-CTR (Kernel)", nwipe_aes_ctr_prng_init, nwipe_aes_ctr_prng_read };

/* Print given number of bytes from unsigned integer number to a byte stream buffer starting with low-endian. */
static inline void u32_to_buffer( u8* restrict buffer, u32 val, const int len )
{
    for( int i = 0; i < len; ++i )
    {
        buffer[i] = (u8) ( val & 0xFFUL );
        val >>= 8;
    }
}
static inline void u64_to_buffer( u8* restrict buffer, u64 val, const int len )
{
    for( int i = 0; i < len; ++i )
    {
        buffer[i] = (u8) ( val & 0xFFULL );
        val >>= 8;
    }
}
static inline u32 isaac_nextval( randctx* restrict ctx )
{
    if( ctx->randcnt == 0 )
    {
        isaac( ctx );
        ctx->randcnt = RANDSIZ;
    }
    ctx->randcnt--;
    return ctx->randrsl[ctx->randcnt];
}
static inline u64 isaac64_nextval( rand64ctx* restrict ctx )
{
    if( ctx->randcnt == 0 )
    {
        isaac64( ctx );
        ctx->randcnt = RANDSIZ;
    }
    ctx->randcnt--;
    return ctx->randrsl[ctx->randcnt];
}

int nwipe_twister_init( NWIPE_PRNG_INIT_SIGNATURE )
{
    nwipe_log( NWIPE_LOG_NOTICE, "Initialising Mersenne Twister prng" );

    if( *state == NULL )
    {
        /* This is the first time that we have been called. */
        *state = malloc( sizeof( twister_state_t ) );
    }
    twister_init( (twister_state_t*) *state, (u32*) ( seed->s ), seed->length / sizeof( u32 ) );
    return 0;
}

int nwipe_twister_read( NWIPE_PRNG_READ_SIGNATURE )
{
    u8* restrict bufpos = buffer;
    size_t words = count / SIZE_OF_TWISTER;  // the values of twister_genrand_int32 is strictly 4 bytes

    /* Twister returns 4-bytes per call, so progress by 4 bytes. */
    for( size_t ii = 0; ii < words; ++ii )
    {
        u32_to_buffer( bufpos, twister_genrand_int32( (twister_state_t*) *state ), SIZE_OF_TWISTER );
        bufpos += SIZE_OF_TWISTER;
    }

    /* If there is some remainder copy only relevant number of bytes to not
     * overflow the buffer. */
    const size_t remain = count % SIZE_OF_TWISTER;  // SIZE_OF_TWISTER is strictly 4 bytes
    if( remain > 0 )
    {
        u32_to_buffer( bufpos, twister_genrand_int32( (twister_state_t*) *state ), remain );
    }

    return 0;
}

int nwipe_isaac_init( NWIPE_PRNG_INIT_SIGNATURE )
{
    int count;
    randctx* isaac_state = *state;

    nwipe_log( NWIPE_LOG_NOTICE, "Initialising Isaac prng" );

    if( *state == NULL )
    {
        /* This is the first time that we have been called. */
        *state = malloc( sizeof( randctx ) );
        isaac_state = *state;

        /* Check the memory allocation. */
        if( isaac_state == 0 )
        {
            nwipe_perror( errno, __FUNCTION__, "malloc" );
            nwipe_log( NWIPE_LOG_FATAL, "Unable to allocate memory for the isaac state." );
            return -1;
        }
    }

    /* Take the minimum of the isaac seed size and available entropy. */
    if( sizeof( isaac_state->randrsl ) < seed->length )
    {
        count = sizeof( isaac_state->randrsl );
    }
    else
    {
        memset( isaac_state->randrsl, 0, sizeof( isaac_state->randrsl ) );
        count = seed->length;
    }

    if( count == 0 )
    {
        /* Start ISACC without a seed. */
        randinit( isaac_state, 0 );
    }
    else
    {
        /* Seed the ISAAC state with entropy. */
        memcpy( isaac_state->randrsl, seed->s, count );

        /* The second parameter indicates that randrsl is non-empty. */
        randinit( isaac_state, 1 );
    }

    return 0;
}

int nwipe_isaac_read( NWIPE_PRNG_READ_SIGNATURE )
{
    randctx* isaac_state = *state;
    u8* restrict bufpos = buffer;
    size_t words = count / SIZE_OF_ISAAC;  // the values of isaac is strictly 4 bytes

    /* Isaac returns 4-bytes per call, so progress by 4 bytes. */
    for( size_t ii = 0; ii < words; ++ii )
    {
        /* get the next 32bit random number */
        u32_to_buffer( bufpos, isaac_nextval( isaac_state ), SIZE_OF_ISAAC );
        bufpos += SIZE_OF_ISAAC;
    }

    /* If there is some remainder copy only relevant number of bytes to not overflow the buffer. */
    const size_t remain = count % SIZE_OF_ISAAC;  // SIZE_OF_ISAAC is strictly 4 bytes
    if( remain > 0 )
    {
        u32_to_buffer( bufpos, isaac_nextval( isaac_state ), remain );
    }

    return 0;
}

int nwipe_isaac64_init( NWIPE_PRNG_INIT_SIGNATURE )
{
    int count;
    rand64ctx* isaac_state = *state;

    nwipe_log( NWIPE_LOG_NOTICE, "Initialising ISAAC-64 prng" );

    if( *state == NULL )
    {
        /* This is the first time that we have been called. */
        *state = malloc( sizeof( rand64ctx ) );
        isaac_state = *state;

        /* Check the memory allocation. */
        if( isaac_state == 0 )
        {
            nwipe_perror( errno, __FUNCTION__, "malloc" );
            nwipe_log( NWIPE_LOG_FATAL, "Unable to allocate memory for the isaac state." );
            return -1;
        }
    }

    /* Take the minimum of the isaac seed size and available entropy. */
    if( sizeof( isaac_state->randrsl ) < seed->length )
    {
        count = sizeof( isaac_state->randrsl );
    }
    else
    {
        memset( isaac_state->randrsl, 0, sizeof( isaac_state->randrsl ) );
        count = seed->length;
    }

    if( count == 0 )
    {
        /* Start ISACC without a seed. */
        rand64init( isaac_state, 0 );
    }
    else
    {
        /* Seed the ISAAC state with entropy. */
        memcpy( isaac_state->randrsl, seed->s, count );

        /* The second parameter indicates that randrsl is non-empty. */
        rand64init( isaac_state, 1 );
    }

    return 0;
}

int nwipe_isaac64_read( NWIPE_PRNG_READ_SIGNATURE )
{
    rand64ctx* isaac_state = *state;
    u8* restrict bufpos = buffer;
    size_t words = count / SIZE_OF_ISAAC64;  // the values of ISAAC-64 is strictly 8 bytes

    for( size_t ii = 0; ii < words; ++ii )
    {
        u64_to_buffer( bufpos, isaac64_nextval( isaac_state ), SIZE_OF_ISAAC64 );
        bufpos += SIZE_OF_ISAAC64;
    }

    /* If there is some remainder copy only relevant number of bytes to not overflow the buffer. */
    const size_t remain = count % SIZE_OF_ISAAC64;  // SIZE_OF_ISAAC64 is strictly 8 bytes
    if( remain > 0 )
    {
        u64_to_buffer( bufpos, isaac64_nextval( isaac_state ), remain );
    }

    return 0;
}

/* EXPERIMENTAL implementation of Lagged Fibonacci generator a lot of random numbers */
int nwipe_add_lagg_fibonacci_prng_init( NWIPE_PRNG_INIT_SIGNATURE )
{
    if( *state == NULL )
    {
        nwipe_log( NWIPE_LOG_NOTICE, "Initialising Lagged Fibonacci generator PRNG" );
        *state = malloc( sizeof( add_lagg_fibonacci_state_t ) );
    }
    add_lagg_fibonacci_init(
        (add_lagg_fibonacci_state_t*) *state, (uint64_t*) ( seed->s ), seed->length / sizeof( uint64_t ) );

    return 0;
}

/* EXPERIMENTAL implementation of XORoroshiro256 algorithm to provide high-quality, but a lot of random numbers */
int nwipe_xoroshiro256_prng_init( NWIPE_PRNG_INIT_SIGNATURE )
{
    nwipe_log( NWIPE_LOG_NOTICE, "Initialising XORoroshiro-256 PRNG" );

    if( *state == NULL )
    {
        /* This is the first time that we have been called. */
        *state = malloc( sizeof( xoroshiro256_state_t ) );
    }
    xoroshiro256_init( (xoroshiro256_state_t*) *state, (uint64_t*) ( seed->s ), seed->length / sizeof( uint64_t ) );

    return 0;
}

int nwipe_add_lagg_fibonacci_prng_read( NWIPE_PRNG_READ_SIGNATURE )
{
    u8* restrict bufpos = buffer;
    size_t words = count / SIZE_OF_ADD_LAGG_FIBONACCI_PRNG;

    /* Loop to fill the buffer with blocks directly from the Fibonacci algorithm */
    for( size_t ii = 0; ii < words; ++ii )
    {
        add_lagg_fibonacci_genrand_uint256_to_buf( (add_lagg_fibonacci_state_t*) *state, bufpos );
        bufpos += SIZE_OF_ADD_LAGG_FIBONACCI_PRNG;  // Move to the next block
    }

    /* Handle remaining bytes if count is not a multiple of SIZE_OF_ADD_LAGG_FIBONACCI_PRNG */
    const size_t remain = count % SIZE_OF_ADD_LAGG_FIBONACCI_PRNG;
    if( remain > 0 )
    {
        unsigned char temp_output[16];  // Temporary buffer for the last block
        add_lagg_fibonacci_genrand_uint256_to_buf( (add_lagg_fibonacci_state_t*) *state, temp_output );

        // Copy the remaining bytes
        memcpy( bufpos, temp_output, remain );
    }

    return 0;  // Success
}

int nwipe_xoroshiro256_prng_read( NWIPE_PRNG_READ_SIGNATURE )
{
    u8* restrict bufpos = buffer;
    size_t words = count / SIZE_OF_XOROSHIRO256_PRNG;

    /* Loop to fill the buffer with blocks directly from the XORoroshiro256 algorithm */
    for( size_t ii = 0; ii < words; ++ii )
    {
        xoroshiro256_genrand_uint256_to_buf( (xoroshiro256_state_t*) *state, bufpos );
        bufpos += SIZE_OF_XOROSHIRO256_PRNG;  // Move to the next block
    }

    /* Handle remaining bytes if count is not a multiple of SIZE_OF_XOROSHIRO256_PRNG */
    const size_t remain = count % SIZE_OF_XOROSHIRO256_PRNG;
    if( remain > 0 )
    {
        unsigned char temp_output[16];  // Temporary buffer for the last block
        xoroshiro256_genrand_uint256_to_buf( (xoroshiro256_state_t*) *state, temp_output );

        // Copy the remaining bytes
        memcpy( bufpos, temp_output, remain );
    }

    return 0;  // Success
}

/**
 * Initialize the AES-CTR PRNG state.
 *
 * Signature: int nwipe_aes_ctr_prng_init(NWIPE_PRNG_INIT_SIGNATURE);
 *
 * - Allocates state if *state is NULL.
 * - Calls underlying aes_ctr_prng_init() with provided seed.
 * - Logs errors on failure.
 */
/*
 * high‑throughput wrapper with pre‑fetch buffer
 * --------------------------------------------------------------------------
 * Provides NWIPE_PRNG_INIT / NWIPE_PRNG_READ glue around the persistent
 * kernel‑AES PRNG.  Adds a 64 KiB stash buffer so that typical small requests
 * from nwipe (e.g. 32 B, 512 B) do **not** trigger a syscall each time.
 */

/* Thread‑local specifier that works in C11 and GNU C */
/* -------------------------------------------------------------------------
 * Ring-Buffer basierter Thread-local Stash
 * ------------------------------------------------------------------------- */

#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 201112L
  #define NW_THREAD_LOCAL _Thread_local
#else
  #define NW_THREAD_LOCAL __thread
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define NW_ALIGN(N) __attribute__((aligned(N)))
#else
  #define NW_ALIGN(N) _Alignas(N)
#endif

/* Kapazität: 1 MiB (Power-of-Two, Vielfaches von 16 KiB) */
#ifndef STASH_CAPACITY
#define STASH_CAPACITY (1u << 20) /* 1 MiB */
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert((STASH_CAPACITY & (STASH_CAPACITY - 1)) == 0,
               "STASH_CAPACITY must be a power of two");
_Static_assert((STASH_CAPACITY % SIZE_OF_AES_CTR_PRNG) == 0,
               "STASH_CAPACITY must be a multiple of SIZE_OF_AES_CTR_PRNG");
#endif

/* Ring-Buffer Speicher */
NW_THREAD_LOCAL static unsigned char stash[STASH_CAPACITY] NW_ALIGN(64);

/* Ring-Indices */
NW_THREAD_LOCAL static size_t rb_head  = 0; /* nächste Leseposition */
NW_THREAD_LOCAL static size_t rb_tail  = 0; /* nächste Schreibposition */
NW_THREAD_LOCAL static size_t rb_count = 0; /* belegte Bytes im Ring */

static inline size_t rb_free(void) {
    return STASH_CAPACITY - rb_count;
}

/* zusammenhängend nutzbare Daten ab head */
static inline size_t rb_contig_used(void) {
    size_t to_end = STASH_CAPACITY - rb_head;
    return (rb_count < to_end) ? rb_count : to_end;
}

/* zusammenhängend freier Platz ab tail */
static inline size_t rb_contig_free(void) {
    size_t to_end = STASH_CAPACITY - rb_tail;
    size_t free = rb_free();
    return (free < to_end) ? free : to_end;
}

/* Refill: sorge dafür, dass mindestens `need` Bytes im Ring liegen.
   Achtung: Wir produzieren immer in 16-KiB-Blöcken. */
static int refill_stash_thread_local(void* state, size_t need)
{
    while (rb_count < need) {
        /* Kein Platz für einen weiteren 16-KiB-Block → nichts zu tun, Caller liest zunächst. */
        if (rb_free() < SIZE_OF_AES_CTR_PRNG)
            break;

        size_t cf = rb_contig_free();
        if (cf >= SIZE_OF_AES_CTR_PRNG) {
            /* Direkt in den Ring schreiben (ohne Bounce-Buffer) */
            if (aes_ctr_prng_genrand_16k_to_buf((aes_ctr_state_t*)state, stash + rb_tail) != 0)
                return -1;
            rb_tail = (rb_tail + SIZE_OF_AES_CTR_PRNG) & (STASH_CAPACITY - 1);
            rb_count += SIZE_OF_AES_CTR_PRNG;
        } else {
            /* Wrap-Fall: einmal 16 KiB in temporären Block, dann in zwei Teile in den Ring kopieren */
            unsigned char tmp[SIZE_OF_AES_CTR_PRNG];
            if (aes_ctr_prng_genrand_16k_to_buf((aes_ctr_state_t*)state, tmp) != 0)
                return -1;
            size_t first = STASH_CAPACITY - rb_tail;               /* bis Pufferende */
            memcpy(stash + rb_tail, tmp, first);
            memcpy(stash, tmp + first, SIZE_OF_AES_CTR_PRNG - first);
            rb_tail = (rb_tail + SIZE_OF_AES_CTR_PRNG) & (STASH_CAPACITY - 1);
            rb_count += SIZE_OF_AES_CTR_PRNG;
        }
    }
    return 0;
}

/* ---------------- PRNG INIT ---------------- */
int nwipe_aes_ctr_prng_init(NWIPE_PRNG_INIT_SIGNATURE)
{
    nwipe_log(NWIPE_LOG_NOTICE, "Initializing AES-CTR PRNG (thread-local ring buffer)");

    if (*state == NULL) {
        *state = calloc(1, sizeof(aes_ctr_state_t));
        if (*state == NULL) {
            nwipe_log(NWIPE_LOG_FATAL, "calloc() failed for PRNG state");
            return -1;
        }
    }

    int rc = aes_ctr_prng_init(
        (aes_ctr_state_t*)*state, (unsigned long*)seed->s, seed->length / sizeof(unsigned long));
    if (rc != 0) {
        nwipe_log(NWIPE_LOG_ERROR, "aes_ctr_prng_init() failed");
        return -1;
    }

    /* Ring zurücksetzen */
    rb_head = rb_tail = rb_count = 0;
    return 0;
}

/* ---------------- PRNG READ ---------------- */
int nwipe_aes_ctr_prng_read(NWIPE_PRNG_READ_SIGNATURE)
{
    unsigned char* out = buffer;
    size_t bytes_left = count;

    /* Fast-Path: große Reads direkt in 16-KiB-Blöcken, wenn der Ring leer ist */
    while (bytes_left >= SIZE_OF_AES_CTR_PRNG && rb_count == 0) {
        if (aes_ctr_prng_genrand_16k_to_buf((aes_ctr_state_t*)*state, out) != 0) {
            nwipe_log(NWIPE_LOG_ERROR, "PRNG direct fill failed");
            return -1;
        }
        out        += SIZE_OF_AES_CTR_PRNG;
        bytes_left -= SIZE_OF_AES_CTR_PRNG;
    }

    while (bytes_left > 0) {
        /* Stelle sicher, dass mind. 1 Byte im Ring liegt (typischer Kleinst-Read-Pfad) */
        if (rb_count == 0) {
            if (refill_stash_thread_local(*state, 1) != 0) {
                nwipe_log(NWIPE_LOG_ERROR, "PRNG refill failed");
                return -1;
            }
            /* Falls trotz refill noch 0 Bytes (nur wenn kein Platz für 16 KiB war): dann direkt
               in den Zielpuffer weiter oben – aber hier haben wir bytes_left < 16 KiB, also
               machen wir weiter und konsumieren, was evtl. da ist (0 → nächste Schleifenrunde). */
            if (rb_count == 0) continue;
        }

        /* Kopiere maximal zusammenhängenden Block ab head */
        size_t avail = rb_contig_used();
        size_t take  = (bytes_left < avail) ? bytes_left : avail;

        memcpy(out, stash + rb_head, take);

        rb_head     = (rb_head + take) & (STASH_CAPACITY - 1);
        rb_count   -= take;
        out        += take;
        bytes_left -= take;

        /* Optional: opportunistisch nachfüllen, wenn viel Platz da ist (senkt Latenz) */
        if (rb_free() >= (2 * SIZE_OF_AES_CTR_PRNG)) {
            if (refill_stash_thread_local(*state, SIZE_OF_AES_CTR_PRNG) != 0) {
                nwipe_log(NWIPE_LOG_ERROR, "PRNG opportunistic refill failed");
                return -1;
            }
        }
    }
    return 0;
}


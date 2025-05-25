/*
 * aes_ctr_prng.c – portable AES‑CTR PRNG (AES‑256, 4‑way parallel)
 * ----------------------------------------------------------------
 *  • Single‑file implementation: **no separate header needed**.
 *  • Compile **once** on any x86‑64/Linux platform **without ISA flags**:
 *      gcc -O3 -std=c11 -DPRNG_PARALLEL=4 -DPRNG_ROUNDS=10 aes_ctr_prng.c -o prng
 *  • Run‑time dispatcher chooses fastest available back‑end:
 *      VAES+AVX‑512  →  AVX2/AES‑NI  →  AES‑NI/SSE2  →  generic C.
 *  • Always uses a 256‑bit master key; counter is little‑endian 128 bit.
 *  • Public API:
 *        int aes_ctr_prng_init(aes_ctr_state_t*, unsigned long *key, unsigned long keylen);
 *        int aes_ctr_prng_genrand_uint256_to_buf(aes_ctr_state_t*, uint8_t *out64);
 *    Each call outputs 64 bytes (4 × 16‑byte AES blocks).
 *
 * Copyright (C) 2025 Fabian Druschke  – MIT License (same as Ascon reference).
 */

#define _GNU_SOURCE 1
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cpuid.h>
#include <immintrin.h>

/* ---------- user‑tunable macros ------------------------------------------ */
#ifndef PRNG_PARALLEL
#  define PRNG_PARALLEL 4       /* number of blocks per call (≥1, ≤4) */
#endif
#ifndef PRNG_ROUNDS
#  define PRNG_ROUNDS 10        /* AES‑128 rounds to execute (≤14)     */
#endif

#ifndef PRNG_ASSERT
# define PRNG_ASSERT(c,m) do{ if(!(c)){ fprintf(stderr,"[PRNG FATAL] %s\n",m); abort(); }}while(0)
#endif

/* ---------- public state type -------------------------------------------- */
typedef struct aes_ctr_state_s {
    uint64_t s[4];              /* s[0]=CTR_lo, s[1]=CTR_hi; s[2..3] spare */
} aes_ctr_state_t;

/* ---------- round‑key storage -------------------------------------------- */
static __m128i g_rk_simd[15]  __attribute__((aligned(16)));  /* SIMD view  */
static uint8_t g_rk_bytes[15][16];                           /* byte view  */
static int     g_rk_ready = 0;

/* ---------- CPUID helpers ------------------------------------------------- */
static inline int cpu_feature(unsigned leaf, unsigned sub, unsigned reg, unsigned bit)
{
    unsigned a,b,c,d;
    if(!__get_cpuid_count(leaf, sub, &a,&b,&c,&d)) return 0;
    unsigned v = (reg==0? a : reg==1? b : reg==2? c : d);
    return (v >> bit) & 1;
}
static inline int has_aesni  (void){ return cpu_feature(1,0,2,25); }
static inline int has_avx2   (void){ return cpu_feature(7,0,1,5 ); }
static inline int has_vaes512(void){ return cpu_feature(7,0,2,9) && cpu_feature(7,0,1,16); }

/* ---------- AES‑256 key expansion (generic C) ----------------------------- */
static const uint8_t sbox[256] = {
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
static uint8_t Rcon[15] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D };
static inline void RotWord(uint8_t*w){uint8_t t=w[0];w[0]=w[1];w[1]=w[2];w[2]=w[3];w[3]=t;}
static inline void SubWord(uint8_t*w){w[0]=sbox[w[0]];w[1]=sbox[w[1]];w[2]=sbox[w[2]];w[3]=sbox[w[3]];}
static void keyexpand256(const uint8_t key[32])
{
    memcpy(g_rk_bytes, key, 32);            /* first two round keys */
    int i = 8, r = 1; uint8_t temp[4];
    while(i < 60) {
        memcpy(temp, g_rk_bytes[i-1], 4);
        if(i % 8 == 0){ RotWord(temp); SubWord(temp); temp[0] ^= Rcon[r++]; }
        else if(i % 8 == 4){ SubWord(temp); }
        for(int j=0;j<4;++j) g_rk_bytes[i][j] = g_rk_bytes[i-8][j] ^ temp[j];
        ++i;
    }
    for(int k=0;k<=PRNG_ROUNDS;++k)
        g_rk_simd[k] = _mm_loadu_si128((const __m128i*)g_rk_bytes[k]);
    g_rk_ready = 1;
}

/* ---------- portable AES block (CTR keystream) --------------------------- */
static inline uint8_t xt(uint8_t x){ return (x<<1) ^ ((x>>7)*0x1B); }
static void MixColumns(uint8_t*s){
    for(int c=0;c<4;++c){
        uint8_t *a=s+4*c; uint8_t a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]=xt(a0)^xt(a1)^a1^a2^a3;
        a[1]=a0^xt(a1)^xt(a2)^a2^a3;
        a[2]=a0^a1^xt(a2)^xt(a3)^a3;
        a[3]=xt(a0)^a0^a1^a2^xt(a3);
    }
}
static void ShiftRows(uint8_t*s){ uint8_t t;
    t=s[1];  s[1]=s[5];  s[5]=s[9];  s[9]=s[13]; s[13]=t;
    t=s[2];  s[2]=s[10]; s[10]=t;    t=s[6];  s[6]=s[14]; s[14]=t;
    t=s[3];  s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
}
static void SubBytes(uint8_t*s){ for(int i=0;i<16;++i) s[i]=sbox[s[i]]; }
static void aes_enc_block_generic(uint8_t*blk)
{
    uint8_t*state=blk; for(int i=0;i<16;++i) state[i] ^= g_rk_bytes[0][i];
    for(int r=1;r<PRNG_ROUNDS;++r){ SubBytes(state); ShiftRows(state); MixColumns(state); for(int i=0;i<16;++i) state[i]^=g_rk_bytes[r][i]; }
    SubBytes(state); ShiftRows(state); for(int i=0;i<16;++i) state[i]^=g_rk_bytes[PRNG_ROUNDS][i];
}

/* ---------- counter helper ----------------------------------------------- */
static inline void ctr_inc(uint64_t *lo, uint64_t *hi, uint64_t n){ uint64_t o=*lo; *lo+=n; if(*lo<o) ++(*hi); }

/* ---------- back‑end prototypes ------------------------------------------ */
typedef int(*prng_f)(aes_ctr_state_t*,uint8_t*);
static prng_f g_genrand = NULL;
static int gen_generic(aes_ctr_state_t*,uint8_t*);
__attribute__((target("aes")))             static int gen_sse (aes_ctr_state_t*,uint8_t*);
__attribute__((target("aes,avx2")))        static int gen_avx2(aes_ctr_state_t*,uint8_t*);
__attribute__((target("vaes,avx512f,avx512dq")))    static int gen_vaes(aes_ctr_state_t*,uint8_t*);

/* ---------- generic C fallback ------------------------------------------- */
static int gen_generic(aes_ctr_state_t*st,uint8_t*out)
{
    uint64_t lo=st->s[0], hi=st->s[1]; uint8_t ctr[16];
    for(int i=0;i<PRNG_PARALLEL;++i){
        memcpy(ctr,&lo,8); memcpy(ctr+8,&hi,8);
        aes_enc_block_generic(ctr);
        memcpy(out + i*16, ctr, 16);
        ++lo; if(!lo) ++hi;
    }
    st->s[0]=lo; st->s[1]=hi; return 0;
}

/* ---------- SIMD helpers and hardware paths ------------------------------ */
static inline __m128i ctr128(uint64_t l,uint64_t h){ return _mm_set_epi64x((long long)h, (long long)l); }
static int gen_sse(aes_ctr_state_t*st,uint8_t*out)
{
    uint64_t lo=st->s[0], hi=st->s[1];
    __m128i c0=ctr128(lo,hi), c1=ctr128(lo+1,hi), c2=ctr128(lo+2,hi), c3=ctr128(lo+3,hi);
    __m128i b0=_mm_xor_si128(c0,g_rk_simd[0]), b1=_mm_xor_si128(c1,g_rk_simd[0]),
            b2=_mm_xor_si128(c2,g_rk_simd[0]), b3=_mm_xor_si128(c3,g_rk_simd[0]);
    for(int i=1;i<PRNG_ROUNDS;++i){
        b0=_mm_aesenc_si128(b0,g_rk_simd[i]);
        b1=_mm_aesenc_si128(b1,g_rk_simd[i]);
        b2=_mm_aesenc_si128(b2,g_rk_simd[i]);
        b3=_mm_aesenc_si128(b3,g_rk_simd[i]);
    }
    b0=_mm_aesenclast_si128(b0,g_rk_simd[PRNG_ROUNDS]);
    b1=_mm_aesenclast_si128(b1,g_rk_simd[PRNG_ROUNDS]);
    b2=_mm_aesenclast_si128(b2,g_rk_simd[PRNG_ROUNDS]);
    b3=_mm_aesenclast_si128(b3,g_rk_simd[PRNG_ROUNDS]);
    _mm_storeu_si128((__m128i*)(out     ), b0);
    _mm_storeu_si128((__m128i*)(out + 16), b1);
    _mm_storeu_si128((__m128i*)(out + 32), b2);
    _mm_storeu_si128((__m128i*)(out + 48), b3);
    ctr_inc(&lo,&hi,PRNG_PARALLEL); st->s[0]=lo; st->s[1]=hi; return 0;
}
static int gen_avx2(aes_ctr_state_t*st,uint8_t*out){ return gen_sse(st,out); }
#ifdef __x86_64__
static int gen_vaes(aes_ctr_state_t*st,uint8_t*out)
{
    uint64_t lo=st->s[0], hi=st->s[1];
    __m512i ctr = _mm512_set_epi64((long long)hi,(long long)(lo+3),(long long)hi,(long long)(lo+2),
                                   (long long)hi,(long long)(lo+1),(long long)hi,(long long)(lo+0));
    __m512i rk=_mm512_broadcast_i64x2(g_rk_simd[0]);
    __m512i b=_mm512_xor_si512(ctr,rk);
    for(int i=1;i<PRNG_ROUNDS;++i){ rk=_mm512_broadcast_i64x2(g_rk_simd[i]); b=_mm512_aesenc_epi128(b,rk);}  
    rk=_mm512_broadcast_i64x2(g_rk_simd[PRNG_ROUNDS]); b=_mm512_aesenclast_epi128(b,rk);
    _mm512_storeu_si512((__m512i*)out,b);
    ctr_inc(&lo,&hi,PRNG_PARALLEL); st->s[0]=lo; st->s[1]=hi; return 0;
}
#endif

/* ---------- public API ---------------------------------------------------- */
int aes_ctr_prng_init(aes_ctr_state_t *st, unsigned long *key, unsigned long key_len)
{
    size_t bytes = key_len * sizeof(unsigned long);
    if(bytes < 32){ fprintf(stderr,"[PRNG] seed/key must be ≥32 bytes\n"); return -1; }
    const uint8_t *seed = (const uint8_t*)key;
    keyexpand256(seed);
    uint64_t ctr_lo=0, ctr_hi=0;
    if(bytes >= 48){ memcpy(&ctr_lo,seed+32,8); memcpy(&ctr_hi,seed+40,8); }
    st->s[0]=ctr_lo; st->s[1]=ctr_hi; st->s[2]=st->s[3]=0;

    if(has_vaes512())                       g_genrand = gen_vaes;
    else if(has_avx2() && has_aesni())      g_genrand = gen_avx2;
    else if(has_aesni())                    g_genrand = gen_sse;
    else                                    g_genrand = gen_generic;
    return 0;
}

int aes_ctr_prng_genrand_uint256_to_buf(aes_ctr_state_t *st, uint8_t *out)
{
    return g_genrand(st,out);
}


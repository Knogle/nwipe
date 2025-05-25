// aes_ctr_prng.cpp – Minimal AES-256-CTR PRNG backend for nwipe
// -----------------------------------------------------------------------------
//  • Uses Linux kernel AF_ALG "ctr(aes)" skcipher for AES-256-CTR keystream.
//  • Public state remains exactly 256 bits (4×64) in aes_ctr_state_t.
//  • Each call to aes_ctr_prng_genrand_16k_to_buf() outputs 16 KiB and advances the 128-bit counter.
//  • C++17 implementation, exported as C API (extern "C").
// -----------------------------------------------------------------------------

#include "aes_ctr_prng.h"
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <cstring>
#include <array>

// Global AES-256 key (32 bytes), defined here for linkage
unsigned char global_key[32];

namespace {

constexpr std::size_t CHUNK = 1u << 14;              // 16 KiB per call
constexpr std::size_t AES_BLOCK = 16u;
constexpr std::size_t BLOCKS_PER_CHUNK = CHUNK / AES_BLOCK; // 1024 blocks

// Store 64-bit little-endian
static inline void store64_le(uint64_t v, unsigned char *buf) {
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<unsigned char>(v >> (8*i));
}

// Build msghdr with ALG_SET_OP and ALG_SET_IV (16-byte IV)
class ControlBuilder {
public:
    ControlBuilder(const unsigned char iv[16], void *plain, size_t len) {
        iov_.iov_base = plain;
        iov_.iov_len  = len;
        msg_.msg_iov = &iov_;
        msg_.msg_iovlen = 1;
        msg_.msg_control = control_.data();
        msg_.msg_controllen = control_.size();

        // ALG_SET_OP = ENCRYPT
        cmsghdr *c1 = CMSG_FIRSTHDR(&msg_);
        c1->cmsg_level = SOL_ALG;
        c1->cmsg_type = ALG_SET_OP;
        c1->cmsg_len = CMSG_LEN(sizeof(uint32_t));
        *reinterpret_cast<uint32_t*>(CMSG_DATA(c1)) = ALG_OP_ENCRYPT;

        // ALG_SET_IV with ivlen + 16-byte IV
        cmsghdr *c2 = CMSG_NXTHDR(&msg_, c1);
        c2->cmsg_level = SOL_ALG;
        c2->cmsg_type = ALG_SET_IV;
        c2->cmsg_len = CMSG_LEN(sizeof(uint32_t)+16);
        uint32_t ivlen = 16;
        std::memcpy(CMSG_DATA(c2), &ivlen, sizeof(ivlen));
        std::memcpy(CMSG_DATA(c2) + sizeof(ivlen), iv, 16);
    }
    struct msghdr* msg() { return &msg_; }
private:
    std::array<char, CMSG_SPACE(sizeof(uint32_t)) + CMSG_SPACE(sizeof(uint32_t)+16)> control_{};
    struct msghdr msg_{};
    struct iovec iov_{};
};

// Open AF_ALG socket for ctr(aes)
static int open_ctr_socket(const unsigned char key[32]) {
    int tfm = ::socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfm < 0) return -1;
    sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    std::strcpy(reinterpret_cast<char*>(sa.salg_type), "skcipher");
    std::strcpy(reinterpret_cast<char*>(sa.salg_name), "ctr(aes)");
    if (::bind(tfm, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        ::close(tfm);
        return -1;
    }
    if (::setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, 32) < 0) {
        ::close(tfm);
        return -1;
    }
    int op = ::accept(tfm, nullptr, nullptr);
    ::close(tfm);
    return op;
}

// Advance 128-bit counter by n blocks
static void ctr_add(aes_ctr_state_t *st, uint64_t n) {
    uint64_t lo = st->s[0];
    st->s[0] += n;
    if (st->s[0] < lo)
        ++st->s[1];
}

} // namespace

extern "C" {

int aes_ctr_prng_init(aes_ctr_state_t *state,
                      unsigned long    init_key[],
                      unsigned long    key_length) {
    if (!state || !init_key || key_length * sizeof(unsigned long) < 32)
        return -1;
    std::memset(state, 0, sizeof(*state));
    std::memcpy(state->s, init_key, sizeof(uint64_t)*2);
    std::memcpy(global_key, init_key, 32);
    int fd = open_ctr_socket(global_key);
    if (fd < 0) return -1;
    ::close(fd);
    return 0;
}

int aes_ctr_prng_genrand_16k_to_buf(aes_ctr_state_t *state,
                                    unsigned char   *bufpos) {
    if (!state || !bufpos) return -1;
    int op = open_ctr_socket(global_key);
    if (op < 0) return -1;
    unsigned char iv[16];
    store64_le(state->s[0], iv);
    store64_le(state->s[1], iv+8);
    static unsigned char zeros[CHUNK] = {0};
    ControlBuilder ctl(iv, zeros, CHUNK);
    if (::sendmsg(op, ctl.msg(), 0) != (ssize_t)CHUNK) { ::close(op); return -1; }
    if (::read(op, bufpos, CHUNK) != (ssize_t)CHUNK) { ::close(op); return -1; }
    ::close(op);
    ctr_add(state, BLOCKS_PER_CHUNK);
    return 0;
}

} // extern "C"


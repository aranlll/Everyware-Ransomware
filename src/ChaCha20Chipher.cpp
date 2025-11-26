#include "../include/ChaCha20Cipher.h"
#include <cstring>
#include <algorithm>

// ---- helpers ----
uint32_t ChaCha20Cipher::rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}
uint32_t ChaCha20Cipher::load_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
void ChaCha20Cipher::store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
void ChaCha20Cipher::quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}
void ChaCha20Cipher::chacha20_block(uint8_t out[64],
                                    const uint8_t key[32],
                                    const uint8_t nonce[12],
                                    uint32_t counter) {
    static const uint32_t constants[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t state[16];
    state[0] = constants[0]; state[1] = constants[1];
    state[2] = constants[2]; state[3] = constants[3];

    for (int i = 0; i < 8; ++i) state[4 + i] = load_le32(key + 4 * i);
    state[12] = counter;
    state[13] = load_le32(nonce + 0);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);

    uint32_t x[16];
    std::memcpy(x, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        // column rounds
        quarter_round(x[0], x[4], x[8],  x[12]);
        quarter_round(x[1], x[5], x[9],  x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        // diagonal rounds
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8],  x[13]);
        quarter_round(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; ++i) {
        x[i] += state[i];
        store_le32(out + 4 * i, x[i]);
    }
}

// ---- class ----
ChaCha20Cipher::ChaCha20Cipher(const uint8_t key_[32], const uint8_t nonce_[12]) {
    std::memcpy(key, key_, 32);
    std::memcpy(nonce, nonce_, 12);
}

void ChaCha20Cipher::process(uint8_t* out, const uint8_t* in, size_t len, uint64_t offset) {
    uint8_t block[64];
    uint32_t counter = static_cast<uint32_t>(offset / 64);
    size_t inner_offset = static_cast<size_t>(offset % 64);
    size_t done = 0;

    while (done < len) {
        chacha20_block(block, key, nonce, counter++);
        size_t n = std::min((size_t)64 - inner_offset, len - done);
        for (size_t i = 0; i < n; ++i) out[done + i] = in[done + i] ^ block[inner_offset + i];
        done += n;
        inner_offset = 0;
    }
}
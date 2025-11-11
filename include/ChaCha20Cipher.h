#pragma once
#include <cstdint>
#include <cstddef>

class ChaCha20Cipher {
private:
    uint8_t key[32];
    uint8_t nonce[12];

    static uint32_t rotl32(uint32_t x, int r);
    static uint32_t load_le32(const uint8_t* p);
    static void store_le32(uint8_t* p, uint32_t v);
    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    static void chacha20_block(uint8_t out[64],
                               const uint8_t key[32],
                               const uint8_t nonce[12],
                               uint32_t counter);

public:
    ChaCha20Cipher(const uint8_t key_[32], const uint8_t nonce_[12]);

    // process: produce keystream XOR over 'in' into 'out', starting at absolute file-offset 'offset'
    void process(uint8_t* out, const uint8_t* in, size_t len, uint64_t offset = 0);
};
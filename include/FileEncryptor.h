#pragma once
#include <string>
#include "ChaCha20Cipher.h"

class FileEncryptor {
private:
    ChaCha20Cipher cipher;

public:
    FileEncryptor(const uint8_t key[32], const uint8_t nonce[12]);

    // encrypt: inputPath -> outputPath (writes encrypted bytes to outputPath)
    bool encrypt(const std::string& inputPath, const std::string& outputPath);

    // decrypt: same as encrypt (XOR stream cipher)
    bool decrypt(const std::string& inputPath, const std::string& outputPath);
};
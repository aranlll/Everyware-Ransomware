#include "../include/FileEncryptor.h"
#include <fstream>
#include <vector>
#include <iostream>

FileEncryptor::FileEncryptor(const uint8_t key[32], const uint8_t nonce[12])
    : cipher(key, nonce) {}

bool FileEncryptor::encrypt(const std::string& inputPath, const std::string& outputPath) {
    const size_t BUF_SIZE = 64 * 1024;
    std::ifstream fin(inputPath, std::ios::binary);
    if (!fin) { std::cerr << "[FileEncryptor] input open failed: " << inputPath << "\n"; return false; }

    std::ofstream fout(outputPath, std::ios::binary | std::ios::trunc);
    if (!fout) { std::cerr << "[FileEncryptor] output open failed: " << outputPath << "\n"; return false; }

    std::vector<uint8_t> inbuf(BUF_SIZE), outbuf(BUF_SIZE);
    uint64_t offset = 0;

    while (fin) {
        fin.read(reinterpret_cast<char*>(inbuf.data()), static_cast<std::streamsize>(BUF_SIZE));
        std::streamsize n = fin.gcount();
        if (n <= 0) break;

        cipher.process(outbuf.data(), inbuf.data(), static_cast<size_t>(n), offset);
        fout.write(reinterpret_cast<const char*>(outbuf.data()), n);
        if (!fout) { std::cerr << "[FileEncryptor] write failed\n"; fin.close(); fout.close(); return false; }

        offset += static_cast<uint64_t>(n);
    }

    fin.close();
    fout.close();
    return true;
}

bool FileEncryptor::decrypt(const std::string& inputPath, const std::string& outputPath) {
    // XOR stream — encrypt/decrypt are identical
    return encrypt(inputPath, outputPath);
}
#pragma once
#include <array>
#include <cstdint>
#include <string>

class KeyManager {
public:
    KeyManager();

    // set fixed key/nonce (copy from caller)
    //void setFixedKeyNonce(const uint8_t k[32], const uint8_t n[12]);일단 주석처리

    // accessors
    const uint8_t* getKey() const noexcept;
    const uint8_t* getNonce() const noexcept;

    // convenience: write to files (binary)
    bool saveToFiles(const std::string& keyPath, const std::string& noncePath) const;

private:
    std::array<uint8_t,32> key{};
    std::array<uint8_t,12> nonce{};
};
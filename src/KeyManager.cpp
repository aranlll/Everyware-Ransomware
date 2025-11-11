// KeyManager.cpp (하드코딩 자동 설정 버전)
#include "../include/KeyManager.h"
#include <iostream>
#include <cstring>

KeyManager::KeyManager() {
    // 생성 시 자동으로 고정된 키/논스 설정
    const uint8_t fixed_key[32] = {
        20,21,12,52,52,2,21,34,13,20,24,13,13,22,2,41,
        34,77,4,9,10,18,5,17,11,11,20,25,11,4,6,5
    };
    const uint8_t fixed_nonce[12] = {10,11,12,13,14,15,16,17,18,19,20,21};
    std::memcpy(key.data(), fixed_key, 32);
    std::memcpy(nonce.data(), fixed_nonce, 12);
    std::cout << "[KeyManager] Fixed test key/nonce loaded.\n";
}

const uint8_t* KeyManager::getKey() const noexcept { return key.data(); }
const uint8_t* KeyManager::getNonce() const noexcept { return nonce.data(); }

bool KeyManager::saveToFiles(const std::string& keyPath, const std::string& noncePath) const {
    // ...
}
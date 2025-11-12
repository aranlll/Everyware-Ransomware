#pragma once
#ifndef API_HASHER_H
#define API_HASHER_H

#include <windows.h>
#include <cstdint>
#include <string>

namespace ApiHasher {

    uint32_t Hash(const char* s);
    uint32_t Hash(const std::string& s);

    FARPROC GetProcAddressByHash(HMODULE module, uint32_t targetHash);
    #ifdef APIHASHER_DEBUG_PRINT
    void PrintSampleHashes();
    #endif

} 

#endif 

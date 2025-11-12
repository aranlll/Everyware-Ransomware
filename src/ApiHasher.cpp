#include "ApiHasher.h"
#include <cstring>

namespace ApiHasher {

    static inline uint32_t ROR(uint32_t value, unsigned int bits) {
        return (value >> bits) | (value << (32 - bits));
    } //ROR 함수 (해시 알고리즘 구현함수라고 생각하면 될 것 같습니다)

    uint32_t Hash(const char* s) {
        if (!s) return 0;
        uint32_t h = 0x811C9DC5u; //예시 주소 
        const unsigned char* p = reinterpret_cast<const unsigned char*>(s);

        while (*p) {
            h = ROR(h, 13);
            h += static_cast<uint32_t>(*p);
            h ^= (h << 7);
            h ^= (h >> 3);
            ++p;
        }


        h = ROR(h, 7) ^ (h >> 16);
        h = ROR(h, 7) ^ (h << 3);

        return h;
    }       // ROR 13으로 해시값 생성 (위의 ROR 함수 사용)

    uint32_t Hash(const std::string& s) {
        return Hash(s.c_str());
    }  // 문자열 오버로딩 
     // 위의 Hash 함수는 char 형식만 받을 수 있어서 문자열로 받을 수 있도록 

   
    static inline void* RVAToVA(HMODULE module, DWORD rva) {
        return reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(module) + rva);
    }  // .exe .dll 찾으려고 상대주소(RVA) 절대주소(VA)로 변환함
    

    FARPROC GetProcAddressByHash(HMODULE module, uint32_t targetHash) {
        if (!module) return nullptr;

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        
        // PE 유효성 확인 (DOS 헤더 (MZ)) 확인 

    #ifdef _WIN64
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
        const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        // NT 헤더로 이동
    #else
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
        const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        //NT 헤더로 이동
    #endif

        if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;
        //export table 존재 확인

        auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVAToVA(module, dir.VirtualAddress));
        if (!exportDir) return nullptr; // 위에서 만든 함수 써서 주소 변환

        DWORD numberOfNames = exportDir->NumberOfNames; 
        // dll이 내보내는 함수 이름 개수
        if (numberOfNames == 0) return nullptr;

        DWORD* namesRVA = reinterpret_cast<DWORD*>(RVAToVA(module, exportDir->AddressOfNames));
        WORD* ordinals = reinterpret_cast<WORD*>(RVAToVA(module, exportDir->AddressOfNameOrdinals));
        DWORD* functionsRVA = reinterpret_cast<DWORD*>(RVAToVA(module, exportDir->AddressOfFunctions));
				// 이름(함수 이름 문자열 RVA  목록) 오디널(각 이름이 가리키는 ordinal번호) 함수 주소(실제 코드 주소들의 RVA)) 테이블 접근
        
        if (!namesRVA || !ordinals || !functionsRVA) return nullptr;

        for (DWORD i = 0; i < numberOfNames; ++i) {
            char* funcName = reinterpret_cast<char*>(RVAToVA(module, namesRVA[i]));
            if (!funcName) continue;

            uint32_t h = Hash(funcName);
            if (h == targetHash) {
                WORD ord = ordinals[i];
                DWORD funcRva = functionsRVA[ord];
                if (funcRva == 0) return nullptr;
						// 절대 주소 상대주소 변환 후 hash 값 취함
						// 이름으로 ordinal 찾고 ordinal로 함수 주소 찾음
           
                FARPROC addr = reinterpret_cast<FARPROC>(RVAToVA(module, funcRva));
                return addr;
                // 실제로 호출할 수 있도록 변환한 주소 리턴시킴
            }
        }

        return nullptr;
    }
    
    
    #ifdef APIHASHER_DEBUG_PRINT
    #include <cstdio>
    void PrintSampleHashes() {
        const char* samples[] = { "LoadLibraryA", "GetProcAddress", "CreateThread", "ExitProcess", "WriteFile", nullptr };
        for (int i = 0; samples[i]; ++i) {
            uint32_t h = Hash(samples[i]);
            std::printf("%-15s -> 0x%08X\n", samples[i], h);
        }
    }
    #endif // 이거는 디버그용 해시 예시들 출력하는거라 실제 코드에는 별 영향을 주진 않습니다 ... 
// GPT 박박 긁어 만든거라 안돌아갈 경우를 대비해 ...
}

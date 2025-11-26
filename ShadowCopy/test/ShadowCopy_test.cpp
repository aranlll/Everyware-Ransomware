#include <Windows.h>
#include <comdef.h>
#include <iostream>
#include <iomanip>
#include "ShadowCopy.h"

// 상세 오류 출력 헬퍼
static void PrintHr(HRESULT hr, const wchar_t* step) {
    _com_error e(hr);
    std::wcerr << L"[!] " << step
        << L" 실패: 0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill(L'0') << (unsigned long)hr
        << L"  (facility=" << std::dec << HRESULT_FACILITY(hr)
        << L", code=" << HRESULT_CODE(hr) << L")";

    if (const wchar_t* msg = e.ErrorMessage()) {
        std::wcerr << L" - " << msg;
    }
    std::wcerr << L"\n";
}

int main() {
    HRESULT hr = DeleteShadowCopy();

    if (hr == S_FALSE) {
        std::cout << "[+] There is no ShadowCopy...\n";
        return 0;   // 스냅샷 없음도 정상 종료
    }
    if (FAILED(hr)) {
        PrintHr(hr, L"DeleteShadowCopy");  // ← 상세 이유 출력
        return 1;   // 오류
    }
    std::cout << "[+] Delete ShadowCopy Complete...\n";
    return 0;       // 성공
}
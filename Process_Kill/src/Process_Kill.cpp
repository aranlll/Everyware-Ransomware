#include "Process_Kill.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <algorithm>
using namespace std;

#pragma comment(lib, "Psapi.lib")

namespace process_killer {
    typedef LONG NTSTATUS;
    typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
        HANDLE, ULONG /*ProcessInformationClass*/,
        PVOID /*ProcessInformation*/, ULONG /*ProcessInformationLength*/,
        PULONG /*ReturnLength*/);

    // Windows 내에서 알려진 값: ProcessBreakOnTermination = 0x1D (29)
    static constexpr ULONG kProcessBreakOnTermination = 0x1D;

    // 시스템 PID(0: Idle, 4 : System) 또는 현재 프로세스 PID 여부 판별
    static inline bool IsSystemPid(DWORD pid) {
        return pid == 0 || pid == 4; // Idle(0), System(4)
    }

    // SeDebugPrivilege를 활성화하여 OpenProcess 등 프로세스 열람/종료 권한 범위 확대
    bool ProcessKiller::EnablePrivilege(LPCWSTR name, bool enable) {
        HANDLE token{};
        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return false;
        }
        TOKEN_PRIVILEGES tp{};
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
            CloseHandle(token);
            return false;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
        return ok && GetLastError() == ERROR_SUCCESS;
    }

    string ProcessKiller::WideToUtf8(const wstring& w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        string s(len, 0);
        if (len) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), len, nullptr, nullptr);
        return s;
    }

    // 실행중인 프로세스의 전체 경로를 얻어 화이트리스트 매칭에 사용
    bool ProcessKiller::GetProcessImagePath(DWORD pid, wstring& outPathW) {
        outPathW.clear();
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) {
            return false;
        }

        DWORD cap = 0;
        // 1차: 버퍼 길이 확인
        QueryFullProcessImageNameW(h, 0, nullptr, &cap);
        if (cap == 0) {
            CloseHandle(h);
            return false;
        }

        outPathW.resize(cap);
        if (!QueryFullProcessImageNameW(h, 0, outPathW.data(), &cap)) {
            CloseHandle(h);
            outPathW.clear();
            return false;
        }
        outPathW.resize(cap);
        CloseHandle(h);
        return !outPathW.empty();
    }

    // critical process 여부 검사
    bool ProcessKiller::IsCriticalProcessHandle(HANDLE hProc) const {
        static PFN_NtQueryInformationProcess pNtQueryInformationProcess = nullptr;
        static bool resolved = false;

        if (!resolved) {
            HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
            if (hNt) {
                pNtQueryInformationProcess = reinterpret_cast<PFN_NtQueryInformationProcess>(
                    GetProcAddress(hNt, "NtQueryInformationProcess"));
            }
            resolved = true;
        }
        if (!pNtQueryInformationProcess)
            return false;

        ULONG breakOnTerm = 0;
        NTSTATUS st = pNtQueryInformationProcess(
            hProc, kProcessBreakOnTermination, &breakOnTerm, sizeof(breakOnTerm), nullptr);

        if (st == 0 /*STATUS_SUCCESS*/ && breakOnTerm != 0) {
            return true; // 중요 프로세스
        }
        return false;
    }

    // 화이트리스트 초기화 & SeDebugPrivilege 활성화
    void ProcessKiller::Initialize() {
        whitelist.InitializeDefault();
        EnablePrivilege(L"SeDebugPrivilege", true);
    }

    // 살려둬야하는 pid 세팅
    void ProcessKiller::BuildSafePidSet() {
        safePids.clear();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) 
            return;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (!Process32FirstW(snap, &pe)) {
            CloseHandle(snap);
            return;
        }

        const DWORD self = GetCurrentProcessId();

        do {
            const DWORD pid = pe.th32ProcessID;
            if (IsSystemPid(pid) || pid == self) {
                safePids.insert(pid);
                continue;
            }

            const wstring exeW = pe.szExeFile;
            string exeA(exeW.begin(), exeW.end());
            if (whitelist.IsProcessWhitelisted(exeA)) {
                safePids.insert(pid);
                continue;
            }

            wstring imgW;
            if (GetProcessImagePath(pid, imgW)) {
                const string imgA = WideToUtf8(imgW);
                if (whitelist.IsPathWhitelisted(imgA)) {
                    safePids.insert(pid);
                    continue;
                }
            }

        } while (Process32NextW(snap, &pe));

        CloseHandle(snap);
        PK_LOG("BuildSafePidSet: completed");
    }

    // safepid를 제외하고 강제 프로세스 종료
    void ProcessKiller::KillAll() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (!Process32FirstW(snap, &pe)) {
            CloseHandle(snap);
            return;
        }

        const DWORD self = GetCurrentProcessId();

        do {
            const DWORD pid = pe.th32ProcessID;
            if (IsSystemPid(pid) || pid == self) {
                continue;
            }
            if (IsPidSafe(pid)) {
                continue;
            }

            const wstring exeW = pe.szExeFile;
            string exeA(exeW.begin(), exeW.end());
            if (whitelist.IsProcessWhitelisted(exeA)) {
                continue;
            }

            wstring imgW;
            if (GetProcessImagePath(pid, imgW)) {
                const string imgA = WideToUtf8(imgW);
                if (whitelist.IsPathWhitelisted(imgA)) {
                    continue;
                }
            }

            HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pid);
            if (!hProc) {
                continue;
            }

            // critical process 보호
            if (IsCriticalProcessHandle(hProc)) {
                PK_LOG("skip critical pid=" + to_string(pid));
                CloseHandle(hProc);
                continue;
            }

            if (TerminateProcess(hProc, 0)) {
                PK_LOG("terminated pid=" + to_string(pid) + " exe=" + exeA);
            }
            else {
                PK_LOG("terminate failed pid=" + to_string(pid));
            }
            CloseHandle(hProc);

        } while (Process32NextW(snap, &pe));

        CloseHandle(snap);
    }

}
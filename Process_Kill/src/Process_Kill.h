#pragma once
#include <windows.h>
#include <string>
#include <unordered_set>
#include "WhiteList.h"
using namespace std;

#ifndef PK_DEBUG
#define PK_DEBUG 1
#endif

#if PK_DEBUG
#define PK_LOG(msg) do { ::OutputDebugStringA(("[ProcessKiller] " + string(msg) + "\n").c_str()); } while(0)
#else
#define PK_LOG(msg) do {} while(0)
#endif

namespace process_killer {

    class ProcessKiller {
    public:
        void Initialize();
        void AddWhitelistPath(const string& path) { whitelist.AddPath(path); }
        void AddWhitelistProcess(const string& exe) { whitelist.AddProcess(exe); }
        void BuildSafePidSet();
        void KillAll();

    private:
        WhitelistManager whitelist;
        unordered_set<DWORD> safePids;

        static bool   EnablePrivilege(LPCWSTR name, bool enable = true);
        static bool   GetProcessImagePath(DWORD pid, wstring& outPathW);
        static string WideToUtf8(const wstring& w);

        bool IsCriticalProcessHandle(HANDLE hProc) const;
        bool IsPidSafe(DWORD pid) const { return safePids.find(pid) != safePids.end(); }
    };
}
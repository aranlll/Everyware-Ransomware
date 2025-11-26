#include "WhiteList.h"
#include <iostream>
using namespace std;

int main() {
    WhitelistManager wm;

    // 1) 초기화
    wm.InitializeDefault();

    // 2) 화이트리스트 설정
    wm.AddPath("C:\\Windows");
    wm.AddPath("C:\\Program Files");
    wm.AddProcess("svchost.exe");
    wm.AddProcess("explorer.exe");

    // 3) 간단한 테스트 함수
    auto check = [](const string& label, bool ok) {
        cout << (ok ? "[OK] " : "[NG] ") << label << '\n';
        };

    // 4) 경로 테스트
    check("Path under Windows",
        wm.IsPathWhitelisted("C:\\Windows\\System32\\drivers\\etc\\hosts"));

    check("Path NOT under Windows (WindowsOld)",
        !wm.IsPathWhitelisted("C:\\WindowsOld\\readme.txt"));

    // 5) 프로세스 테스트 (이름/전체 경로 모두 허용되는지)
    check("Process svchost by name",
        wm.IsProcessWhitelisted("svchost.exe"));

    check("Process svchost by full path (case-insensitive, filename only)",
        wm.IsProcessWhitelisted("C:\\Windows\\System32\\SVCHOST.EXE"));

    check("Process NOT whitelisted",
        !wm.IsProcessWhitelisted("random.exe"));

    cout << "Done.\n";
    return 0;
}
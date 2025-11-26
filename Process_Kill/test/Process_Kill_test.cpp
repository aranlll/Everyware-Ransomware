#include "Process_Kill.h"
using namespace process_killer;

int main() {
    ProcessKiller pk;
    pk.Initialize();
    pk.AddWhitelistPath("C:\\Windows");
    pk.AddWhitelistPath("C:\\Program Files");
    pk.AddWhitelistProcess("explorer.exe");
    pk.AddWhitelistProcess("svchost.exe");
    pk.BuildSafePidSet();
    pk.KillAll();
    return 0;
}

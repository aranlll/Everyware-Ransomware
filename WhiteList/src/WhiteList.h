#pragma once
#include <string>
#include <vector>
using namespace std;

class WhitelistManager {
private:
    vector<string> pathList;
    vector<string> procList;

public:
    void InitializeDefault();
    void AddPath(const string& path);
    void AddProcess(const string& proc);
    bool IsPathWhitelisted(const string& path);
    bool IsProcessWhitelisted(const string& proc);
};
#include "WhiteList.h"
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <string>
#include <iostream>

using namespace std;
namespace fs = std::filesystem;

// 빌드 전 #define WL_DEBUG 0을 설정하면 디버깅 로그 삭제 가능
#ifndef WL_DEBUG
#define WL_DEBUG 0
#endif

#if WL_DEBUG
#define WL_LOG(msg) do { cerr << "[Whitelist] " << msg << endl; } while(0)
#else
#define WL_LOG(msg) do {} while(0)
#endif

namespace {
    // 좌우 공백 제거
    // 입력 노이즈 감소 목적
    inline string TrimWhitespace(const string& input_text) {
        const char* kWhitespace = " \t\r\n";
        const size_t first = input_text.find_first_not_of(kWhitespace);
        if (first == string::npos) {
            WL_LOG("TrimWhitespace: input is all whitespace or empty");
            return "";
        }
        const size_t last = input_text.find_last_not_of(kWhitespace);
        return input_text.substr(first, last - first + 1);
    }

    // 소문자 변환
    // 윈도우 경로/파일명 비교의 대소문자 무시 정책을 맞추기 위해 -> Window에서는 대소문자 구분 X
    inline void ToLowercaseInplace(string& text) {
        transform(text.begin(), text.end(), text.begin(),
            [](unsigned char c) { return static_cast<char>(tolower(c)); });
    }

    // '/' → '\'로 변경
    inline void ConvertForwardSlashesToBackslashes(string& path_text) {
        for (auto& ch : path_text) if (ch == '/') ch = '\\';
    }

    // "C:\" 형태의 드라이브 루트 여부
    inline bool IsDriveRootPath(const string& normalized_path) {
        return (normalized_path.size() == 3 &&
            normalized_path[1] == ':' &&
            normalized_path[2] == '\\');
    }

    // 일반 경로 정규화: 절대화 + lexical normalize + 소문자 + 구분자 통일
    // (일반 경로 끝의 '\'는 제거, 단 드라이브 루트 "C:\"는 유지)
    inline string NormalizeFilePath(const string& raw_path) {
        string trimmed_input = TrimWhitespace(raw_path);
        if (trimmed_input.empty()) {
            WL_LOG("NormalizeFilePath: empty input");
            return "";
        }

        fs::path path_obj(trimmed_input);
        try {
            if (path_obj.is_relative()) {
                path_obj = fs::absolute(path_obj);
                WL_LOG("NormalizeFilePath: made absolute: " << path_obj.string());
            }
            else {
                WL_LOG("NormalizeFilePath: already absolute: " << path_obj.string());
            }
            path_obj = path_obj.lexically_normal();
            WL_LOG("NormalizeFilePath: lexically normalized: " << path_obj.string());
        }
        catch (const exception& ex) {
            WL_LOG(string("NormalizeFilePath: exception during fs ops: ") + ex.what());
            // 실패해도 가능한 범위에서 계속 진행
        }
        // 예상하지 못한 모든 종류의 예외를 처리
        catch (...) {
            WL_LOG("NormalizeFilePath: unknown exception during fs ops");
        }

        string normalized_path = path_obj.string();
        if (normalized_path.empty()) {
            WL_LOG("NormalizeFilePath: path became empty after fs ops");
            return "";
        }

        ConvertForwardSlashesToBackslashes(normalized_path);
        ToLowercaseInplace(normalized_path);

        // 끝의 '\' 제거(드라이브 루트는 예외)
        if (!normalized_path.empty() &&
            normalized_path.back() == '\\' &&
            !IsDriveRootPath(normalized_path)) {
            normalized_path.pop_back();
            WL_LOG("NormalizeFilePath: trimmed trailing backslash (non-root): " << normalized_path);
        }
        else {
            WL_LOG("NormalizeFilePath: final normalized: " << normalized_path);
        }
        return normalized_path;
    }

    // 루트 경로 정규화: NormalizeFilePath + 항상 끝에 '\' 부여
    // 접두사로 인해 발생하는 오탐을 줄이기 위해
    inline string NormalizeRootPath(const string& raw_root_path) {
        if (raw_root_path.empty()) {
            WL_LOG("NormalizeRootPath: empty input");
            return "";
        }
        string normalized_root = NormalizeFilePath(raw_root_path);
        if (normalized_root.empty()) {
            WL_LOG("NormalizeRootPath: NormalizeFilePath failed; returning empty");
            return "";
        }
        if (normalized_root.back() != '\\') {
            normalized_root.push_back('\\');
            WL_LOG("NormalizeRootPath: ensured trailing backslash: " << normalized_root);
        }
        else {
            WL_LOG("NormalizeRootPath: already has trailing backslash: " << normalized_root);
        }
        return normalized_root;
    }

    // 프로세스명 정규화: 경로가 와도 filename만 취해 소문자로 변환
    // Ex : C:\...\svchost.exe -> svchost.exe
    inline string NormalizeProcessName(const string& proc_path_or_name) {
        string trimmed_input = TrimWhitespace(proc_path_or_name);
        if (trimmed_input.empty()) {
            WL_LOG("NormalizeProcessName: empty input");
            return "";
        }
        string file_name_lower = fs::path(trimmed_input).filename().string();
        ToLowercaseInplace(file_name_lower);
        if (file_name_lower.empty()) {
            WL_LOG("NormalizeProcessName: filename extraction failed (empty)");
        }
        else {
            WL_LOG("NormalizeProcessName: normalized process name: " << file_name_lower);
        }
        return file_name_lower;
    }

    // path가 root의 하위 폴더나 파일이 맞는지 검사
    inline bool IsPathUnderRoot(const string& normalized_path,
        const string& normalized_root_with_slash) {
        if (normalized_path.empty() || normalized_root_with_slash.empty()) {
            WL_LOG("IsPathUnderRoot: one of the arguments is empty");
            return false;
        }
        const bool is_under = (normalized_path.rfind(normalized_root_with_slash, 0) == 0);
        WL_LOG("IsPathUnderRoot: path=" << normalized_path
            << " root=" << normalized_root_with_slash
            << " => " << (is_under ? "true" : "false"));
        return is_under;
    }

}

// 내부 리스트를 초기화
void WhitelistManager::InitializeDefault() {
    // mutex 제거 버전: 락 없이 바로 접근
    pathList.clear();
    procList.clear();
    WL_LOG("InitializeDefault: cleared pathList and procList");

    // 추후에 추가예정
    // pathList = { NormalizeRootPath("C:\\Windows") };
    // procList = { NormalizeProcessName("explorer.exe") };
}

// 입력 경로를 루트로 정규화하여 추가
void WhitelistManager::AddPath(const string& path) {
    if (path.empty()) {
        WL_LOG("AddPath: empty input; ignored");
        return;
    }

    const string normalized_root_with_slash = NormalizeRootPath(path);
    if (normalized_root_with_slash.empty()) {
        WL_LOG("AddPath: NormalizeRootPath returned empty; ignored");
        return;
    }

    // 비어 있으면 바로 추가
    if (pathList.empty()) {
        pathList.push_back(normalized_root_with_slash);
        WL_LOG("AddPath: pathList was empty; inserted root: " << normalized_root_with_slash);
        return;
    }

    // 이미 더 상위 루트가 있으면 추가 불필요
    const string normalized_root_without_slash = normalized_root_with_slash.substr(0, normalized_root_with_slash.size() - 1);

    bool is_already_covered = false;
    for (const auto& existing_root_with_slash : pathList) {
        if (!existing_root_with_slash.empty()) {
            if (IsPathUnderRoot(normalized_root_without_slash, existing_root_with_slash)) {
                WL_LOG("AddPath: new root is covered by existing root: "
                    << existing_root_with_slash << " ; skipping "
                    << normalized_root_with_slash);
                is_already_covered = true;
                break;
            }
        }
    }
    if (is_already_covered) return;

    // 기존 루트 중 새 루트 하위인 것은 제거하여 최소화
    for (auto iter = pathList.begin(); iter != pathList.end(); ) {
        if (!iter->empty()) {
            const string existing_root_without_slash = iter->substr(0, iter->size() - 1);
            if (IsPathUnderRoot(existing_root_without_slash, normalized_root_with_slash)) {
                WL_LOG("AddPath: removing existing root covered by new root: " << *iter);
                iter = pathList.erase(iter);
                continue;
            }
        }
        ++iter;
    }

    // 중복 체크 후 추가
    if (find(pathList.begin(), pathList.end(), normalized_root_with_slash) == pathList.end()) {
        pathList.push_back(normalized_root_with_slash);
        sort(pathList.begin(), pathList.end());
        pathList.erase(unique(pathList.begin(), pathList.end()), pathList.end());
        WL_LOG("AddPath: inserted new root: " << normalized_root_with_slash);
    }
    else {
        WL_LOG("AddPath: duplicate root; ignored: " << normalized_root_with_slash);
    }
}

// 프로세스명을 정규화해 중복 없이 추가
void WhitelistManager::AddProcess(const string& proc) {
    if (proc.empty()) {
        WL_LOG("AddProcess: empty input; ignored");
        return;
    }

    const string normalized_proc_name = NormalizeProcessName(proc);
    if (normalized_proc_name.empty()) {
        WL_LOG("AddProcess: NormalizeProcessName returned empty; ignored");
        return;
    }

    if (procList.empty()) {
        procList.push_back(normalized_proc_name);
        WL_LOG("AddProcess: procList was empty; inserted proc: " << normalized_proc_name);
        return;
    }

    if (find(procList.begin(), procList.end(), normalized_proc_name) == procList.end()) {
        procList.push_back(normalized_proc_name);
        WL_LOG("AddProcess: inserted new proc: " << normalized_proc_name);
    }
    else {
        WL_LOG("AddProcess: duplicate proc; ignored: " << normalized_proc_name);
    }
}

// 해당 경로가 등록된 루트들 중 어느 하나의 하위라면 화이트리스트로 판단
bool WhitelistManager::IsPathWhitelisted(const string& path) {
    if (path.empty()) {
        WL_LOG("IsPathWhitelisted: empty input => false");
        return false;
    }

    const string normalized_path = NormalizeFilePath(path);
    if (normalized_path.empty()) {
        WL_LOG("IsPathWhitelisted: normalized path is empty => false");
        return false;
    }

    if (pathList.empty()) {
        WL_LOG("IsPathWhitelisted: pathList is empty => false");
        return false;
    }

    for (const auto& root_with_slash : pathList) {
        if (!root_with_slash.empty() && IsPathUnderRoot(normalized_path, root_with_slash)) {
            WL_LOG("IsPathWhitelisted: matched root => true (" << root_with_slash << ")");
            return true;
        }
        else {
            if (!root_with_slash.empty()) {
                WL_LOG("IsPathWhitelisted: not under root => " << root_with_slash);
            }
        }
    }
    WL_LOG("IsPathWhitelisted: no root matched => false");
    return false;
}

// 해당 파일이 등록된 프로세스 목록에 존재하면 화이트리스트로 판단
bool WhitelistManager::IsProcessWhitelisted(const string& proc) {
    if (proc.empty()) {
        WL_LOG("IsProcessWhitelisted: empty input => false");
        return false;
    }

    const string normalized_proc_name = NormalizeProcessName(proc);
    if (normalized_proc_name.empty()) {
        WL_LOG("IsProcessWhitelisted: normalized name is empty => false");
        return false;
    }

    if (procList.empty()) {
        WL_LOG("IsProcessWhitelisted: procList is empty => false");
        return false;
    }

    const bool is_found = (find(procList.begin(), procList.end(), normalized_proc_name) != procList.end());
    if (is_found) {
        WL_LOG("IsProcessWhitelisted: found => true (" << normalized_proc_name << ")");
    }
    else {
        WL_LOG("IsProcessWhitelisted: not found => false (" << normalized_proc_name << ")");
    }
    return is_found;
}
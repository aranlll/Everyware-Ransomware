#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <set>

namespace fs = std::filesystem;

class FileScanner {
public:
    // targetDir: 검색할 최상위 디렉토리(절대경로/상대경로 가능)
    explicit FileScanner(const std::string& targetDir);

    // 디렉토리 스캔하여 화이트리스트에 해당하는 파일 경로 목록 반환
    // followSymlinks: 심볼릭 링크를 따라갈지 여부 (기본: false)
    std::vector<fs::path> scan(bool followSymlinks = false) const;

    // 설정자들
    void setMaxDepth(size_t d) noexcept;                          // 재귀 최대 깊이
    void setWhitelist(const std::set<std::string>& exts) noexcept; // 허용 확장자 집합 (소문자 포함)
    void setMaxFileSizeBytes(uint64_t bytes) noexcept;            // 파일 크기 제한(바이트), 0이면 제한 없음

private:
    fs::path target;
    size_t maxDepth = 10;
    std::set<std::string> whitelist = {
        ".txt", ".md", ".csv", ".log", ".json",
        ".jpg", ".jpeg", ".png", ".bmp", ".gif",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx",
        ".cpp", ".hpp", ".h", ".c", ".py", ".java",
        ".mp3", ".wav"
    };
    uint64_t maxFileSize = 0; // 0 = 무제한

    // 내부 헬퍼
    bool isUnsafeTarget(const fs::path& p) const;
    static std::string normExtLower(const fs::path& p);
};

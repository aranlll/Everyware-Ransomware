#include "../include/FileScanner.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <functional>
#include <system_error>

using namespace std;
namespace fs = std::filesystem;

// -----------------------------
// 도우미 함수: 문자열을 소문자로 변환
// -----------------------------
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

// -----------------------------
// 생성자: 대상 디렉토리 경로 설정
// -----------------------------
FileScanner::FileScanner(const std::string& targetDir)
    : target(targetDir) {}

// -----------------------------
// 설정자들
// -----------------------------
void FileScanner::setMaxDepth(size_t d) noexcept { maxDepth = d; }
void FileScanner::setWhitelist(const std::set<std::string>& exts) noexcept { whitelist = exts; }
void FileScanner::setMaxFileSizeBytes(uint64_t bytes) noexcept { maxFileSize = bytes; }

// -----------------------------
// normExtLower: 파일 확장자를 소문자로 반환
// -----------------------------
std::string FileScanner::normExtLower(const fs::path& p) {
    std::string ext = p.extension().string();
    return toLower(ext);
}

// -----------------------------
// isUnsafeTarget: 시스템/루트 디렉토리 같은 위험한 대상 차단
// (플랫폼별 간단 체크; 필요시 더 엄격하게 확장 가능)
// -----------------------------
bool FileScanner::isUnsafeTarget(const fs::path& p) const {
    std::string s = p.lexically_normal().string();
    return false;
}

// -----------------------------
// scan: 재귀적으로 디렉토리 탐색하여 whitelist에 맞는 파일 목록 반환
// - 예외/권한 문제는 무시하고 가능한 파일만 수집
// - 깊이 제한 및 파일 크기 제한 적용
// -----------------------------
std::vector<fs::path> FileScanner::scan(bool followSymlinks) const {
    std::vector<fs::path> result;

    // 대상 존재 및 디렉토리 확인
    std::error_code ec;
    if (!fs::exists(target, ec) || !fs::is_directory(target, ec)) {
        std::cerr << "[FileScanner] 대상이 존재하지 않거나 디렉토리가 아님: " << target << "\n";
        return result;
    }

    // 안전 체크: 루트/시스템 등 위험한 경로는 거부
    if (isUnsafeTarget(target)) {
        std::cerr << "[FileScanner] 거부된 대상(시스템/루트): " << target << "\n";
        return result;
    }

    // 내부 재귀 함수 정의
    std::function<void(const fs::path&, size_t)> visit;
    visit = [&](const fs::path& p, size_t depth) {
        // 깊이 제한 체크
        if (depth > maxDepth) return;

        // 디렉토리 항목 열기
        std::error_code dirEc;
        for (const auto& entry : fs::directory_iterator(p, fs::directory_options::skip_permission_denied, dirEc)) {
            try {
                // 항목 경로
                fs::path ep = entry.path();

                // 디렉토리이면 재귀
                if (entry.is_directory(dirEc)) {
                    // 안전: 심볼릭 링크를 따라갈지 여부 고려
                    if (entry.is_symlink(dirEc) && !followSymlinks) {
                        continue;
                    }
                    visit(ep, depth + 1);
                }
                // 파일이면 화이트리스트/크기 검사
                else if (entry.is_regular_file(dirEc)) {
                    // 파일 크기 제한(설정되어 있다면)
                    if (maxFileSize > 0) {
                        std::error_code sizeEc;
                        uint64_t sz = static_cast<uint64_t>(fs::file_size(ep, sizeEc));
                        if (sizeEc) {
                            // 파일 크기 조회 실패 시 건너뜀
                            continue;
                        }
                        if (sz > maxFileSize) continue;
                    }

                    // 확장자 필터(소문자 비교)
                    std::string ext = normExtLower(ep);
                    if (whitelist.find(ext) != whitelist.end()) {
                        result.push_back(ep);
                    }
                }
                // 그 외(특수파일 등)는 건너뜀
            } catch (const std::exception& ex) {
                // 특정 엔트리에서 예외 발생 시 경고 후 다음 항목 진행
                std::cerr << "[FileScanner] 스킵: " << entry.path() << " (" << ex.what() << ")\n";
                continue;
            }
        }
        if (dirEc) {
            // 디렉토리 반복 중 에러가 발생하면 로그만 남김 (권한 등)
            std::cerr << "[FileScanner] directory_iterator error at " << p << " : " << dirEc.message() << "\n";
        }
    };

    // 실제 탐색 시작
    try {
        visit(target, 0);
    } catch (const std::exception& ex) {
        std::cerr << "[FileScanner] scan 중 예외: " << ex.what() << "\n";
    }

    return result;
}

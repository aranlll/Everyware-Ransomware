#include <iostream>
#include <windows.h>
#include <winternl.h> // PIMAGE_... 헤더 구조체를 위해 필요
#include <psapi.h>   // GetModuleFileNameExA
#include <libloaderapi.h> // GetModuleHandleA
#include <string>
#include <vector>

/*
 * ==========================================================================
 * "unhooking.h"의 추정 내용 (헤더 파일이 없으므로 여기에 직접 정의)
 * ==========================================================================
 */

 // 1. 훅 타입 정의
typedef enum _HOOK_TYPE {
	HOOK_NONE,
	HOOK_UNSUPPORTED,
	HOOK_RELATIVE,
	HOOK_ABSOLUTE,
	HOOK_ABSOLUTE_INDIRECT,
	HOOK_ABSOLUTE_INDIRECT_64
} HOOK_TYPE;

// 2. 오류 코드 정의 (임의의 값)
#define ERR_SUCCESS 0
#define ERR_MOD_NAME_NOT_FOUND 1
#define ERR_CREATE_FILE_FAILED 2
#define ERR_CREATE_FILE_MAPPING_FAILED 3
#define ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS 4
#define ERR_MAP_FILE_FAILED 5
#define ERR_MEM_DEPROTECT_FAILED 6
#define ERR_MEM_REPROTECT_FAILED 7
#define ERR_TEXT_SECTION_NOT_FOUND 8
#define ERR_ENUM_PROCESS_MODULES_FAILED 9
#define ERR_SIZE_TOO_SMALL 10

// 3. 훅 정보 구조체 (이 코드에서는 직접 사용되진 않지만 원본에 있었음)
typedef struct _HOOK_FUNC_INFO {
	HMODULE hModule;
	LPVOID lpFuncAddress;
	CHAR szFuncName[256];
	CHAR szHookModuleName[MAX_PATH];
	LPVOID lpHookAddress;
} HOOK_FUNC_INFO, * LPHOOK_FUNC_INFO;

/*
 * ==========================================================================
 * 1. 후킹 탐지 및 헬퍼 함수 (원본 코드 기반)
 * ==========================================================================
 */

 /**
  * @brief 특정 함수의 프롤로그를 검사하여 인라인 훅 여부를 식별합니다.
  */
static HOOK_TYPE IsHooked(const LPVOID lpFuncAddress, DWORD_PTR* dwAddressOffset) {
	LPCBYTE lpAddress = (LPCBYTE)lpFuncAddress;

	if (lpAddress[0] == 0xE9) { // JMP rel
		*dwAddressOffset = 1;
		return HOOK_RELATIVE;
	}
	else if (lpAddress[0] == 0x90 && lpAddress[1] == 0xE9) { // NOP + JMP rel
		*dwAddressOffset = 2;
		return HOOK_RELATIVE;
	}
	else if (lpAddress[0] == 0x8B && lpAddress[1] == 0xFF && lpAddress[2] == 0xE9) { // MOV EDI, EDI + JMP rel
		*dwAddressOffset = 3;
		return HOOK_RELATIVE;
	}
	else if (lpAddress[0] == 0x68 && lpAddress[5] == 0xC3) { // PUSH ... RET
		*dwAddressOffset = 1;
		return HOOK_ABSOLUTE;
	}
	else if (lpAddress[0] == 0x90 && lpAddress[1] == 0x68 && lpAddress[6] == 0xC3) { // NOP + PUSH ... RET
		*dwAddressOffset = 2;
		return HOOK_ABSOLUTE;
	}
	else if (lpAddress[0] == 0xFF && lpAddress[1] == 0x25) { // JMP [addr]
		*dwAddressOffset = 2;
		return HOOK_ABSOLUTE_INDIRECT;
	}
	else if (lpAddress[0] == 0x8B && lpAddress[1] == 0xFF && lpAddress[2] == 0xFF && lpAddress[3] == 0x25) { // MOV EDI, EDI + JMP [addr]
		*dwAddressOffset = 4;
		return HOOK_ABSOLUTE_INDIRECT;
	}
	else if (lpAddress[0] == 0x48 && lpAddress[1] == 0xFF && lpAddress[2] == 0x25) { // JMP [rip+...] (x64)
		*dwAddressOffset = 3;
		return HOOK_ABSOLUTE_INDIRECT_64;
	}

	return HOOK_NONE;
}

/*
   메모리 보호 속성을 변경하고 이전 속성을 반환합니다.
 */
static DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect) {
	DWORD flOldProtect = 0;
	BOOL bRet = VirtualProtect(
		lpAddress,
		nSize,
		flNewProtect,
		&flOldProtect
	);

	if (bRet == FALSE) {
		return 0; // 실패 시 0 반환
	}

	return flOldProtect;
}

/*
  @brief 모듈 핸들로부터 디스크 상의 전체 파일 경로를 가져옵니다.
 */
DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize) {
	DWORD dwLength = GetModuleFileNameExA(
		GetCurrentProcess(),
		hModule,
		szModuleName,
		nSize
	);

	if (dwLength == 0) {
		strncpy_s(szModuleName, nSize, "<not found>", _TRUNCATE);
		return ERR_MOD_NAME_NOT_FOUND;
	}

	return ERR_SUCCESS;
}


/*
 * ==========================================================================
 * 2. "외과수술식" 언후킹 핵심 로직
 * ==========================================================================
 */

 /**
  * @brief 모듈의 Export Table을 파싱하여 후킹된 함수만 선별적으로 복구합니다.
  * @param hModule 후킹된 모듈의 핸들 (예: GetModuleHandleA("ntdll.dll"))
  * @param lpMapping 디스크에서 로드한 깨끗한 모듈의 매핑 주소
  * @return 성공 시 ERR_SUCCESS, 실패 시 오류 코드
  */
static DWORD SurgicallyRepairHooks(const HMODULE hModule, const LPVOID lpMapping) {
	// 1. 두 모듈의 PE 헤더를 파싱합니다.
	PIMAGE_DOS_HEADER pLocalDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pLocalNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pLocalDosHeader->e_lfanew);

	PIMAGE_DOS_HEADER pCleanDosHeader = (PIMAGE_DOS_HEADER)lpMapping;
	PIMAGE_NT_HEADERS pCleanNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + pCleanDosHeader->e_lfanew);

	// 2. 두 모듈의 Export Directory를 찾습니다.
	DWORD dwExportDirRVA = pLocalNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (dwExportDirRVA == 0) return ERR_SUCCESS; // Export 테이블이 없는 DLL (정상)
	PIMAGE_EXPORT_DIRECTORY pLocalExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + dwExportDirRVA);

	DWORD dwCleanExportDirRVA = pCleanNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (dwCleanExportDirRVA == 0) return ERR_SUCCESS; // Export 테이블이 없는 DLL (정상)
	PIMAGE_EXPORT_DIRECTORY pCleanExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpMapping + dwCleanExportDirRVA);

	// 깨끗한 DLL의 Export 테이블 정보
	PDWORD pdwCleanFunctions = (PDWORD)((DWORD_PTR)lpMapping + pCleanExportDir->AddressOfFunctions);
	PDWORD pdwCleanNames = (PDWORD)((DWORD_PTR)lpMapping + pCleanExportDir->AddressOfNames);
	PWORD pwCleanOrdinals = (PWORD)((DWORD_PTR)lpMapping + pCleanExportDir->AddressOfNameOrdinals);

	// 후킹된 DLL의 Export 테이블 정보
	PDWORD pdwLocalFunctions = (PDWORD)((DWORD_PTR)hModule + pLocalExportDir->AddressOfFunctions);


	// 3. 깨끗한 모듈의 Export Table을 기준으로 모든 함수를 순회합니다.
	// (후킹된 모듈의 EAT가 변조되었을 가능성에 대비)
	for (DWORD i = 0; i < pCleanExportDir->NumberOfNames; i++) {
		// 3-1. 깨끗한 모듈에서 함수 이름과 서수(ordinal)를 가져옵니다.
		LPCSTR pszFuncName = (LPCSTR)((DWORD_PTR)lpMapping + pdwCleanNames[i]);
		WORD wOrdinal = pwCleanOrdinals[i];

		// 3-2. 서수를 이용해 두 모듈에서 각각 함수의 주소를 찾습니다.
		LPVOID lpLocalFuncAddress = (LPVOID)((DWORD_PTR)hModule + pdwLocalFunctions[wOrdinal]);
		LPVOID lpCleanFuncAddress = (LPVOID)((DWORD_PTR)lpMapping + pdwCleanFunctions[wOrdinal]);

		// 3-3. IsHooked 함수로 후킹 여부를 검사합니다.
		DWORD_PTR dwHookOffset = 0;
		HOOK_TYPE hookType = IsHooked(lpLocalFuncAddress, &dwHookOffset);

		if (hookType != HOOK_NONE && hookType != HOOK_UNSUPPORTED) {


			// 3-4. 원본 코드로 복구를 시도합니다.
			// 16바이트를 복구한다고 가정합니다. (대부분의 핫패치 훅은 16바이트 이내)
			const SIZE_T nPatchSize = 16;

			// 3-5. 메모리 권한을 변경합니다. (쓰기 가능하게)
			DWORD flOldProtect = ProtectMemory(
				lpLocalFuncAddress,
				nPatchSize,
				PAGE_EXECUTE_READWRITE
			);

			if (!flOldProtect) {
				std::cerr << "        [ERR] Failed to deprotect memory for " << pszFuncName << std::endl;
				continue; // 권한 변경 실패. 다음 함수로
			}

			// 3-6. 깨끗한 코드로 덮어씁니다. (memcpy)
			memcpy(lpLocalFuncAddress, lpCleanFuncAddress, nPatchSize);

			// 3-7. 메모리 권한을 원래대로 복구합니다.
			ProtectMemory(
				lpLocalFuncAddress,
				nPatchSize,
				flOldProtect
			);

		}
	}

	return ERR_SUCCESS;
}


/**
 * @brief "Surgical" 방식으로 모듈을 언후킹합니다.
 * 디스크에서 깨끗한 DLL을 로드/매핑한 후, SurgicallyRepairHooks를 호출합니다.
 */
DWORD UnhookModule(const HMODULE hModule) {
	CHAR szModuleName[MAX_PATH];
	ZeroMemory(szModuleName, sizeof(szModuleName));

	// 1. 모듈의 전체 경로를 가져옵니다.
	DWORD dwRet = GetModuleName(
		hModule,
		szModuleName,
		sizeof(szModuleName)
	);
	if (dwRet != ERR_SUCCESS) {
		return dwRet; // GetModuleName에서 오류 발생
	}

	// 2. 깨끗한 원본 파일을 엽니다.
	HANDLE hFile = CreateFileA(
		szModuleName, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ERR_CREATE_FILE_FAILED;
	}

	// 3. 파일 매핑 객체를 생성합니다.
	HANDLE hFileMapping = CreateFileMappingA(
		hFile, NULL, PAGE_READONLY | SEC_IMAGE,
		0, 0, NULL
	);
	if (!hFileMapping) {
		CloseHandle(hFile);
		return (GetLastError() == ERROR_ALREADY_EXISTS) ?
			ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS :
			ERR_CREATE_FILE_MAPPING_FAILED;
	}

	// 4. 파일을 메모리에 매핑합니다. (이것이 "깨끗한" DLL 데이터입니다)
	LPVOID lpMapping = MapViewOfFile(
		hFileMapping, FILE_MAP_READ, 0, 0, 0
	);
	if (!lpMapping) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return ERR_MAP_FILE_FAILED;
	}

	// 5. 핵심: 선별적 복구 함수를 호출합니다.
	// (기존 ReplaceExecSection 대신 사용)
	dwRet = SurgicallyRepairHooks(hModule, lpMapping);

	// 6. 리소스 정리
	UnmapViewOfFile(lpMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return dwRet; // SurgicallyRepairHooks의 결과 반환
}


/*
 * ==========================================================================
 * 3. 메인 로직: 타겟 리스트 기반 언후킹 실행
 * ==========================================================================
 */

 /**
  * @brief 타겟 리스트에 있는 핵심 모듈들만 언후킹을 시도합니다.
  */
void RunTargetedUnhooking()
{
	// 1. EDR/백신이 주로 후킹하는 핵심 DLL 리스트를 정의합니다.
	const char* targetDlls[] = {
		"ntdll.dll",
		"kernel32.dll",
		"kernelbase.dll",
		"advapi32.dll",
		"ws2_32.dll",
		"user32.dll"
	};


	// 2. GetModules() 대신, 타겟 리스트를 순회합니다.
	for (const char* dllName : targetDlls)
	{
		// 3. DLL 이름을 기반으로 모듈 핸들을 직접 가져옵니다.
		HMODULE hModule = GetModuleHandleA(dllName);

		if (hModule == NULL) {
			// 해당 DLL이 아직 로드되지 않았을 수 있습니다. (정상)
			continue;
		}

		// 4. UnhookModule 함수를 호출합니다.
		DWORD dwResult = UnhookModule(hModule);


}
#include <iostream>
#include <windows.h>
#include <winternl.h>
//PE헤더 파싱에 사용(깨끗한 DLL 매핑 & 안에서 함소 주소를 찾으려면 필요)
#include <psapi.h> 
//GetModuleInformation, 현재 시스템에서 실행중인 프로세스 & 로드한 dll 정보
#include <pathcchj.h>
//경로 조합&함수

#include "unhooking.h"

typedef enum _HOOK_TYPE {
	//훅 타입 
}

DWORD CheckModuleForHooks(const HMODULE hModule, LPHOOK_FUNC_INFO* infos, const SIZE_T nSize, LPDWORD cbNeeded);
//hModule로 지정된 DLL을 훅 스캐닝 하여, 인라인 후킹된 함수를 찾음(변경 X)
//CheckModuleForHooks에서 isHook을 통해 선형탐색하면 될듯 ??

★★★★★
static HOOK_TYPE isHooked(const LPVOID lpFuncAddress, DWORD_PTR* dwAddressOFFset) {
	//훅 여부를 확인하고 후킹 여부에 따라 dwAdadressOffset을 설정
	//인라인 후킹 확인 예시
	if (lpAddress[0] == 0xE9) {
		*dwAddressOffset = 1;
		return HOOK_RELATIVE;
	}
	//인자값 : 
	1. lpFuncAddress : 함수의 메모리 시작 주소
		2. * dwAddressOffset DWORD_PTR * (메모리 주소를 담을 수 있는 크기의 정수 변수에 대한 포인터)
		//리턴값 1. HOOK X 2. 상대주소로 후킹됨 3. 절대주소로 후킹됨

		★★★★★

		DWORD UnhookModule(const HMODULE hModule);
	//hMoudle에 있는 후킹된 코드 영역을 꺠끗한 원본 파일의 코드로 덮어쓰는 언후킹
	1. GetModuleName으로 메모리 파일의 원본 파일 경로 확인
		2. CreateFile로 위에서 찾은 메모리 경로의 깨끗한 원본을 엶
		3. CreateFileMapping으로 파일을 메모리에 매핑할 수 있도록 객체 생성
		4. MapViewOfFile로 매핑 객체를 통해 깨끗한 파일을 프로세스 메모리에 데이터처럼 불러옴
		5. ReplaceExecSection 호출 : 후킹된 코드를 꺠끗한 원본의 데이터로 덮어씀
		6. 리소스 정리 & 결과 반환(성공 : SUCCESS)

		DWORD GetModuleNmae(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize);
	//hModule을 받아서 이 모듈이 로드된 디스크의 전체 경로를 문자열로 반환

	CreateFile, CreateFileMapping, MapViewOFFIle은 Windows.h에 포함됨

		static DWORD ReplaceExecSection(const HMODULE hModule, const LPVOID lpMapping) {
		//인자값 
		1. hModule :.text섹션이 교체될 후킹된 원본 대상
			2. lpMapping : 새로 로드한 깨끗한 상태의 dll 주소(UnhookModule이 읽어오고 매핑한 주소)

			//진행과정
			1. lpMapping을 분석해서 덮어쓸 코드 영역의 위치와 크기
			2. hMoudle의.text영역의 권한을 변경(VirtualProtect로 쓰기 권한 부여)
			3. hModule의.text영역에 깨끗한 코드 삽입
			4. 메모리 권한 원상 복구(hModule의 쓰기 권한 제거)
			5. 반환값(성공 : SUCCESS)
	}

	static DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect) {
		//VirtualProtect로 권한 변경을 조금 더 편하게 하기 위한 보조 함수, 특정 메모리 영역의 속성
		//을 변경하고, 변경 전의 원래 권한 값을 반환
	}

	DWORD GetModule(HMODULE * hModules, const DWORD nSize, LPDWORD dwNumModules);
	//현재 로드된 모든 DLL 목록을 가져옴

	static BOOL CompareFilePaths(LPCSTR lpszFilePath1, LPCSTR lpszFilePath2) {
		//두개의 파일 경로를 받아서 폴더 경로가 같은지 확인하는 보조함수
	}
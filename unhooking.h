#pragma once
#include <Windows.h>
#define SIZE_OF_FUNC_NAME 256

typedef struct _HOOK_FUNC_INFO{
/*훅 정보를 저장할 구조체
	1. hModule : 함수의 핸들 모듈(함수가 원래 소속된 DLL의 메모리 시작 주소)
	2. dwOrdinal : 함수의 고유 ID 번호
	3. lpFuncAddress : 후킹된 함수가 위치한 실제 메모리 주소
	4. szFuncName : 후킹된 함수의 이름
	5. szHookModuleName : 훅의 목적지 주소(JMP)
	6. lpHookAddress (악성코드 주소가 어떤 DLL 모듈에 포함되어있는지 확인)
*/

// unhooking.h에 선언 안되어있지만 필요한 변수(타코드에서 사용하는 변수)
// LPDWORD cbNeeded
// LPSTR szModuleName

//LPVOID와 HMODULE은 void*형이다 
HMODULE hModule;
DWORD dwOrdinal;
LPVOID lpFuncAddress;
//char형은 c언어와의 호환 + 저수준 제어
CHAR szFuncName[SIZEOF_FUNC_NAME];
CHAR szHookModuleName[SIZEOF_FUNC_NAME];
LPVOID lpHookAddress;

} HOOK_FUNC_INFO, *LPHOOK_FUNC_INFO;

LPHOOK_FUNC_INFO NewHookFuncInfo(void);
// HookFuncInfo 포인터의 동적 할당
// 성공시 주소 return 실패시 NULL
BOOL FreeHookFuncInfo(LPHOOK_FUNC_INFO *info);
// 선언된 포인터 할당 해제 
// 성공시 True 실패시 False

DWORD CheckModuleForHooks(const HMODULE hModule, LPHOOK_FUNC_INFO *infos, const SIZE_T nSize, LPDWORD cbNeeded);

/*hModule로 지정된 DLL을 훅 스캐닝 하여, 인라인 후킹된 함수를 찾음(변경 X)
1. 파일 경로 찾기
2. 복사본 로드
3. 코드 덮어쓰기
*/

DWORD UnhookModule(const HMODULE hModule);
// hMoudle에 있는 후킹된 코드 영역을 꺠끗한 원본 파일의 코드로 덮어쓰는 언후킹
/* Parameter : hModule

리턴값 : 
1. SUCCESS
2. ERR_MOD_NAME_NOT_FOUND
3. ERR_CREATE_FILE_FAILED
4. ERR_CREATE_FILE_MAPPING_FAILED
5. ERR_MAP_FILE_FAILED

*/


DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize);
// hModule을 받아서 이 모듈이 로드된 디스크의 전체 경로를 문자열로 반홙
// 현재 로드된 모든 DLL 목록을 가져옴
/* Parameter
-hModule : 모듈 핸들
-szModuleName : 배열형태의 경로, 출력을 위한 인수
-nsize : 경로의 길이(szModuleName버퍼의 총 크기)
*/

//리턴값 : SUCCESS, NOT Found


DWORD GetModules(HMODULE *hModules, const DWORD nSize, LPDWORD dwNumModules);
// 현재 프로세스에서 로드되어있는 DLL의 핸들 목록을 가져옴
/* Parameters 
-hModule : 찾아낸 모듈들의 HMODULE 핸들 값을 채워 넣을 배열
-Size : 버퍼의 크기
-dwNumModules : 함수가 실제로 찾은 모듈의 총 개수를 저장할 포인터
*/
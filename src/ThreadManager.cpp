#include "ThreadManager.h"
#include <iostream>
#include <chrono>

using namespace ThreadManager;

ThreadPool::ThreadPool(PoolType type, size_t threadCount)
    : poolType(type) // 어떤 타입인지 구분용 (이것도 나중에 수정해야합니다 지금은 LOCAL/ NETWORK/BACKUP 으로 나눠져 있음))
{
    threads.reserve(threadCount); // 쓰레드 벡터에 지정개수만큼 공간 확보
}  
ThreadPool::~ThreadPool() {
    Stop(); // 쓰레드 종료
} 

void ThreadPool::Start() {
    stopFlag = false;
    for (size_t i = 0; i < threads.capacity(); ++i) {
        threads.emplace_back(&ThreadPool::Worker, this);
    } // 쓰레드를 생성하고 Worker 함수 실행
    // threads.capaciry 만큼 반복  
}

void ThreadPool::Stop() {
    {
        std::unique_lock<std::mutex> lock(mtx);
        stopFlag = true; //중지요청 
    }
    cv.notify_all(); // 대기중 쓰레드 깨우기

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    } // 쓰레드 작업종료 후 정리됨
    threads.clear();
}


void ThreadPool::AddTask(const std::wstring& filename) {
    {
        std::unique_lock<std::mutex> lock(mtx);
        tasks.push({ filename, poolType }); // task에 작업 추가
    }
    cv.notify_one(); // 대기중이던 쓰레드 하나만 깨우기
}

size_t ThreadPool::GetPendingCount() {
    std::unique_lock<std::mutex> lock(mtx);
    return tasks.size();
}

void ThreadPool::Worker() {
    while (true) {
        Task task;

        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&]() { return stopFlag || !tasks.empty(); });
							// 새 작업 들어오거나 stopFlag 들어오면 깸 
            if (stopFlag && tasks.empty())
                break;

            task = tasks.front();
            tasks.pop(); //맨앞 작업 꺼냄 
        }

        
        std::wcout << L"[Thread " << GetCurrentThreadId() << L"] "
                   << L"Processing file: " << task.filename << L" in pool ";

        switch (task.poolType) {
        case LOCAL_POOL:   std::wcout << L"(LOCAL)\n"; break;
        case NETWORK_POOL: std::wcout << L"(NETWORK)\n"; break;
        case BACKUP_POOL:  std::wcout << L"(BACKUP)\n"; break;
        } // 어떤 작업 처리중인지 콘솔 출력 (디버그용)

        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 시뮬레이션
    }
}


void PoolManager::CreatePools(size_t localCount, size_t networkCount, size_t backupCount) {
    localPool   = new ThreadPool(LOCAL_POOL, localCount);
    networkPool = new ThreadPool(NETWORK_POOL, networkCount);
    backupPool  = new ThreadPool(BACKUP_POOL, backupCount);

    localPool->Start();
    networkPool->Start();
    backupPool->Start();
} // 3개한꺼번에 관리하는 관리자 , 각 쓰레드풀 시작

void PoolManager::AddTask(PoolType pool, const std::wstring& filename) {
    switch (pool) {
    case LOCAL_POOL:   if (localPool)   localPool->AddTask(filename); break;
    case NETWORK_POOL: if (networkPool) networkPool->AddTask(filename); break;
    case BACKUP_POOL:  if (backupPool)  backupPool->AddTask(filename); break;
    }
} // 각 지정한 풀에 작업 추가(파일이름), 저희 파일 이거 불러오는거 누구 담당인가요...? 

void PoolManager::WaitAll() {
   
    bool done = false;
    while (!done) {
        done = true;
        if (localPool   && localPool->GetPendingCount() > 0) done = false;
        if (networkPool && networkPool->GetPendingCount() > 0) done = false;
        if (backupPool  && backupPool->GetPendingCount() > 0) done = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } // 한작업이 끝나고나면 풀의 작업 다 끝날때까지 
}

void PoolManager::StopAll() {
    if (localPool)   localPool->Stop();
    if (networkPool) networkPool->Stop();
    if (backupPool)  backupPool->Stop();
} 

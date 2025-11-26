#pragma once
#include <Windows.h>
#include <string>
#include <queue>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace ThreadManager {

    enum PoolType {
        LOCAL_POOL = 0,
        NETWORK_POOL,
        BACKUP_POOL
    };

    struct Task {
        std::wstring filename;
        PoolType poolType;
    };

    class ThreadPool {
    public:
        ThreadPool(PoolType type, size_t threadCount);
        ~ThreadPool();

        void Start();
        void Stop();
        void AddTask(const std::wstring& filename);
        size_t GetPendingCount();

    private:
        void Worker(); 

        PoolType poolType;
        std::vector<std::thread> threads;
        std::queue<Task> tasks;

        std::mutex mtx;
        std::condition_variable cv;
        bool stopFlag = false;
    };

    class PoolManager {
    public:
        void CreatePools(size_t localCount, size_t networkCount, size_t backupCount);
        void AddTask(PoolType pool, const std::wstring& filename);
        void WaitAll();
        void StopAll();

    private:
        ThreadPool* localPool = nullptr;
        ThreadPool* networkPool = nullptr;
        ThreadPool* backupPool = nullptr;
    };

} 
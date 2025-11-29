#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <set>
#include <sys/types.h>

namespace core {

class TargetProcess;

enum class WatchType {
    Writes,
    Accesses
};

struct WatchHit {
    uint64_t count{0};
    std::string bytes;
    std::string opcode;
    WatchType type{WatchType::Writes};
    std::string access;
};

class DebugWatchSession {
public:
    DebugWatchSession(TargetProcess &proc, uintptr_t address, WatchType type, size_t lenBytes = 4);
    ~DebugWatchSession();

    void start();
    void stop();
    bool isRunning() const { return running_.load(); }

    uintptr_t address() const { return address_; }
    WatchType type() const { return type_; }
    const TargetProcess &proc() const { return proc_; }
    TargetProcess &proc() { return proc_; }
    size_t length() const { return len_; }

    std::vector<std::pair<uint64_t, WatchHit>> snapshot() const;

private:
    TargetProcess &proc_;
    uintptr_t address_{0};
    WatchType type_;
    size_t len_{4};

    mutable std::mutex mutex_;
    std::map<uint64_t, WatchHit> hits_;

    std::thread thread_;
    std::atomic<bool> running_{false};

    // External watcher process (ce_watch) we delegate to.
    pid_t childPid_{-1};
    int childFd_{-1};
    int childCmdFd_{-1};
    int childRespFd_{-1};
    std::mutex commandMutex_;

    void loop();
    void parseLine(const std::string &line);
    void clearHardwareWatchpointsFallback();
    bool sendWriteCommand(uintptr_t address, const uint8_t *data, size_t len);

public:
    static bool writeViaWatcher(pid_t pid, uintptr_t address, const uint8_t *data, size_t len);
};

} // namespace core

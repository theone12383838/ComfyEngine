#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include <sys/types.h>

#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

enum class WatchMode {
    Write,
    Access
};

class Watcher {
public:
    Watcher(pid_t pid, uintptr_t address, WatchMode mode, size_t length, int commandFd = -1, int responseFd = -1);
    ~Watcher();

    int run();
    void requestStop();

private:
    pid_t pid_{-1};
    uintptr_t address_{0};
    uintptr_t alignedAddress_{0};
    size_t length_{4};
    WatchMode mode_{WatchMode::Write};
    int memFd_{-1};
    std::set<pid_t> tids_;
    std::atomic<bool> running_{false};
    bool attached_{false};
    int commandFd_{-1};
    int responseFd_{-1};
    std::string commandBuffer_;

#ifdef HAVE_CAPSTONE
    csh capstoneHandle_{0};
    bool capstoneReady_{false};
#endif

    bool attachToProcess();
    bool openMem();
    bool enumerateThreads(std::vector<pid_t> &out) const;
    bool armThreads();
    bool armThread(pid_t tid);
    bool waitForStop(pid_t tid, int &status) const;
    void eventLoop();
    void handleTrap(pid_t tid);
    void refreshThreads();
    void cleanup();
    void disarmThread(pid_t tid);
    bool handleCommands();
    bool handleCommand(const std::string &line);
    bool writeBytes(uintptr_t address, const std::vector<uint8_t> &bytes);
    void sendResponse(const std::string &msg);
    static uintptr_t alignAddress(uintptr_t addr, size_t len);
    static unsigned long lengthBits(size_t len);
    std::string formatBytes(const uint8_t *buf, size_t len) const;
    void logf(const char *fmt, ...) const;
};

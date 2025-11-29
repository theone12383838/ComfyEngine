#include "Watcher.h"

#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

namespace {

void printUsage(const char *prog) {
    std::cerr << "Usage: " << prog << " <pid> <address> <mode> [len]\n"
              << "  <pid>     integer process id\n"
              << "  <address> hex address (e.g. 0x7ffdeadbeef)\n"
              << "  <mode>    write | access\n"
              << "  <len>     1 | 2 | 4 | 8 (default 4)\n";
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        printUsage(argv[0]);
        return 1;
    }

    char *end = nullptr;
    long pidLong = std::strtol(argv[1], &end, 10);
    if (!end || *end != '\0' || pidLong <= 0) {
        std::cerr << "Invalid pid\n";
        return 1;
    }
    pid_t pid = static_cast<pid_t>(pidLong);

    end = nullptr;
    unsigned long long addrVal = std::strtoull(argv[2], &end, 0);
    if (!end || *end != '\0') {
        std::cerr << "Invalid address\n";
        return 1;
    }
    uintptr_t address = static_cast<uintptr_t>(addrVal);

    std::string modeStr = argv[3];
    WatchMode mode;
    if (modeStr == "write") {
        mode = WatchMode::Write;
    } else if (modeStr == "access") {
        mode = WatchMode::Access;
    } else {
        std::cerr << "Mode must be \"write\" or \"access\"\n";
        return 1;
    }

    size_t len = 4;
    if (argc == 5) {
        end = nullptr;
        unsigned long l = std::strtoul(argv[4], &end, 10);
        if (!end || *end != '\0') {
            std::cerr << "Invalid length\n";
            return 1;
        }
        len = static_cast<size_t>(l);
        if (!(len == 1 || len == 2 || len == 4 || len == 8)) {
            std::cerr << "Length must be 1, 2, 4, or 8\n";
            return 1;
        }
    }

    int cmdFd = -1;
    int respFd = -1;
    if (const char *cmdEnv = std::getenv("COMFYENGINE_WATCH_CMD_FD")) {
        cmdFd = std::atoi(cmdEnv);
    }
    if (const char *respEnv = std::getenv("COMFYENGINE_WATCH_RESP_FD")) {
        respFd = std::atoi(respEnv);
    }

    Watcher watcher(pid, address, mode, len, cmdFd, respFd);
    return watcher.run();
}

#pragma once

#include <string>
#include <vector>
#include <sys/types.h>

namespace core {

struct ProcessInfo {
    pid_t pid;
    std::string name;
    std::string cmdline;
};

class ProcessEnumerator {
public:
    static std::vector<ProcessInfo> list();
};

} // namespace core

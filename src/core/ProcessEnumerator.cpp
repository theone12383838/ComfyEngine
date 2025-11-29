#include "core/ProcessEnumerator.h"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <charconv>

namespace fs = std::filesystem;

namespace core {

namespace {
std::string read_first_line(const fs::path &p) {
    std::ifstream f(p);
    std::string line;
    if (f.good()) {
        std::getline(f, line);
    }
    return line;
}

std::string read_cmdline(const fs::path &p) {
    std::ifstream f(p, std::ios::in | std::ios::binary);
    if (!f.good()) return {};
    std::string buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (char &c : buf) {
        if (c == '\0') c = ' ';
    }
    return buf;
}

bool to_pid(const std::string &s, pid_t &pid) {
    auto *begin = s.data();
    auto *end = s.data() + s.size();
    int value = 0;
    auto res = std::from_chars(begin, end, value);
    if (res.ec != std::errc() || res.ptr != end) return false;
    pid = static_cast<pid_t>(value);
    return true;
}
} // namespace

std::vector<ProcessInfo> ProcessEnumerator::list() {
    std::vector<ProcessInfo> result;
    for (const auto &entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        pid_t pid;
        if (!to_pid(entry.path().filename().string(), pid)) continue;
        fs::path base = entry.path();
        std::string name = read_first_line(base / "comm");
        if (name.empty()) name = base.filename().string();
        std::string cmd = read_cmdline(base / "cmdline");
        result.push_back(ProcessInfo{pid, name, cmd});
    }
    std::sort(result.begin(), result.end(), [](const ProcessInfo &a, const ProcessInfo &b) {
        return a.pid < b.pid;
    });
    return result;
}

} // namespace core

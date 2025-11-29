#include "core/TargetProcess.h"
#include "core/DebugWatch.h"

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <string>

namespace {
class PtraceGuard {
public:
    explicit PtraceGuard(pid_t pid) : pid_(pid) {
        if (pid_ <= 0) return;
        if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) {
            return;
        }
        int status = 0;
        if (waitpid(pid_, &status, __WALL) == -1) {
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            return;
        }
        attached_ = true;
    }
    ~PtraceGuard() {
        if (attached_) {
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        }
    }
    bool ok() const { return attached_; }

private:
    pid_t pid_{-1};
    bool attached_{false};
};
} // namespace

namespace core {

TargetProcess::TargetProcess() = default;

TargetProcess::~TargetProcess() {
    detach();
}

bool TargetProcess::attach(pid_t pid) {
    lastError_.clear();
    if (attached_ && pid_ == pid) return true;
    if (attached_) detach();
    pid_ = pid;
    return attach();
}

bool TargetProcess::attach() {
    lastError_.clear();
    if (attached_) return true;
    if (pid_ <= 0) {
        lastError_ = "invalid pid";
        return false;
    }
    // With ptrace_scope=0 we can read/write using process_vm_* without
    // taking a global ptrace attachment. Keep this lightweight here;
    // debug features that need ptrace (like hardware watchpoints) manage
    // their own attachments.
    attached_ = true;
    return true;
}

void TargetProcess::detach() {
    if (!attached_) return;
    attached_ = false;
    pid_ = -1;
    lastError_.clear();
}

std::vector<MemoryRegion> TargetProcess::regions() const {
    std::vector<MemoryRegion> out;
    if (!attached_) return out;
    std::stringstream path;
    path << "/proc/" << pid_ << "/maps";
    std::ifstream f(path.str());
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string range, perms, offset, dev, inode, pathName;
        if (!(iss >> range >> perms >> offset >> dev >> inode)) continue;
        std::getline(iss, pathName);
        if (!pathName.empty() && pathName[0] == ' ') pathName.erase(0, 1);
        auto dash = range.find('-');
        if (dash == std::string::npos) continue;
        uintptr_t start = std::stoull(range.substr(0, dash), nullptr, 16);
        uintptr_t end = std::stoull(range.substr(dash + 1), nullptr, 16);
        out.push_back(MemoryRegion{start, end, perms, pathName});
    }
    return out;
}

std::vector<pid_t> TargetProcess::listThreads() const {
    std::vector<pid_t> tids;
    if (!attached_) return tids;
    std::string taskDir = "/proc/" + std::to_string(pid_) + "/task";
    if (DIR *dir = opendir(taskDir.c_str())) {
        while (auto *ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = static_cast<pid_t>(std::strtol(ent->d_name, nullptr, 10));
            if (tid > 0) tids.push_back(tid);
        }
        closedir(dir);
    }
    return tids;
}

bool TargetProcess::readMemory(uintptr_t address, void *buffer, size_t len) const {
    if (!attached_) return false;
    struct iovec local{buffer, len};
    struct iovec remote{reinterpret_cast<void *>(address), len};
    ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;
    // Fallback to ptrace for small reads
    PtraceGuard guard(pid_);
    if (!guard.ok()) return false;
    size_t readBytes = 0;
    long word = 0;
    unsigned char *buf = static_cast<unsigned char *>(buffer);
    errno = 0;
    while (readBytes < len) {
        word = ptrace(PTRACE_PEEKDATA, pid_, address + readBytes, nullptr);
        if (word == -1 && errno) return false;
        size_t copy = std::min(sizeof(long), len - readBytes);
        std::memcpy(buf + readBytes, &word, copy);
        readBytes += copy;
    }
    return true;
}

bool TargetProcess::writeMemory(uintptr_t address, const void *buffer, size_t len) const {
    if (!attached_) return false;
    struct iovec local{const_cast<void *>(buffer), len};
    struct iovec remote{reinterpret_cast<void *>(address), len};
    ssize_t n = process_vm_writev(pid_, &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(len)) return true;
    // Fallback to ptrace for small writes
    PtraceGuard guard(pid_);
    if (!guard.ok()) {
        if (DebugWatchSession::writeViaWatcher(pid_, address,
                                               static_cast<const uint8_t *>(buffer), len)) {
            return true;
        }
        return false;
    }
    size_t written = 0;
    const unsigned char *buf = static_cast<const unsigned char *>(buffer);
    while (written < len) {
        long word = 0;
        size_t copy = std::min(sizeof(long), len - written);
        std::memcpy(&word, buf + written, copy);
        if (ptrace(PTRACE_POKEDATA, pid_, address + written, word) == -1) {
            return false;
        }
        written += copy;
    }
    return true;
}

} // namespace core

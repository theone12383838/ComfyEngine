#include "Watcher.h"

#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <sstream>
#include <string>
#include <vector>
#include <thread>

namespace {
Watcher *gActiveWatcher = nullptr;

void onSignal(int) {
    if (gActiveWatcher) {
        gActiveWatcher->requestStop();
    }
}
} // namespace

Watcher::Watcher(pid_t pid, uintptr_t address, WatchMode mode, size_t length, int commandFd, int responseFd)
    : pid_(pid), address_(address), length_(length), mode_(mode),
      commandFd_(commandFd), responseFd_(responseFd) {
    if (length_ != 1 && length_ != 2 && length_ != 4 && length_ != 8) {
        length_ = 4;
    }
    alignedAddress_ = alignAddress(address_, length_);
    if (commandFd_ >= 0) {
        fcntl(commandFd_, F_SETFL, O_NONBLOCK);
    }
}

Watcher::~Watcher() {
    requestStop();
    cleanup();
}

int Watcher::run() {
    running_.store(true);
    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    gActiveWatcher = this;

    if (!attachToProcess()) {
        cleanup();
        gActiveWatcher = nullptr;
        return 1;
    }
    if (!openMem()) {
        cleanup();
        gActiveWatcher = nullptr;
        return 1;
    }

#ifdef HAVE_CAPSTONE
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle_) == CS_ERR_OK) {
        capstoneReady_ = true;
        cs_option(capstoneHandle_, CS_OPT_DETAIL, CS_OPT_OFF);
    }
#endif

    if (!armThreads()) {
        cleanup();
        gActiveWatcher = nullptr;
        return 1;
    }

    logf("watching pid %d addr=0x%lx len=%zu mode=%s",
         pid_,
         static_cast<unsigned long>(alignedAddress_),
         length_,
         mode_ == WatchMode::Write ? "write" : "access");

    eventLoop();
    cleanup();
    gActiveWatcher = nullptr;
    return 0;
}

void Watcher::requestStop() {
    running_.store(false);
    for (pid_t tid : tids_) {
        ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);
    }
}

bool Watcher::attachToProcess() {
    if (pid_ <= 0) {
        logf("invalid pid");
        return false;
    }

    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) {
        logf("PTRACE_ATTACH failed: %s", std::strerror(errno));
        return false;
    }

    int status = 0;
    if (waitpid(pid_, &status, __WALL) == -1) {
        logf("waitpid after attach failed: %s", std::strerror(errno));
        return false;
    }
    if (!WIFSTOPPED(status)) {
        logf("tracee did not stop after attach");
        return false;
    }

    attached_ = true;
    return true;
}

bool Watcher::openMem() {
    std::string path = "/proc/" + std::to_string(pid_) + "/mem";
    memFd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (memFd_ == -1) {
        logf("failed to open %s: %s", path.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

bool Watcher::enumerateThreads(std::vector<pid_t> &out) const {
    std::string taskDir = "/proc/" + std::to_string(pid_) + "/task";
    if (DIR *dir = opendir(taskDir.c_str())) {
        while (dirent *ent = readdir(dir)) {
            if (!ent || ent->d_name[0] == '.') continue;
            char *end = nullptr;
            long tidVal = std::strtol(ent->d_name, &end, 10);
            if (end && *end == '\0' && tidVal > 0) {
                out.push_back(static_cast<pid_t>(tidVal));
            }
        }
        closedir(dir);
    } else {
        logf("failed to open %s: %s", taskDir.c_str(), std::strerror(errno));
        return false;
    }
    return !out.empty();
}

bool Watcher::armThreads() {
    std::vector<pid_t> threads;
    if (!enumerateThreads(threads)) {
        logf("no threads found to arm");
        return false;
    }

    size_t armed = 0;
    for (pid_t tid : threads) {
        if (tids_.count(tid)) continue;
        if (armThread(tid)) {
            tids_.insert(tid);
            armed++;
        }
    }

    if (armed == 0) {
        logf("failed to arm any thread");
        return false;
    }
    logf("armed %zu thread(s)", armed);
    return true;
}

bool Watcher::armThread(pid_t tid) {
    int status = 0;
    bool alreadyStopped = (tid == pid_ && attached_);

    if (tid != pid_) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1 && errno != EPERM) {
            logf("attach tid=%d failed: %s", tid, std::strerror(errno));
            return false;
        }
    } else {
        // tid == main pid; we are already attached and in a stopped state after the initial waitpid.
        alreadyStopped = true;
    }

    if (!alreadyStopped) {
        // Interrupt the thread so we can safely modify debug registers.
        ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);

        if (!waitForStop(tid, status)) {
            logf("tid=%d did not stop", tid);
            return false;
        }

        if (!WIFSTOPPED(status)) {
            logf("tid=%d not in stopped state", tid);
            return false;
        }
    }

    // Program DR0
    if (ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg[0]),
               alignedAddress_) == -1) {
        logf("poke DR0 tid=%d failed: %s", tid, std::strerror(errno));
        return false;
    }

    // Build DR7 from scratch to avoid inheriting unknown bits.
    unsigned long dr7 = 0;
    unsigned long rw = (mode_ == WatchMode::Write) ? 0b01UL : 0b11UL;
    unsigned long lenBits = lengthBits(length_);

    dr7 |= 1UL << 0;        // L0 enable
    dr7 |= (rw << 16);      // RW0
    dr7 |= (lenBits << 18); // LEN0

    if (ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg[7]),
               dr7) == -1) {
        logf("poke DR7 tid=%d failed: %s", tid, std::strerror(errno));
        return false;
    }

    // Clear DR6
    ptrace(PTRACE_POKEUSER, tid,
           offsetof(struct user, u_debugreg[6]),
           0);

    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        logf("continue tid=%d failed: %s", tid, std::strerror(errno));
        return false;
    }

    logf("armed tid=%d DR0=0x%lx DR7=0x%lx",
         tid,
         static_cast<unsigned long>(alignedAddress_),
         dr7);
    return true;
}

bool Watcher::waitForStop(pid_t tid, int &status) const {
    for (;;) {
        pid_t w = waitpid(tid, &status, __WALL);
        if (w == -1) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (w == tid)
            return true;
    }
}

void Watcher::eventLoop() {
    while (running_.load() && !tids_.empty()) {
        bool handledCmd = handleCommands();
        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid == 0) {
            if (!handledCmd)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        if (tid == -1) {
            if (errno == EINTR) {
                if (!running_.load()) break;
                continue;
            }
            logf("waitpid failed: %s", std::strerror(errno));
            break;
        }

        if (tids_.find(tid) == tids_.end()) {
            if (WIFSTOPPED(status)) {
                ptrace(PTRACE_CONT, tid, nullptr, WSTOPSIG(status));
            }
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            logf("tid=%d exited", tid);
            tids_.erase(tid);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            continue;
        }

        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP) {
            handleTrap(tid);
        } else {
            ptrace(PTRACE_CONT, tid, nullptr, sig);
        }

        refreshThreads();
    }
}

void Watcher::handleTrap(pid_t tid) {
    errno = 0;
    unsigned long dr6 = ptrace(PTRACE_PEEKUSER, tid,
                               offsetof(struct user, u_debugreg[6]),
                               nullptr);
    bool dr6Ok = !(dr6 == static_cast<unsigned long>(-1) && errno);

    // Clear DR6 to avoid stale statuses.
    ptrace(PTRACE_POKEUSER, tid,
           offsetof(struct user, u_debugreg[6]),
           0);

    struct user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
    }

    uint64_t rip = regs.rip;
    uint8_t buf[16]{};
    ssize_t n = pread(memFd_, buf, sizeof(buf), static_cast<off_t>(rip));
    if (n < 0) n = 0;

    std::string bytesStr = formatBytes(buf, static_cast<size_t>(n));
    std::string asmStr;

#ifdef HAVE_CAPSTONE
    if (capstoneReady_ && n > 0) {
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(capstoneHandle_, buf, static_cast<size_t>(n), rip, 1, &insn);
        if (count > 0) {
            const cs_insn &ci = insn[0];
            asmStr = ci.mnemonic;
            if (ci.op_str && ci.op_str[0]) {
                asmStr += " ";
                asmStr += ci.op_str;
            }
            cs_free(insn, count);
        }
    }
#endif

    if (asmStr.empty()) {
        asmStr = bytesStr.empty() ? "(no bytes)" : bytesStr;
    }

    unsigned long dr6Masked = dr6Ok ? (dr6 & 0xfUL) : 0;

    std::fprintf(stdout,
                 "tid=%d rip=0x%llx dr6=%s bytes=%s inst=%s\n",
                 static_cast<int>(tid),
                 static_cast<unsigned long long>(rip),
                 dr6Ok ? ([dr6Masked]() {
                     static char buf[32];
                     std::snprintf(buf, sizeof(buf), "0x%lx", dr6Masked);
                     return buf;
                 }()) : "peek-failed",
                 bytesStr.c_str(),
                 asmStr.c_str());
    std::fflush(stdout);

    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
}

void Watcher::refreshThreads() {
    std::vector<pid_t> current;
    if (!enumerateThreads(current)) return;
    for (pid_t tid : current) {
        if (tids_.count(tid)) continue;
        if (armThread(tid)) {
            tids_.insert(tid);
        }
    }
}

void Watcher::cleanup() {
    running_.store(false);

    for (pid_t tid : std::vector<pid_t>(tids_.begin(), tids_.end())) {
        disarmThread(tid);
    }
    tids_.clear();

#ifdef HAVE_CAPSTONE
    if (capstoneReady_) {
        cs_close(&capstoneHandle_);
        capstoneReady_ = false;
    }
#endif

    if (memFd_ != -1) {
        close(memFd_);
        memFd_ = -1;
    }
}

void Watcher::disarmThread(pid_t tid) {
    int status = 0;
    ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);
    if (!waitForStop(tid, status)) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return;
    }

    unsigned long dr7 = 0; // disable L0, clear RW0/LEN0
    ptrace(PTRACE_POKEUSER, tid,
           offsetof(struct user, u_debugreg[7]),
           dr7);

    ptrace(PTRACE_POKEUSER, tid,
           offsetof(struct user, u_debugreg[0]),
           0);
    ptrace(PTRACE_POKEUSER, tid,
           offsetof(struct user, u_debugreg[6]),
           0);

    ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
}

uintptr_t Watcher::alignAddress(uintptr_t addr, size_t len) {
    switch (len) {
    case 2: return addr & ~uintptr_t(1);
    case 4: return addr & ~uintptr_t(3);
    case 8: return addr & ~uintptr_t(7);
    default: return addr;
    }
}

unsigned long Watcher::lengthBits(size_t len) {
    switch (len) {
    case 1: return 0b00UL;
    case 2: return 0b01UL;
    case 8: return 0b10UL;
    default: return 0b11UL; // 4 bytes
    }
}

std::string Watcher::formatBytes(const uint8_t *buf, size_t len) const {
    std::string out;
    char tmp[4];
    for (size_t i = 0; i < len; ++i) {
        std::snprintf(tmp, sizeof(tmp), "%02x", buf[i]);
        out += tmp;
        if (i + 1 < len) out += ' ';
    }
    return out;
}

void Watcher::logf(const char *fmt, ...) const {
    std::fprintf(stderr, "[ce_watch] ");
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
}

bool Watcher::handleCommands() {
    if (commandFd_ < 0) return false;
    bool processed = false;
    char buf[256];
    for (;;) {
        ssize_t n = ::read(commandFd_, buf, sizeof(buf));
        if (n > 0) {
            processed = true;
            commandBuffer_.append(buf, static_cast<size_t>(n));
            size_t pos = 0;
            while ((pos = commandBuffer_.find('\n')) != std::string::npos) {
                std::string line = commandBuffer_.substr(0, pos);
                commandBuffer_.erase(0, pos + 1);
                handleCommand(line);
            }
            continue;
        }
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (n == 0) {
            commandFd_ = -1;
            break;
        }
        break;
    }
    return processed;
}

bool Watcher::handleCommand(const std::string &line) {
    if (line.empty()) return false;
    std::istringstream iss(line);
    std::string command;
    iss >> command;
    if (command == "WRITE") {
        std::string addrStr;
        if (!(iss >> addrStr)) {
            sendResponse("ERR missing-addr");
            return false;
        }
        uintptr_t addr = 0;
        try {
            addr = std::stoull(addrStr, nullptr, 16);
        } catch (...) {
            sendResponse("ERR invalid-addr");
            return false;
        }
        std::vector<uint8_t> bytes;
        std::string tok;
        while (iss >> tok) {
            try {
                bytes.push_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16) & 0xFF));
            } catch (...) {
                sendResponse("ERR invalid-byte");
                return false;
            }
        }
        if (bytes.empty()) {
            sendResponse("ERR empty");
            return false;
        }
        bool ok = writeBytes(addr, bytes);
        sendResponse(ok ? "OK" : "ERR write-failed");
        return ok;
    }
    sendResponse("ERR unknown");
    return false;
}

bool Watcher::writeBytes(uintptr_t address, const std::vector<uint8_t> &bytes) {
    if (pid_ <= 0) return false;
    if (ptrace(PTRACE_INTERRUPT, pid_, nullptr, nullptr) == -1)
        return false;
    int status = 0;
    if (waitpid(pid_, &status, __WALL) == -1)
        return false;

    bool ok = true;
    size_t offset = 0;
    while (offset < bytes.size()) {
        long word = 0;
        size_t chunk = std::min(sizeof(long), bytes.size() - offset);
        std::memcpy(&word, bytes.data() + offset, chunk);
        if (ptrace(PTRACE_POKEDATA, pid_, address + offset, word) == -1) {
            ok = false;
            break;
        }
        offset += chunk;
    }

    ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
    return ok;
}

void Watcher::sendResponse(const std::string &msg) {
    if (responseFd_ < 0) return;
    std::string line = msg;
    line.push_back('\n');
    ::write(responseFd_, line.c_str(), line.size());
}

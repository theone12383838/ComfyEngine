#include "core/CodeInjector.h"

#include <algorithm>

namespace core {

CodeInjector::CodeInjector(const TargetProcess &proc) : proc_(proc) {}

bool CodeInjector::patchBytes(uintptr_t address, const std::vector<uint8_t> &bytes) {
    if (!proc_.isAttached()) return false;
    PatchRecord rec{};
    rec.address = address;
    rec.patched = bytes;
    rec.original.resize(bytes.size());
    if (!proc_.readMemory(address, rec.original.data(), rec.original.size())) return false;
    if (!proc_.writeMemory(address, rec.patched.data(), rec.patched.size())) return false;
    patches_[address] = rec;
    return true;
}

bool CodeInjector::restore(uintptr_t address) {
    auto it = patches_.find(address);
    if (it == patches_.end()) return false;
    if (!proc_.writeMemory(address, it->second.original.data(), it->second.original.size())) return false;
    patches_.erase(it);
    return true;
}

} // namespace core

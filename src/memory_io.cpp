#include "memory_io.h"

#include <algorithm>

bool ReadRemoteBytes(HANDLE proc, std::uintptr_t addr, void* dst, std::size_t len) {
    SIZE_T n = 0;
    return ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), dst, len, &n) && n == len;
}

std::optional<std::uint32_t> ReadRemoteU32(HANDLE proc, std::uintptr_t addr) {
    std::uint32_t v = 0;
    if (!ReadRemoteBytes(proc, addr, &v, sizeof(v))) {
        return std::nullopt;
    }
    return v;
}

std::optional<std::uintptr_t> ReadRemotePointer(HANDLE proc, std::uintptr_t addr) {
#ifdef _WIN64
    std::uint64_t v = 0;
    if (!ReadRemoteBytes(proc, addr, &v, sizeof(v))) {
        return std::nullopt;
    }
    return static_cast<std::uintptr_t>(v);
#else
    std::uint32_t v = 0;
    if (!ReadRemoteBytes(proc, addr, &v, sizeof(v))) {
        return std::nullopt;
    }
    return static_cast<std::uintptr_t>(v);
#endif
}

std::optional<std::string> ReadRemoteString(HANDLE proc, std::uintptr_t addr, std::size_t max_len) {
    std::vector<char> buf(max_len + 1, '\0');
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf.data(),
                           static_cast<SIZE_T>(max_len), &read) ||
        read == 0) {
        return std::nullopt;
    }
    buf[std::min(read, static_cast<SIZE_T>(max_len))] = '\0';
    return std::string(buf.data());
}

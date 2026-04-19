#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <Windows.h>

bool ReadRemoteBytes(HANDLE proc, std::uintptr_t addr, void* dst, std::size_t len);

std::optional<std::uint32_t> ReadRemoteU32(HANDLE proc, std::uintptr_t addr);

std::optional<std::uintptr_t> ReadRemotePointer(HANDLE proc, std::uintptr_t addr);

// Reads a null-terminated string from the target (ASCII / UTF-8 subset).
std::optional<std::string> ReadRemoteString(HANDLE proc, std::uintptr_t addr,
                                            std::size_t max_len = 512);

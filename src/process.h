#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <Windows.h>

struct ModuleInfo {
    std::wstring name;
    std::uintptr_t base = 0;
    std::size_t size = 0;
};

// Opens the process by name (e.g. L"hl2.exe" for TF2). Returns 0 on failure.
DWORD FindProcessIdByName(const std::wstring& process_name);

// Lists native modules (32- or 64-bit matching this build) for an open process handle.
std::vector<ModuleInfo> EnumerateModules(HANDLE process);

// Finds module by file name (case-insensitive), e.g. L"client.dll".
bool FindModule(const std::vector<ModuleInfo>& modules, const std::wstring& module_name,
                ModuleInfo* out);

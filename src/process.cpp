#include "process.h"

#include <TlHelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>

DWORD FindProcessIdByName(const std::wstring& process_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        if (_wcsicmp(pe.szExeFile, process_name.c_str()) == 0) {
            CloseHandle(snap);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return 0;
}

std::vector<ModuleInfo> EnumerateModules(HANDLE proc) {
    std::vector<ModuleInfo> out;
    if (!proc || proc == INVALID_HANDLE_VALUE) {
        return out;
    }

    HMODULE mods[2048]{};
    DWORD needed = 0;
#ifdef _WIN64
    constexpr DWORD kFilter = LIST_MODULES_64BIT;
#else
    constexpr DWORD kFilter = LIST_MODULES_32BIT;
#endif
    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, kFilter)) {
        return out;
    }

    const unsigned count = needed / static_cast<unsigned>(sizeof(HMODULE));
    for (unsigned i = 0; i < count && i < 2048; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) {
            continue;
        }
        wchar_t name[MAX_PATH]{};
        if (!GetModuleBaseNameW(proc, mods[i], name, MAX_PATH)) {
            continue;
        }
        ModuleInfo info;
        info.name = name;
        info.base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        info.size = mi.SizeOfImage;
        out.push_back(std::move(info));
    }
    return out;
}

bool FindModule(const std::vector<ModuleInfo>& modules, const std::wstring& module_name,
                ModuleInfo* out) {
    for (const auto& m : modules) {
        if (_wcsicmp(m.name.c_str(), module_name.c_str()) == 0) {
            if (out) {
                *out = m;
            }
            return true;
        }
    }
    return false;
}

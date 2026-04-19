#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <Windows.h>

#include "memory_io.h"
#include "netvar_dump.h"
#include "pattern.h"
#include "process.h"

namespace {

std::string WideToUtf8(std::wstring_view w) {
    if (w.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr,
                                         0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), size, nullptr,
                        nullptr);
    return out;
}

bool ReadRemoteRegion(HANDLE proc, std::uintptr_t base, std::size_t size,
                      std::vector<std::uint8_t>* out) {
    out->resize(size);
    SIZE_T read = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(base), out->data(), size, &read)) {
        return false;
    }
    out->resize(read);
    return read == size;
}

std::optional<std::uintptr_t> ParseHexUintPtr(std::wstring_view s) {
    if (s.empty()) {
        return std::nullopt;
    }
    if (s.size() > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
    if (s.empty()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (wchar_t c : s) {
        int digit = -1;
        if (c >= L'0' && c <= L'9') {
            digit = static_cast<int>(c - L'0');
        } else if (c >= L'a' && c <= L'f') {
            digit = 10 + static_cast<int>(c - L'a');
        } else if (c >= L'A' && c <= L'F') {
            digit = 10 + static_cast<int>(c - L'A');
        } else {
            return std::nullopt;
        }
        v = (v << 4) | static_cast<std::uint64_t>(digit);
#ifndef _WIN64
        if (v > 0xFFFFFFFFull) {
            return std::nullopt;
        }
#endif
    }
    return static_cast<std::uintptr_t>(v);
}

void PrintUsage() {
    std::wcout
        << L"Usage:\n"
        << L"  tf2_dumper.exe [process.exe] [--head 0x<ClientClass*>] [--out <file>] [--pattern <ida>]\n"
        << L"\n"
        << L"Dumps networked netvars (RecvTable/RecvProp) for every ClientClass.\n"
#ifdef _WIN64
        << L"Build: x64 — use with 64-bit TF2 (e.g. tf_win64.exe).\n"
#else
        << L"Build: Win32 — use with 32-bit TF2 (hl2.exe).\n"
#endif
        << L"\n"
        << L"  --head     Manual ClientClass* instead of auto-scan.\n"
        << L"  --pattern  Scan first 16MiB of client.dll; then exit.\n";
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    std::wstring process_name = L"hl2.exe";
    std::wstring out_path;
    std::optional<std::uintptr_t> manual_head;
    std::wstring pattern_wide;

    for (int i = 1; i < argc; ++i) {
        std::wstring_view a = argv[i];
        if (a == L"--head" && i + 1 < argc) {
            if (const auto p = ParseHexUintPtr(argv[i + 1])) {
                manual_head = *p;
            } else {
                std::wcerr << L"Bad --head value.\n";
                return 2;
            }
            ++i;
            continue;
        }
        if (a == L"--out" && i + 1 < argc) {
            out_path = argv[i + 1];
            ++i;
            continue;
        }
        if (a == L"--pattern" && i + 1 < argc) {
            pattern_wide = argv[i + 1];
            ++i;
            continue;
        }
        if (a == L"-h" || a == L"--help") {
            PrintUsage();
            return 0;
        }
        if (a[0] == L'-') {
            std::wcerr << L"Unknown option.\n";
            PrintUsage();
            return 2;
        }
        process_name = std::wstring(a);
    }

    const DWORD pid = FindProcessIdByName(process_name);
    if (!pid) {
        std::wcerr << L"Process not found: " << process_name << L"\n";
        return 1;
    }

    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) {
        std::wcerr << L"OpenProcess failed. Try running as Administrator. Error: " << GetLastError()
                   << L"\n";
        return 1;
    }

    const std::vector<ModuleInfo> modules = EnumerateModules(proc);
    ModuleInfo client{};
    if (!FindModule(modules, L"client.dll", &client)) {
        std::wcerr << L"client.dll not loaded.\n";
        CloseHandle(proc);
        return 1;
    }

    std::wcout << L"PID: " << pid << L"\n";
    std::wcout << L"client.dll: base=0x" << std::hex << client.base << L" size=0x" << client.size
               << std::dec << L"\n";

    std::ostream* out = &std::cout;
    std::ofstream file;
    const bool dump_to_file = !out_path.empty();
    if (dump_to_file) {
        file.open(out_path, std::ios::out | std::ios::trunc);
        if (!file) {
            std::wcerr << L"Failed to open output file.\n";
            CloseHandle(proc);
            return 1;
        }
        out = &file;
        std::wcout << L"Netvar text goes to this file (console only shows status): " << out_path
                   << L"\n";
    }

    if (!pattern_wide.empty()) {
        const std::string pattern = WideToUtf8(pattern_wide);
        constexpr std::size_t kMaxRead = 16 * 1024 * 1024;
        const std::size_t read_size = (client.size > kMaxRead) ? kMaxRead : client.size;
        std::vector<std::uint8_t> buf;
        if (!ReadRemoteRegion(proc, client.base, read_size, &buf)) {
            std::wcerr << L"ReadProcessMemory failed. Error: " << GetLastError() << L"\n";
            CloseHandle(proc);
            return 1;
        }
        if (const auto off = PatternScan(buf, pattern)) {
            const std::uintptr_t addr = client.base + *off;
            *out << "Pattern hit client.dll+0x" << std::hex << *off << " -> 0x" << addr << std::dec
                 << "\n";
        } else {
            *out << "Pattern not found in scanned region.\n";
        }
        CloseHandle(proc);
        return 0;
    }

    std::uintptr_t head = 0;
    if (manual_head) {
        head = *manual_head;
        *out << "// Using manual ClientClass* head = 0x" << std::hex << head << std::dec << "\n";
    } else {
        std::wcout << L"Scanning client.dll for ClientClass list (can take a while)...\n"
                   << std::flush;
        head = FindClientClassHead(proc, client.base, client.size);
        if (!head) {
            std::wcerr << L"Could not locate ClientClass list head. Pass --head 0x....\n";
            CloseHandle(proc);
            return 1;
        }
        *out << "// ClientClass* head (auto) = 0x" << std::hex << head << std::dec << "\n";
    }

    if (dump_to_file) {
        std::wcout << L"Dumping netvars...\n" << std::flush;
    }
    DumpAllNetvars(proc, client.base, client.size, head, *out);

    if (dump_to_file) {
        std::wcout << L"Done. Full dump is in: " << out_path << L"\n";
    }

    CloseHandle(proc);
    return 0;
}

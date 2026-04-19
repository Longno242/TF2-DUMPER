#include "pe_util.h"

#include <Windows.h>

#include <cstring>

#include "memory_io.h"

namespace {

#pragma pack(push, 1)
struct DosHeader {
    std::uint16_t e_magic;
    std::uint8_t e_cblp[58];
    std::int32_t e_lfanew;
};
#pragma pack(pop)

}  // namespace

bool ReadPeSections(HANDLE proc, std::uintptr_t module_base, std::vector<PeSection>* out) {
    out->clear();

    DosHeader dos{};
    if (!ReadRemoteBytes(proc, module_base, &dos, sizeof(dos))) {
        return false;
    }
    if (dos.e_magic != 0x5A4D) {  // MZ
        return false;
    }

    const std::uintptr_t nt = module_base + static_cast<std::uintptr_t>(dos.e_lfanew);
    std::uint32_t sig = 0;
    if (!ReadRemoteBytes(proc, nt, &sig, sizeof(sig)) || sig != 0x00004550) {  // PE\0\0
        return false;
    }

    const std::uintptr_t file_header = nt + 4;

    std::uint16_t machine = 0;
    if (!ReadRemoteBytes(proc, file_header, &machine, sizeof(machine))) {
        return false;
    }
#ifdef _WIN64
    if (machine != 0x8664) {  // AMD64 — tf_win64 / 64-bit client.dll
        return false;
    }
#else
    if (machine != 0x014c) {  // I386 — hl2.exe 32-bit
        return false;
    }
#endif

    std::uint16_t num_sections = 0;
    if (!ReadRemoteBytes(proc, file_header + 2, &num_sections, sizeof(num_sections))) {
        return false;
    }

    std::uint16_t opt_size = 0;
    if (!ReadRemoteBytes(proc, file_header + 16, &opt_size, sizeof(opt_size))) {
        return false;
    }

    const std::uintptr_t first_section =
        file_header + 20 + static_cast<std::uintptr_t>(opt_size);

    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::uintptr_t sh = first_section + static_cast<std::uintptr_t>(i) * 40;
        char name[9]{};
        std::uint32_t virt_size = 0;
        std::uint32_t virt_addr = 0;
        std::uint32_t chars = 0;
        if (!ReadRemoteBytes(proc, sh, name, 8) ||
            !ReadRemoteBytes(proc, sh + 8, &virt_size, sizeof(virt_size)) ||
            !ReadRemoteBytes(proc, sh + 12, &virt_addr, sizeof(virt_addr)) ||
            !ReadRemoteBytes(proc, sh + 36, &chars, sizeof(chars))) {
            return false;
        }
        PeSection sec;
        sec.name = name;
        sec.virtual_address = virt_addr;
        sec.virtual_size = virt_size;
        sec.characteristics = chars;
        out->push_back(std::move(sec));
    }
    return true;
}

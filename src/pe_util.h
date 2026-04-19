#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <Windows.h>

struct PeSection {
    std::string name;
    std::uintptr_t virtual_address = 0;  // RVA
    std::uint32_t virtual_size = 0;
    std::uint32_t characteristics = 0;
};

// Reads PE headers from the remote module base and returns section table.
bool ReadPeSections(HANDLE proc, std::uintptr_t module_base, std::vector<PeSection>* out);

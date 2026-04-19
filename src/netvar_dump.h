#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>

#include <Windows.h>

// Locates g_pClientClassHead by scanning PE data sections for a plausible ClientClass list.
// Returns 0 on failure.
std::uintptr_t FindClientClassHead(HANDLE proc, std::uintptr_t module_base, std::size_t module_size);

// Dumps flattened netvar paths with cumulative offsets (entity-relative) for every ClientClass.
void DumpAllNetvars(HANDLE proc, std::uintptr_t module_base, std::size_t module_size,
                    std::uintptr_t client_class_head, std::ostream& out);

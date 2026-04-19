#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// IDA-style pattern: "48 8B 05 ? ? ? ? 48 85 C0" — '?' are wildcards.
std::optional<std::uintptr_t> PatternScan(const std::vector<std::uint8_t>& haystack,
                                          const std::string& ida_pattern);

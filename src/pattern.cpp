#include "pattern.h"

#include <cstdlib>
#include <sstream>

namespace {

bool ParseByte(const std::string& tok, std::uint8_t* out, bool* is_wildcard) {
    if (tok == "?" || tok == "??") {
        *is_wildcard = true;
        return true;
    }
    *is_wildcard = false;
    if (tok.size() != 2) {
        return false;
    }
    char* end = nullptr;
    unsigned long v = std::strtoul(tok.c_str(), &end, 16);
    if (end != tok.c_str() + 2 || v > 0xFF) {
        return false;
    }
    *out = static_cast<std::uint8_t>(v);
    return true;
}

bool ParsePattern(const std::string& ida_pattern, std::vector<std::uint8_t>* bytes,
                  std::vector<bool>* mask) {
    std::istringstream iss(ida_pattern);
    std::string tok;
    while (iss >> tok) {
        std::uint8_t b = 0;
        bool wild = false;
        if (!ParseByte(tok, &b, &wild)) {
            return false;
        }
        bytes->push_back(b);
        mask->push_back(wild);
    }
    return !bytes->empty();
}

}  // namespace

std::optional<std::uintptr_t> PatternScan(const std::vector<std::uint8_t>& haystack,
                                          const std::string& ida_pattern) {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> mask;
    if (!ParsePattern(ida_pattern, &bytes, &mask)) {
        return std::nullopt;
    }

    const std::size_t n = bytes.size();
    if (haystack.size() < n) {
        return std::nullopt;
    }

    for (std::size_t i = 0; i + n <= haystack.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < n; ++j) {
            if (!mask[j] && haystack[i + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return static_cast<std::uintptr_t>(i);
        }
    }
    return std::nullopt;
}

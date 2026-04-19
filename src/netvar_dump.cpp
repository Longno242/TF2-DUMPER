#include "netvar_dump.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ios>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "memory_io.h"
#include "pe_util.h"
#include "source_layout.h"

namespace {

namespace sl = SourceLayout;

constexpr int kDptArray = 5;
constexpr int kDptDataTable = 6;

bool InModule(std::uintptr_t p, std::uintptr_t base, std::size_t size) {
    return p >= base && p < base + size;
}

bool IsAlphaNumUnderscore(std::string_view s) {
    for (unsigned char c : s) {
        if (!(std::isalnum(c) != 0 || c == '_')) {
            return false;
        }
    }
    return !s.empty();
}

std::optional<std::string> ReadName(HANDLE proc, std::uintptr_t addr) {
    auto s = ReadRemoteString(proc, addr, 256);
    if (!s || s->empty() || s->size() > 200) {
        return std::nullopt;
    }
    return s;
}

bool RecvTableLooksValid(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                         std::uintptr_t rt) {
    if (!InModule(rt, mod_base, mod_size)) {
        return false;
    }
    const auto n = ReadRemoteU32(proc, rt + sl::kRtNumProps);
    if (!n || *n == 0 || *n > 4096) {
        return false;
    }
    const auto props = ReadRemotePointer(proc, rt + sl::kRtProps);
    if (!props || !InModule(*props, mod_base, mod_size)) {
        return false;
    }
    const auto nn = ReadRemotePointer(proc, rt + sl::kRtNetTableName);
    if (!nn) {
        return false;
    }
    const auto name = ReadName(proc, *nn);
    if (!name || name->size() < 4) {
        return false;
    }
    return name->compare(0, 3, "DT_") == 0;
}

bool ClientClassLooksValid(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                           std::uintptr_t cc) {
    if (!InModule(cc, mod_base, mod_size)) {
        return false;
    }
    const auto nn = ReadRemotePointer(proc, cc + sl::kCcNetworkName);
    if (!nn || !InModule(*nn, mod_base, mod_size)) {
        return false;
    }
    const auto net = ReadName(proc, *nn);
    if (!net || !IsAlphaNumUnderscore(*net)) {
        return false;
    }
    const auto rt = ReadRemotePointer(proc, cc + sl::kCcRecvTable);
    if (!rt) {
        return false;
    }
    return RecvTableLooksValid(proc, mod_base, mod_size, *rt);
}

int CountClientClassChain(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                          std::uintptr_t head) {
    int count = 0;
    std::uintptr_t cur = head;
    std::unordered_set<std::uintptr_t> seen;
    while (cur && count < 4096) {
        if (seen.count(cur)) {
            return 0;
        }
        seen.insert(cur);
        if (!ClientClassLooksValid(proc, mod_base, mod_size, cur)) {
            return 0;
        }
        ++count;
        const auto next = ReadRemotePointer(proc, cur + sl::kCcNext);
        if (!next || *next == 0) {
            break;
        }
        cur = *next;
    }
    return count;
}

std::optional<int> ReadRecvPropInt(HANDLE proc, std::uintptr_t prop, std::uintptr_t off) {
    const auto v = ReadRemoteU32(proc, prop + off);
    if (!v) {
        return std::nullopt;
    }
    return static_cast<int>(*v);
}

std::optional<std::uintptr_t> ReadRecvPropPtr(HANDLE proc, std::uintptr_t prop, std::uintptr_t off) {
    return ReadRemotePointer(proc, prop + off);
}

void DumpRecvProp(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                  std::uintptr_t prop_addr, int accum_offset, const std::string& path,
                  std::ostream& out, int depth, bool inside_array);

void DumpRecvTable(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                   std::uintptr_t table_addr, int accum_offset, const std::string& path,
                   std::ostream& out, int depth) {
    if (depth > 128) {
        return;
    }
    if (!RecvTableLooksValid(proc, mod_base, mod_size, table_addr)) {
        return;
    }

    const auto n = ReadRemoteU32(proc, table_addr + sl::kRtNumProps);
    const auto props_ptr = ReadRemotePointer(proc, table_addr + sl::kRtProps);
    if (!n || !props_ptr) {
        return;
    }

    for (std::uint32_t i = 0; i < *n; ++i) {
        const std::uintptr_t prop_addr = *props_ptr + static_cast<std::uintptr_t>(i) * sl::kRecvPropBytes;
        if (!InModule(prop_addr, mod_base, mod_size)) {
            break;
        }
        DumpRecvProp(proc, mod_base, mod_size, prop_addr, accum_offset, path, out, depth, false);
    }
}

void DumpRecvProp(HANDLE proc, std::uintptr_t mod_base, std::size_t mod_size,
                  std::uintptr_t prop_addr, int accum_offset, const std::string& path,
                  std::ostream& out, int depth, bool inside_array) {
    if (depth > 128) {
        return;
    }

    const auto name_ptr = ReadRecvPropPtr(proc, prop_addr, sl::kRpVarName);
    const auto recv_type = ReadRecvPropInt(proc, prop_addr, sl::kRpRecvType);
    const auto offset = ReadRecvPropInt(proc, prop_addr, sl::kRpOffset);
    const auto data_table = ReadRecvPropPtr(proc, prop_addr, sl::kRpDataTable);
    const auto array_prop = ReadRecvPropPtr(proc, prop_addr, sl::kRpArrayProp);
    const auto n_elem = ReadRecvPropInt(proc, prop_addr, sl::kRpNumElements);
    const auto stride = ReadRecvPropInt(proc, prop_addr, sl::kRpElementStride);

    if (!name_ptr || !recv_type || !offset) {
        return;
    }

    std::string prop_name;
    if (const auto nm = ReadName(proc, *name_ptr)) {
        prop_name = *nm;
    } else {
        prop_name = "<bad_name>";
    }

    if (prop_name == "should_never_see_this") {
        return;
    }

    const std::string full_path = path.empty() ? prop_name : (path + "." + prop_name);

    const int type = *recv_type;
    const int off = *offset;

    if (type == kDptDataTable && data_table && *data_table) {
        if (!InModule(*data_table, mod_base, mod_size)) {
            return;
        }
        DumpRecvTable(proc, mod_base, mod_size, *data_table, accum_offset + off, full_path, out,
                      depth + 1);
        return;
    }

    if (type == kDptArray && array_prop && *array_prop && n_elem && stride) {
        const int count = *n_elem;
        const int elem_stride = *stride;
        if (count <= 0 || count > 2048 || elem_stride < 0 || elem_stride > 65536) {
            return;
        }
        const int cap = std::min(count, 512);
        for (int idx = 0; idx < cap; ++idx) {
            const std::uintptr_t inner = *array_prop;
            if (!InModule(inner, mod_base, mod_size)) {
                break;
            }
            const std::string indexed_path = full_path + "[" + std::to_string(idx) + "]";
            DumpRecvProp(proc, mod_base, mod_size, inner, accum_offset + off + idx * elem_stride,
                         indexed_path, out, depth + 1, true);
        }
        if (count > cap) {
            out << full_path << "[]"
                << " /* array truncated in dump: " << count << " elements, stride " << elem_stride
                << " */\n";
        }
        return;
    }

    const int total = accum_offset + off;
    out << full_path << " = 0x" << std::hex << total << std::dec;
    if (inside_array) {
        out << "  // array element";
    }
    out << '\n';
}

}  // namespace

std::uintptr_t FindClientClassHead(HANDLE proc, std::uintptr_t module_base,
                                   std::size_t module_size) {
    std::vector<PeSection> secs;
    if (!ReadPeSections(proc, module_base, &secs)) {
        return 0;
    }

    std::uintptr_t best_head = 0;
    int best_count = 0;

    for (const auto& sec : secs) {
        if (sec.name != ".data" && sec.name != ".rdata") {
            continue;
        }

        std::vector<std::uint8_t> buf;
        buf.resize(sec.virtual_size);
        const std::uintptr_t run = module_base + sec.virtual_address;
        if (!ReadRemoteBytes(proc, run, buf.data(), buf.size())) {
            continue;
        }

#ifdef _WIN64
        for (std::size_t i = 0; i + 8 <= buf.size(); i += 8) {
            std::uint64_t cand = 0;
            std::memcpy(&cand, buf.data() + i, sizeof(cand));
            const std::uintptr_t cc = static_cast<std::uintptr_t>(cand);
#else
        for (std::size_t i = 0; i + 4 <= buf.size(); i += 4) {
            std::uint32_t cand = 0;
            std::memcpy(&cand, buf.data() + i, sizeof(cand));
            const std::uintptr_t cc = static_cast<std::uintptr_t>(cand);
#endif
            if (!InModule(cc, module_base, module_size)) {
                continue;
            }
            const int chain = CountClientClassChain(proc, module_base, module_size, cc);
            if (chain > best_count && chain >= 8) {
                best_count = chain;
                best_head = cc;
            }
        }
    }

    return best_head;
}

void DumpAllNetvars(HANDLE proc, std::uintptr_t module_base, std::size_t module_size,
                    std::uintptr_t client_class_head, std::ostream& out) {
    std::unordered_set<std::uintptr_t> seen;
    std::uintptr_t cur = client_class_head;

    while (cur && seen.size() < 5000) {
        if (seen.count(cur)) {
            break;
        }
        seen.insert(cur);

        if (!ClientClassLooksValid(proc, module_base, module_size, cur)) {
            out << "// invalid ClientClass at 0x" << std::hex << cur << std::dec << "\n";
            break;
        }

        const auto net_ptr = ReadRemotePointer(proc, cur + sl::kCcNetworkName);
        const auto rt_ptr = ReadRemotePointer(proc, cur + sl::kCcRecvTable);
        const auto cid = ReadRemoteU32(proc, cur + sl::kCcClassId);

        std::string net_name = "?";
        if (net_ptr && InModule(*net_ptr, module_base, module_size)) {
            if (const auto s = ReadName(proc, *net_ptr)) {
                net_name = *s;
            }
        }

        std::string table_name = "?";
        if (rt_ptr && RecvTableLooksValid(proc, module_base, module_size, *rt_ptr)) {
            const auto tn = ReadRemotePointer(proc, *rt_ptr + sl::kRtNetTableName);
            if (tn) {
                if (const auto s = ReadName(proc, *tn)) {
                    table_name = *s;
                }
            }
        }

        out << "\n// ClientClass: " << net_name << "  recv: " << table_name << "  id=";
        if (cid) {
            out << *cid;
        } else {
            out << "?";
        }
        out << "  ptr=0x" << std::hex << cur << std::dec << "\n";

        if (rt_ptr && *rt_ptr) {
            DumpRecvTable(proc, module_base, module_size, *rt_ptr, 0, table_name, out, 0);
        }

        const auto next = ReadRemotePointer(proc, cur + sl::kCcNext);
        if (!next || *next == 0) {
            break;
        }
        cur = *next;
    }
}

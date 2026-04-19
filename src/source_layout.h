#pragma once

#include <cstddef>
#include <cstdint>

// Offsets mirror Valve Source SDK dt_recv.h / client_class.h layouts for MSVC.
// x86: verified against TF2 32-bit / Source 2013.
// x64: MSVC x64 class layout (8-byte pointer alignment).

namespace SourceLayout {

#ifdef _WIN64

inline constexpr std::size_t kPointerSize = 8;
inline constexpr std::size_t kRecvPropBytes = 96;

inline constexpr std::uintptr_t kCcNetworkName = 16;
inline constexpr std::uintptr_t kCcRecvTable = 24;
inline constexpr std::uintptr_t kCcNext = 32;
inline constexpr std::uintptr_t kCcClassId = 40;

inline constexpr std::uintptr_t kRtProps = 0;
inline constexpr std::uintptr_t kRtNumProps = 8;
inline constexpr std::uintptr_t kRtNetTableName = 24;

inline constexpr std::uintptr_t kRpVarName = 0;
inline constexpr std::uintptr_t kRpRecvType = 8;
inline constexpr std::uintptr_t kRpDataTable = 64;
inline constexpr std::uintptr_t kRpArrayProp = 32;
inline constexpr std::uintptr_t kRpOffset = 72;
inline constexpr std::uintptr_t kRpElementStride = 76;
inline constexpr std::uintptr_t kRpNumElements = 80;

#else

inline constexpr std::size_t kPointerSize = 4;
inline constexpr std::size_t kRecvPropBytes = 60;

inline constexpr std::uintptr_t kCcNetworkName = 8;
inline constexpr std::uintptr_t kCcRecvTable = 12;
inline constexpr std::uintptr_t kCcNext = 16;
inline constexpr std::uintptr_t kCcClassId = 20;

inline constexpr std::uintptr_t kRtProps = 0;
inline constexpr std::uintptr_t kRtNumProps = 4;
inline constexpr std::uintptr_t kRtNetTableName = 12;

inline constexpr std::uintptr_t kRpVarName = 0;
inline constexpr std::uintptr_t kRpRecvType = 4;
inline constexpr std::uintptr_t kRpDataTable = 40;
inline constexpr std::uintptr_t kRpArrayProp = 24;
inline constexpr std::uintptr_t kRpOffset = 44;
inline constexpr std::uintptr_t kRpElementStride = 48;
inline constexpr std::uintptr_t kRpNumElements = 52;

#endif

}  // namespace SourceLayout

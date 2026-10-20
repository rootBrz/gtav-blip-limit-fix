#pragma once

#include <cstddef>
#include <cstdint>

namespace blip {

// Inspected x64 script-program layout; all pointers are validated before use.
struct ScriptProgram {
    std::uint8_t padding0[0x10];
    const std::uint8_t* const* pages;
    std::uint32_t hash;
    std::uint32_t length;
    std::uint8_t padding1[0x0c];
    std::uint32_t nativeCount;
    std::uint8_t padding2[0x10];
    const std::uintptr_t* natives;
    std::uint8_t padding3[0x10];
    std::uint32_t nameHash;
    std::uint32_t references;
    const char* name;
};
static_assert(offsetof(ScriptProgram, pages) == 0x10);
static_assert(offsetof(ScriptProgram, length) == 0x1c);
static_assert(offsetof(ScriptProgram, nativeCount) == 0x2c);
static_assert(offsetof(ScriptProgram, natives) == 0x40);
static_assert(offsetof(ScriptProgram, nameHash) == 0x58);
static_assert(offsetof(ScriptProgram, name) == 0x60);

enum class ScriptResult {
    Waiting, Patched, Unchanged, Transient, MissingGuard, Ambiguous, Invalid, WriteFailed
};

inline constexpr unsigned kScriptFailureLimit = 100;
inline constexpr unsigned kScriptRetryMs = 100;

// Cumulative failure budget, not elapsed time. Only validated success resets it.
constexpr bool continueScriptPolling(ScriptResult result, unsigned& failures) {
    switch (result) {
    case ScriptResult::Transient:
        if (failures < kScriptFailureLimit) ++failures;
        return failures < kScriptFailureLimit;
    case ScriptResult::Waiting:
        return true;
    case ScriptResult::Patched:
    case ScriptResult::Unchanged:
        failures = 0;
        return true;
    default:
        return false;
    }
}

// Reads fresh program/page snapshots each call; no cached pointer survives a yield.
ScriptResult patchController(const ScriptProgram* const* programs,
                             std::uint16_t limit, std::size_t& guardOffset);

} // namespace blip

#pragma once

#include "memory.hpp"
#include <array>
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
    Waiting, Patched, Unchanged, Transient, MissingGuard, UnsupportedGuard, Ambiguous, Invalid, WriteFailed
};

inline constexpr unsigned kScriptFailureLimit = 100;
inline constexpr unsigned kScriptRetryMs = 100;

// Cumulative per-callback failure budget, not elapsed time. Waiting preserves it.
constexpr bool continueScriptPolling(ScriptResult result, unsigned& failures) {
    switch (result) {
    case ScriptResult::Transient:
        if (failures < kScriptFailureLimit) ++failures;
        return failures < kScriptFailureLimit;
    case ScriptResult::Waiting:
        return true;
    default:
        return false;
    }
}

// Filled only when no guard is found: raw bytes around every PUSH 2000 / WAIT-shaped
// native, found by byte search (not instruction decoding), to show why matching failed.
inline constexpr std::size_t kDiagMaxCandidates = 8;
inline constexpr std::size_t kDiagBefore = 48;
inline constexpr std::size_t kDiagAfter = 24;

struct WaitCandidate {
    std::size_t nativeOffset = 0; // offset of the 0x2C byte
    std::size_t start = 0;        // offset of bytes[0]
    std::size_t size = 0;
    std::array<std::uint8_t, kDiagBefore + 4 + kDiagAfter> bytes{};
};

struct ScriptDiagnostics {
    bool collected = false;
    bool faulted = false;
    std::size_t length = 0;
    std::uint32_t nativeCount = 0;
    std::size_t waitNatives = 0;  // NATIVE sig 0x04 (1 arg, 0 results)
    std::size_t countNatives = 0; // NATIVE sig 0x01 (0 args, 1 result)
    std::size_t candidates = 0;   // PUSH 2000 shortly before a WAIT-shaped native
    std::size_t stored = 0;
    std::array<WaitCandidate, kDiagMaxCandidates> found{};
};

struct ProgramArrayScan {
    memory::ScanStatus status = memory::ScanStatus::Missing;
    memory::ImageScan original;
    memory::ImageScan scrDbg;
    memory::ImageScan legacy;
    const ScriptProgram* const* programs = nullptr;
};

// Each locator must be unique; all present matches must resolve to the same array.
ProgramArrayScan findProgramArray(HMODULE module);

// Reads fresh program/page snapshots each call; no cached pointer survives a yield.
// guardOffset reports the predicate rewrite start, including any preserved padding.
// diagnostics, when given, is filled on MissingGuard.
ScriptResult patchController(const ScriptProgram* const* programs,
                             std::uint16_t limit, std::size_t& guardOffset,
                             ScriptDiagnostics* diagnostics = nullptr);

} // namespace blip

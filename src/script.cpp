#include "script.hpp"
#include "memory.hpp"
#include "guard.hpp"

#include <array>
#include <cstring>

namespace blip {
namespace {
constexpr std::size_t MaxScriptLength = 8 * 1024 * 1024;
constexpr std::size_t MaxPages = MaxScriptLength / kPageSize;
using Pages = std::array<const std::uint8_t*, MaxPages>;
constexpr char ScriptName[] = "blip_controller";

int memoryException(unsigned long code) {
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
                   code == STATUS_GUARD_PAGE_VIOLATION
               ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

bool sameProgram(const ScriptProgram& a, const ScriptProgram& b) {
    return a.pages == b.pages && a.length == b.length && a.hash == b.hash &&
           a.nativeCount == b.nativeCount && a.natives == b.natives &&
           a.nameHash == b.nameHash && a.name == b.name;
}

const std::uint8_t* addressAt(const Pages& pages, std::size_t offset) {
    const auto base = reinterpret_cast<std::uintptr_t>(pages[offset / kPageSize]);
    const auto within = offset % kPageSize;
    if (base > ~std::uintptr_t{0} - within) return nullptr;
    return reinterpret_cast<const std::uint8_t*>(base + within);
}

ScriptResult findGuard(const Pages& pages, std::size_t length,
                       std::uint32_t nativeCount, std::uint16_t limit, GuardMatch& match) {
    __try {
        const auto byteAt = [&](std::size_t i) { return *addressAt(pages, i); };
        switch (findSemanticGuard(byteAt, length, nativeCount, limit, match)) {
        case GuardStatus::Found:
            return match.configured ? ScriptResult::Unchanged : ScriptResult::Patched;
        case GuardStatus::Missing:
            return ScriptResult::MissingGuard;
        case GuardStatus::Ambiguous:
            return ScriptResult::Ambiguous;
        case GuardStatus::Unsupported:
            return ScriptResult::UnsupportedGuard;
        case GuardStatus::Changed:
            return ScriptResult::Transient;
        case GuardStatus::Invalid:
            return ScriptResult::Invalid;
        }
        return ScriptResult::Invalid;
    } __except (memoryException(GetExceptionCode())) {
        return ScriptResult::Transient;
    }
}

ScriptResult writeGuard(const Pages& pages, const GuardMatch& match) {
    // Preflight rejection has made no writes and can be retried.
    for (std::size_t i = 0; i < match.patchSize; ++i)
        if (!memory::accessible(addressAt(pages, match.patchOffset + i), 1, true))
            return ScriptResult::Transient;
    __try {
        for (std::size_t i = 0; i < match.windowSize; ++i)
            if (*addressAt(pages, match.windowOffset + i) != match.expected[i])
                return ScriptResult::Transient;
    } __except (memoryException(GetExceptionCode())) {
        return ScriptResult::Transient;
    }
    volatile std::size_t written = 0;
    __try {
        for (std::size_t i = 0; i < match.patchSize; ++i) {
            *const_cast<volatile std::uint8_t*>(addressAt(pages, match.patchOffset + i)) =
                match.replacement[i];
            written = i + 1;
        }
        return ScriptResult::Patched;
    } __except (memoryException(GetExceptionCode())) {
        // Best effort only: these byte writes are not atomic, and restoration can fail.
        __try {
            for (std::size_t i = 0; i < written; ++i)
                *const_cast<volatile std::uint8_t*>(addressAt(pages, match.patchOffset + i)) =
                    match.expected[match.patchOffset - match.windowOffset + i];
        } __except (memoryException(GetExceptionCode())) {
            // Do not retry or assume the original expression was restored.
        }
        return ScriptResult::WriteFailed;
    }
}
template<std::size_t N>
bool resolveProgramArray(HMODULE module, const memory::ImageScan& scan,
                         const std::array<int, N>& pattern,
                         const ScriptProgram* const*& programs) {
    std::array<std::uint8_t, N> locator;
    if (!memory::read(scan.match, locator.data(), locator.size())) return false;
    for (std::size_t i = 0; i < N; ++i)
        if (pattern[i] >= 0 && locator[i] != pattern[i]) return false;
    std::int32_t displacement;
    std::memcpy(&displacement, locator.data() + 3, sizeof(displacement));
    const auto base = reinterpret_cast<std::uintptr_t>(module);
    const auto match = reinterpret_cast<std::uintptr_t>(scan.match);
    if (match < base || match - base > scan.imageSize) return false;
    const auto offset = static_cast<std::int64_t>(match - base) + 7 + displacement + 0xd8;
    constexpr auto bytes = kProgramSlots * sizeof(ScriptProgram*);
    if (offset < 0xd8 || static_cast<std::uint64_t>(offset) > scan.imageSize ||
        bytes > scan.imageSize - static_cast<std::size_t>(offset)) return false;
    programs = reinterpret_cast<const ScriptProgram* const*>(base + static_cast<std::size_t>(offset));
    return true;
}
} // namespace

ProgramArrayScan findProgramArray(HMODULE module) {
    ProgramArrayScan result;
    const std::array<memory::ImagePattern, 3> patterns = {{
        {kProgramLocator.data(), kProgramLocator.size(), result.original},
        {kProgramLocatorScrDbg.data(), kProgramLocatorScrDbg.size(), result.scrDbg},
        {kProgramLocatorLegacy.data(), kProgramLocatorLegacy.size(), result.legacy},
    }};
    memory::findImagePatterns(module, patterns.data(), patterns.size());
    // Missing alone permits fallback. Never hide ambiguity, invalid images, or scan faults.
    for (const auto* scan : {&result.original, &result.scrDbg, &result.legacy}) {
        if (scan->status != memory::ScanStatus::Missing && scan->status != memory::ScanStatus::Found) {
            result.status = scan->status;
            return result;
        }
    }
    const ScriptProgram* const* original = nullptr;
    const ScriptProgram* const* scrDbg = nullptr;
    const ScriptProgram* const* legacy = nullptr;
    if ((result.original.status == memory::ScanStatus::Found &&
         !resolveProgramArray(module, result.original, kProgramLocator, original)) ||
        (result.scrDbg.status == memory::ScanStatus::Found &&
         !resolveProgramArray(module, result.scrDbg, kProgramLocatorScrDbg, scrDbg)) ||
        (result.legacy.status == memory::ScanStatus::Found &&
         !resolveProgramArray(module, result.legacy, kProgramLocatorLegacy, legacy)) ||
        (original && scrDbg && original != scrDbg) ||
        (original && legacy && original != legacy) ||
        (scrDbg && legacy && scrDbg != legacy)) {
        result.status = memory::ScanStatus::Invalid;
        return result;
    }
    result.programs = original ? original : scrDbg ? scrDbg : legacy;
    result.status = result.programs ? memory::ScanStatus::Found : memory::ScanStatus::Missing;
    return result;
}

ScriptResult patchController(const ScriptProgram* const* programs,
                             std::uint16_t limit, std::size_t& guardOffset) {
    if (limit < kMinLimit || limit > kMaxLimit) return ScriptResult::Invalid;
    std::array<const ScriptProgram*, kProgramSlots> slots;
    if (!memory::read(programs, slots.data(), sizeof(slots))) return ScriptResult::Transient;
    const ScriptProgram* selected = nullptr;
    std::size_t selectedSlot = 0;
    ScriptProgram program{};
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        const auto pointer = slots[slot];
        if (!pointer || pointer == selected) continue;
        ScriptProgram candidate;
        if (!memory::read(pointer, &candidate, sizeof(candidate)) ||
            candidate.nameHash != kScriptHash) continue;
        char name[sizeof(ScriptName)];
        if (!memory::read(candidate.name, name, sizeof(name))) return ScriptResult::Transient;
        if (std::memcmp(name, ScriptName, sizeof(name)) != 0) continue;
        if (selected) return ScriptResult::Ambiguous;
        selected = pointer;
        selectedSlot = slot;
        program = candidate;
    }
    if (!selected) return ScriptResult::Waiting;
    if (program.length > MaxScriptLength || program.nativeCount > 65536)
        return ScriptResult::Invalid;
    if (!program.length || !program.nativeCount ||
        !memory::accessible(program.natives, static_cast<std::size_t>(program.nativeCount) * sizeof(std::uintptr_t)))
        return ScriptResult::Transient;
    const auto pageCount = (program.length + kPageSize - 1) / kPageSize;
    Pages pages;
    if (!memory::read(program.pages, pages.data(), pageCount * sizeof(pages[0])))
        return ScriptResult::Transient;
    for (std::size_t i = 0; i < pageCount; ++i) {
        const auto remaining = program.length - i * kPageSize;
        const auto size = remaining < kPageSize ? remaining : kPageSize;
        if (!memory::accessible(pages[i], size)) return ScriptResult::Transient;
    }
    GuardMatch match;
    const auto result = findGuard(pages, program.length, program.nativeCount, limit, match);
    if (result != ScriptResult::Patched && result != ScriptResult::Unchanged) return result;
    if (result == ScriptResult::Patched) {
        ScriptProgram current;
        Pages currentPages;
        if (!memory::read(selected, &current, sizeof(current)) || !sameProgram(program, current) ||
            !memory::read(current.pages, currentPages.data(), pageCount * sizeof(currentPages[0])) ||
            std::memcmp(pages.data(), currentPages.data(), pageCount * sizeof(pages[0])) != 0)
            return ScriptResult::Transient;
        const ScriptProgram* registered = nullptr;
        if (!memory::read(programs + selectedSlot, &registered, sizeof(registered)) ||
            registered != selected) return ScriptResult::Transient;
        const auto written = writeGuard(pages, match);
        if (written != ScriptResult::Patched) return written;
    }
    guardOffset = match.patchOffset;
    return result;
}
} // namespace blip

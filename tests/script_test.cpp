#include "memory.hpp"
#include "patch.hpp"
#include "script.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;

void branch(Bytes& code, std::size_t at, std::size_t target) {
    const auto delta = static_cast<std::ptrdiff_t>(target) - static_cast<std::ptrdiff_t>(at + 3);
    assert(delta >= -32768 && delta <= 32767);
    const auto encoded = static_cast<std::uint16_t>(delta);
    code[at + 1] = static_cast<std::uint8_t>(encoded);
    code[at + 2] = static_cast<std::uint8_t>(encoded >> 8);
}

Bytes makeLoop(std::initializer_list<std::uint8_t> predicate, std::size_t padding = 0,
               bool waitOnFalse = false) {
    Bytes code = {0x2c, 0x01, 0x00, 10}; // Count: zero arguments, one result.
    code.insert(code.end(), predicate);
    code.insert(code.end(), padding, 0x00);
    const auto conditional = code.size();
    code.insert(code.end(), {0x56, 0, 0});
    const auto exitJump = code.size();
    if (waitOnFalse) code.insert(code.end(), {0x55, 0, 0});
    const auto body = code.size();
    code.insert(code.end(), {0x43, 0xd0, 0x07, 0x2c, 0x04, 0x00, 47});
    const auto back = code.size();
    code.insert(code.end(), {0x55, 0, 0});
    const auto exit = code.size();
    code.insert(code.end(), {0x2e, 0, 0}); // Branches land on a real LEAVE instruction.
    branch(code, conditional, waitOnFalse ? body : exit);
    if (waitOnFalse) branch(code, exitJump, exit);
    branch(code, back, 0);
    return code;
}

struct Script {
    std::array<std::uint8_t*, 2> storage{};
    std::array<const std::uint8_t*, 2> pages{};
    std::array<std::uintptr_t, 64> natives{};
    std::array<const blip::ScriptProgram*, blip::kProgramSlots> slots{};
    blip::ScriptProgram program{};

    Script() {
        for (std::size_t i = 0; i < storage.size(); ++i) {
            storage[i] = static_cast<std::uint8_t*>(VirtualAlloc(
                nullptr, blip::kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            assert(storage[i]);
            pages[i] = storage[i];
        }
        program.pages = pages.data();
        program.length = static_cast<std::uint32_t>(pages.size() * blip::kPageSize);
        program.nativeCount = static_cast<std::uint32_t>(natives.size());
        program.natives = natives.data();
        program.nameHash = blip::kScriptHash;
        program.name = "blip_controller";
        slots[0] = &program;
    }
    ~Script() {
        for (const auto p : storage) assert(VirtualFree(p, 0, MEM_RELEASE));
    }
    Script(const Script&) = delete;
    Script& operator=(const Script&) = delete;
    std::uint8_t& byte(std::size_t i) { return storage[i / blip::kPageSize][i % blip::kPageSize]; }
    Bytes loop(std::size_t at, std::initializer_list<std::uint8_t> predicate = {0x25, 0x96, 0x0c, 0x06},
               std::size_t padding = 0, bool waitOnFalse = false) {
        const auto code = makeLoop(predicate, padding, waitOnFalse);
        for (std::size_t i = 0; i < code.size(); ++i) byte(at + i) = code[i];
        return code;
    }
    void unchanged(std::size_t at, const Bytes& code) {
        for (std::size_t i = 0; i < code.size(); ++i) assert(byte(at + i) == code[i]);
    }
    void protect(unsigned page, std::size_t offset, std::size_t size, DWORD flags) {
        DWORD previous;
        assert(VirtualProtect(storage[page] + offset, size, flags, &previous));
    }
    blip::ScriptResult patch(std::size_t& offset, std::uint16_t limit = 1900) {
        return blip::patchController(slots.data(), limit, offset);
    }
    void original(std::size_t at) {
        constexpr std::array<std::uint8_t, 4> predicate = {0x25, 0x96, 0x0c, 0x06};
        for (std::size_t i = 0; i < predicate.size(); ++i)
            assert(byte(at + 4 + i) == predicate[i]);
    }
};

void testPatchAndReload() {
    Script first;
    const auto at = blip::kPageSize - 6; // The expression itself crosses separate VM allocations.
    first.loop(at);
    first.protect(0, 4096, 4096, PAGE_READONLY); // A readable VM page spans protection regions.
    std::size_t offset = 0;
    unsigned failures = 0;
    first.slots[0] = nullptr;
    auto result = first.patch(offset);
    assert(result == blip::ScriptResult::Waiting);
    assert(blip::continueScriptPolling(result, failures) && failures == 0);
    first.slots[0] = &first.program;
    result = first.patch(offset);
    assert(result == blip::ScriptResult::Patched);
    assert(!blip::continueScriptPolling(result, failures));
    assert(offset == at + 4);
    const auto replacement = blip::encodeLimit(1900);
    for (std::size_t i = 0; i < replacement.size(); ++i)
        assert(first.byte(offset + i) == replacement[i]);
    assert(first.byte(at + 8) == 0x56 && first.byte(at + 19) == 0xeb);
    result = first.patch(offset);
    assert(result == blip::ScriptResult::Unchanged);
    assert(!blip::continueScriptPolling(result, failures));
    // A different ceiling is not vanilla-only any more: the guard shape identifies it, so it is rewritten.
    assert(first.patch(offset, 1997) == blip::ScriptResult::Patched);

    Script reloaded;
    reloaded.loop(31);
    first.slots[0] = nullptr;
    first.slots[137] = &reloaded.program;
    unsigned reloadFailures = 0; // ScriptHook starts a new callback for the new save.
    result = first.patch(offset, 1997);
    assert(result == blip::ScriptResult::Patched);
    assert(!blip::continueScriptPolling(result, reloadFailures));
    assert(offset == 35);
    const auto newLimit = blip::encodeLimit(1997);
    for (std::size_t i = 0; i < newLimit.size(); ++i)
        assert(reloaded.byte(offset + i) == newLimit[i]);
    first.slots[137] = nullptr;
    assert(first.patch(offset) == blip::ScriptResult::Waiting);
}

void testVariablePredicates() {
    for (const auto predicate : {
             std::initializer_list<std::uint8_t>{0x28, 0x96, 0, 0, 0, 0x0b},
             std::initializer_list<std::uint8_t>{0x64, 0x96, 0, 0, 0x0c, 0x06},
             std::initializer_list<std::uint8_t>{0x25, 0x96, 0, 0x0c, 0, 0x06}}) {
        Script script;
        const auto at = blip::kPageSize - 7;
        const auto before = script.loop(at, predicate, 3);
        const auto branchAt = 4 + predicate.size() + 3;
        std::size_t offset = 123;
        assert(script.patch(offset) == blip::ScriptResult::Patched);
        assert(offset == at + 4);
        const auto encoded = blip::encodeLimit(1900);
        for (std::size_t i = 0; i < before.size(); ++i) {
            if (i < 4 || i >= branchAt) assert(script.byte(at + i) == before[i]);
            else if (i < branchAt - encoded.size()) assert(script.byte(at + i) == 0);
            else assert(script.byte(at + i) == encoded[i - (branchAt - encoded.size())]);
        }
        assert(script.patch(offset) == blip::ScriptResult::Unchanged);
    }

    Script opposite;
    const auto before = opposite.loop(100, {0x28, 0x96, 0, 0, 0, 0x0c}, 2, true);
    std::size_t offset = 0;
    assert(opposite.patch(offset) == blip::ScriptResult::Patched);
    assert(offset == 104);
    const auto branchAt = 12u;
    for (std::size_t i = 0; i < before.size(); ++i)
        if (i < 4 || i >= branchAt) assert(opposite.byte(100 + i) == before[i]);
    assert(opposite.byte(100 + branchAt - 1) == 0x0c); // ILT preserves false-edge WAIT polarity.
    assert(opposite.patch(offset) == blip::ScriptResult::Unchanged);
}

void testUnchangedAndUnsupported() {
    Script originalLimit;
    auto before = originalLimit.loop(100);
    std::size_t offset = 123;
    assert(originalLimit.patch(offset, 150) == blip::ScriptResult::Unchanged);
    assert(offset == 104);
    originalLimit.unchanged(100, before);

    Script configured;
    before = configured.loop(100, {0x28, 0x6c, 0x07, 0, 0, 0x0b}, 2);
    assert(configured.patch(offset) == blip::ScriptResult::Unchanged);
    assert(offset == 104);
    configured.unchanged(100, before);

    Script narrow;
    before = narrow.loop(100, {0x25, 0x96, 0x0b});
    offset = 123;
    assert(narrow.patch(offset) == blip::ScriptResult::UnsupportedGuard);
    assert(offset == 123);
    narrow.unchanged(100, before);
    unsigned failures = 0;
    assert(!blip::continueScriptPolling(blip::ScriptResult::UnsupportedGuard, failures));
    assert(narrow.patch(offset, 150) == blip::ScriptResult::Unchanged);
    narrow.unchanged(100, before);
    offset = 123;
    assert(narrow.patch(offset, 256) == blip::ScriptResult::UnsupportedGuard);
    assert(offset == 123);
    narrow.unchanged(100, before);
    assert(narrow.patch(offset, 255) == blip::ScriptResult::Patched);
    assert(offset == 104);
    assert(narrow.byte(offset) == 0x25 && narrow.byte(offset + 1) == 255 &&
           narrow.byte(offset + 2) == 0x0b);
    for (std::size_t i = 0; i < before.size(); ++i)
        if (i < 4 || i >= 7) assert(narrow.byte(100 + i) == before[i]);
    assert(narrow.patch(offset, 255) == blip::ScriptResult::Unchanged);
}

void testBranchSafety() {
    for (const bool wrongBackedge : {false, true}) {
        Script script;
        auto before = script.loop(100);
        if (wrongBackedge) branch(before, 18, 1); // Count NATIVE operand is not a loop header.
        else branch(before, 8, 12); // WAIT's S16 operand is not an exit instruction.
        for (std::size_t i = 0; i < before.size(); ++i) script.byte(100 + i) = before[i];
        std::size_t offset = 123;
        const auto result = script.patch(offset);
        assert(result == blip::ScriptResult::MissingGuard || result == blip::ScriptResult::Invalid);
        assert(offset == 123);
        script.unchanged(100, before);
    }
}

void testWritePreflight() {
    Script script;
    const auto at = blip::kPageSize - 6;
    const auto before = script.loop(at, {0x28, 0x96, 0, 0, 0, 0x0b}, 3);
    script.protect(1, 0, blip::kPageSize, PAGE_READONLY);
    std::size_t offset = 123;
    assert(script.patch(offset) == blip::ScriptResult::Transient);
    assert(offset == 123);
    script.unchanged(at, before); // No byte of the longer cross-page predicate may change.
    script.protect(1, 0, blip::kPageSize, PAGE_READWRITE);
    assert(script.patch(offset) == blip::ScriptResult::Patched);

    for (DWORD flags : {DWORD(PAGE_NOACCESS), DWORD(PAGE_READWRITE | PAGE_GUARD)}) {
        Script unreadable;
        unreadable.loop(100);
        unreadable.protect(1, 0, blip::kPageSize, flags);
        assert(unreadable.patch(offset) == blip::ScriptResult::Transient);
        unreadable.original(100);
        MEMORY_BASIC_INFORMATION info{};
        assert(VirtualQuery(unreadable.storage[1], &info, sizeof(info)));
        assert(info.Protect == flags); // No access may consume a guard page.
    }
}

void testAmbiguityAndIdentity() {
    Script script;
    script.loop(100);
    std::size_t offset = 0;
    auto otherProgram = script.program;
    script.slots[1] = &otherProgram;
    assert(script.patch(offset) == blip::ScriptResult::Ambiguous);
    script.original(100);
    script.slots[1] = nullptr;
    script.loop(blip::kPageSize + 100);
    assert(script.patch(offset) == blip::ScriptResult::Ambiguous);
    script.original(100);
    const auto replacement = blip::encodeLimit(1900);
    for (std::size_t i = 0; i < replacement.size(); ++i) script.byte(104 + i) = replacement[i];
    assert(script.patch(offset) == blip::ScriptResult::Ambiguous); // Original plus already-patched loops also conflict.
    script.original(blip::kPageSize + 100);

    Script collision;
    collision.loop(100);
    static constexpr char otherName[16] = "other_script";
    collision.program.name = otherName;
    assert(collision.patch(offset) == blip::ScriptResult::Waiting);
    collision.original(100);
    collision.program.name = reinterpret_cast<const char*>(1);
    assert(collision.patch(offset) == blip::ScriptResult::Transient);
}

void testMalformedScript() {
    Script script;
    script.loop(100);
    const auto valid = script.program;
    std::size_t offset = 0;
    script.program.length = 8u * 1024 * 1024 + 1;
    assert(script.patch(offset) == blip::ScriptResult::Invalid);
    script.original(100);
    script.program = valid;
    script.program.length = 120; // Final JMP operand is truncated.
    assert(script.patch(offset) == blip::ScriptResult::Invalid);
    script.original(100);
    script.program = valid;
    for (auto nativeCount : {47u, 65537u}) {
        script.program.nativeCount = nativeCount;
        assert(script.patch(offset) == blip::ScriptResult::Invalid);
        script.original(100);
    }
    script.program = valid;
    script.byte(117) = 10; // Both calls must not resolve the same native-table entry.
    assert(script.patch(offset) == blip::ScriptResult::Invalid);
    script.byte(117) = 47;
    script.program.pages = nullptr;
    assert(script.patch(offset) == blip::ScriptResult::Transient);
    script.program = valid;
    script.pages[1] = nullptr;
    assert(script.patch(offset) == blip::ScriptResult::Transient);
    script.original(100);
}

void testReadinessRecovery() {
    Script script;
    script.loop(100);
    const auto valid = script.program;
    std::size_t offset = 123;
    unsigned failures = 0;
    auto retry = [&] {
        const auto result = script.patch(offset);
        assert(result == blip::ScriptResult::Transient);
        assert(blip::continueScriptPolling(result, failures));
        assert(offset == 123);
        script.original(100);
    };
    script.program.length = 0;
    retry();
    script.program = valid;
    script.program.nativeCount = 0;
    retry();
    script.program = valid;
    script.program.natives = nullptr;
    retry();
    script.program = valid;
    script.program.pages = nullptr;
    retry();
    script.program = valid;
    script.pages[1] = nullptr;
    retry();
    script.pages[1] = script.storage[1];
    script.program.name = nullptr;
    retry();
    script.program = valid;
    assert(failures == 6);
    const auto result = script.patch(offset);
    assert(result == blip::ScriptResult::Patched);
    assert(!blip::continueScriptPolling(result, failures) && failures == 6);
    assert(offset == 104);
    assert(script.byte(offset) == 0x43 && script.byte(offset + 3) == 0x0b);
}

void testRetryExhaustion() {
    Script script;
    script.loop(100);
    script.program.pages = nullptr;
    std::size_t offset = 123;
    unsigned failures = 0;
    for (unsigned attempt = 1; attempt < blip::kScriptFailureLimit; ++attempt) {
        const auto result = script.patch(offset);
        assert(result == blip::ScriptResult::Transient);
        assert(blip::continueScriptPolling(result, failures));
        assert(failures == attempt);
        script.slots[0] = nullptr;
        assert(blip::continueScriptPolling(script.patch(offset), failures));
        assert(failures == attempt); // Disappearance cannot reset the failure budget.
        script.slots[0] = &script.program;
    }
    assert(!blip::continueScriptPolling(script.patch(offset), failures));
    assert(failures == blip::kScriptFailureLimit);
    assert(!blip::continueScriptPolling(blip::ScriptResult::Transient, failures));
    assert(failures == blip::kScriptFailureLimit); // Saturate; never wrap into more retries.
    assert(offset == 123);
    script.original(100);
    for (const auto terminal : {blip::ScriptResult::Invalid, blip::ScriptResult::MissingGuard,
                               blip::ScriptResult::UnsupportedGuard, blip::ScriptResult::Ambiguous,
                               blip::ScriptResult::WriteFailed})
        assert(!blip::continueScriptPolling(terminal, failures));
    assert(!blip::continueScriptPolling(blip::ScriptResult::Unchanged, failures));
    assert(failures == blip::kScriptFailureLimit); // Success ends this callback, not its failure budget.
}
} // namespace

void testLocatedScript(const blip::ScriptProgram* const* programs) {
    Script script;
    script.loop(100);
    std::array<std::uint8_t, 2 * blip::kPageSize> expected;
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = script.byte(i);
    const auto replacement = blip::encodeLimit(1900);
    std::memcpy(expected.data() + 104, replacement.data(), replacement.size());
    auto* slot = const_cast<const blip::ScriptProgram**>(programs);
    slot[0] = &script.program;
    std::size_t offset = 0;
    script.program.natives = nullptr;
    assert(blip::patchController(programs, 1900, offset) == blip::ScriptResult::Transient);
    assert(offset == 0);
    script.original(100);
    script.program.natives = script.natives.data();
    assert(blip::patchController(programs, 1900, offset) == blip::ScriptResult::Patched);
    assert(offset == 104);
    for (std::size_t i = 0; i < expected.size(); ++i) assert(script.byte(i) == expected[i]);
    assert(blip::patchController(programs, 1900, offset) == blip::ScriptResult::Unchanged);
    slot[0] = nullptr;
}

void testScripts() {
    testPatchAndReload();
    testVariablePredicates();
    testUnchangedAndUnsupported();
    testBranchSafety();
    testWritePreflight();
    testAmbiguityAndIdentity();
    testMalformedScript();
    testReadinessRecovery();
    testRetryExhaustion();
    std::puts("PASS: script identity, semantic paged guards, variable predicate writes, refusal safety and retry limits");
}

#include "memory.hpp"
#include "patch.hpp"
#include "script.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

namespace {
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
    void loop(std::size_t at) {
        for (std::size_t i = 0; i < blip::kGuard.size(); ++i)
            byte(at + i) = static_cast<std::uint8_t>(blip::kGuard[i] < 0 ? 0 : blip::kGuard[i]);
        byte(at + 3) = 10;
        byte(at + 17) = 47;
    }
    void protect(unsigned page, std::size_t offset, std::size_t size, DWORD flags) {
        DWORD previous;
        assert(VirtualProtect(storage[page] + offset, size, flags, &previous));
    }
    blip::ScriptResult patch(std::size_t& offset, std::uint16_t limit = 1900) {
        return blip::patchController(slots.data(), limit, offset);
    }
    void original(std::size_t at) {
        for (std::size_t i = 0; i < 4; ++i)
            assert(byte(at + 4 + i) == blip::kGuard[4 + i]);
    }
};

void testPatchAndReload() {
    Script first;
    const auto at = blip::kPageSize - 6; // The expression itself crosses separate VM allocations.
    first.loop(at);
    first.protect(0, 4096, 4096, PAGE_READONLY); // A readable VM page spans protection regions.
    std::size_t offset = 0;
    assert(first.patch(offset) == blip::ScriptResult::Patched);
    assert(offset == at + 4);
    const auto replacement = blip::encodeLimit(1900);
    for (std::size_t i = 0; i < replacement.size(); ++i)
        assert(first.byte(offset + i) == replacement[i]);
    assert(first.byte(at + 8) == 0x56 && first.byte(at + 19) == 0xeb);
    assert(first.patch(offset) == blip::ScriptResult::Unchanged);
    assert(first.patch(offset, 1997) == blip::ScriptResult::MissingGuard); // Do not overwrite another configured patch.

    Script reloaded;
    reloaded.loop(31);
    first.slots[0] = nullptr;
    first.slots[137] = &reloaded.program;
    assert(first.patch(offset, 1997) == blip::ScriptResult::Patched);
    assert(offset == 35);
    const auto newLimit = blip::encodeLimit(1997);
    for (std::size_t i = 0; i < newLimit.size(); ++i)
        assert(reloaded.byte(offset + i) == newLimit[i]);
    first.slots[137] = nullptr;
    assert(first.patch(offset) == blip::ScriptResult::Waiting);
}

void testWritePreflight() {
    Script script;
    const auto at = blip::kPageSize - 6;
    script.loop(at);
    script.protect(1, 0, blip::kPageSize, PAGE_READONLY);
    std::size_t offset = 123;
    assert(script.patch(offset) == blip::ScriptResult::Transient);
    assert(offset == 123);
    script.original(at); // The writable first half must not be patched either.
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
    script.program.length = 100 + static_cast<std::uint32_t>(blip::kGuard.size()) - 1;
    assert(script.patch(offset) == blip::ScriptResult::MissingGuard);
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
    assert(blip::continueScriptPolling(result, failures) && failures == 0);
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
                               blip::ScriptResult::Ambiguous, blip::ScriptResult::WriteFailed})
        assert(!blip::continueScriptPolling(terminal, failures));
    assert(blip::continueScriptPolling(blip::ScriptResult::Unchanged, failures));
    assert(failures == 0); // A validated patch starts a fresh budget for later reloads.
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
    testWritePreflight();
    testAmbiguityAndIdentity();
    testMalformedScript();
    testReadinessRecovery();
    testRetryExhaustion();
    std::puts("PASS: script identity, paged guards, readiness recovery, retry limits and write preflight");
}

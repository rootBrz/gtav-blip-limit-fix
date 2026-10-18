#define WIN32_LEAN_AND_MEAN
#include <main.h>
#include <cstdarg>
#include <cwchar>
#include <cstdio>
#include "config.hpp"
#include "patch.hpp"
#include <cstdint>
#include <cstring>

namespace {

HMODULE module;
HANDLE logFile = INVALID_HANDLE_VALUE;
std::uint16_t limit = blip::kDefaultLimit;

void log(const char* format, ...) {
    if (logFile == INVALID_HANDLE_VALUE) return;
    char line[512];
    va_list args;
    va_start(args, format);
    int size = std::vsnprintf(line, sizeof(line)-2, format, args);
    va_end(args);
    if (size < 0) return;
    if (size > static_cast<int>(sizeof(line)-3)) size = sizeof(line)-3;
    line[size++] = '\r';
    line[size++] = '\n';
    DWORD written;
    WriteFile(logFile, line, size, &written, nullptr);
    FlushFileBuffers(logFile);
}

bool accessible(const void* pointer, std::size_t size, bool writable = false) {
    if (!pointer || !size) return false;
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(pointer, &info, sizeof(info)) || info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    const auto protection = info.Protect & 0xff;
    const bool canRead = protection == PAGE_READONLY || protection == PAGE_READWRITE ||
        protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
    const bool canWrite = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
    const auto offset = reinterpret_cast<std::uintptr_t>(pointer) -
        reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    return canRead && (!writable || canWrite) && offset <= info.RegionSize &&
        size <= info.RegionSize - offset;
}

struct Program {
    std::uint8_t padding0[0x10];
    std::uint8_t** pages;
    std::uint32_t hash;
    std::uint32_t length;
    std::uint8_t padding1[0x0c];
    std::uint32_t nativeCount;
    std::uint8_t padding2[0x28];
    std::uint32_t nameHash;
};
static_assert(offsetof(Program, pages) == 0x10);
static_assert(offsetof(Program, length) == 0x1c);
static_assert(offsetof(Program, nameHash) == 0x58);

bool initialize();

void patternFailure(const wchar_t* detail) {
    MessageBoxW(nullptr, detail, L"BlipLimitFix: pattern search failed",
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

void run() {
    if (!initialize()) return;
    const auto replacement = blip::encodeLimit(limit);
    auto base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        log("REFUSED: expected a Windows x64 game image");
        return;
    }
    const auto sections = IMAGE_FIRST_SECTION(nt);
    Program** programs = nullptr;
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        const auto size = section.Misc.VirtualSize;
        if (section.VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            size > nt->OptionalHeader.SizeOfImage-section.VirtualAddress) continue;
        auto code = base + section.VirtualAddress;
        if (!accessible(code, size)) continue;
        auto offset = blip::uniqueMatch([&](std::size_t j) { return code[j]; }, size,
                                       blip::kProgramLocator);
        if (offset == size) continue;
        if (programs || offset > size) {
            log("REFUSED: ambiguous program-array locator");
            patternFailure(L"The game-code pattern is ambiguous. BlipLimitFix has stopped without patching. See BlipLimitFix.log.");
            return;
        }
        std::int32_t displacement;
        std::memcpy(&displacement, code+offset+3, sizeof(displacement));
        const auto address = reinterpret_cast<std::uintptr_t>(code+offset+7) + displacement + 0xd8;
        const auto imageStart = reinterpret_cast<std::uintptr_t>(base);
        if (address < imageStart || address-imageStart >= nt->OptionalHeader.SizeOfImage ||
            blip::kProgramSlots*sizeof(Program*) > nt->OptionalHeader.SizeOfImage-(address-imageStart)) {
            log("REFUSED: program array is outside the game image");
            return;
        }
        programs = reinterpret_cast<Program**>(address);
    }
    if (!programs) {
        log("REFUSED: program-array locator not found");
        patternFailure(L"The game-code pattern was not found. BlipLimitFix has stopped without patching. See BlipLimitFix.log.");
        return;
    }
    if (!accessible(programs, blip::kProgramSlots*sizeof(*programs))) {
        log("REFUSED: no unique readable program array found");
        return;
    }
    log("Located program array dynamically; waiting for blip_controller");
    std::uint8_t* lastPage = nullptr;
    std::size_t lastGuard = 0;
    for (;;) {
        for (unsigned i = 0; i < blip::kProgramSlots; ++i) {
            auto program = programs[i];
            if (!accessible(program, sizeof(Program)) || program->nameHash != blip::kScriptHash) continue;
            if (!program->length || program->length > 8*1024*1024 ||
                !accessible(program->pages, ((program->length+blip::kPageSize-1)/blip::kPageSize)*sizeof(void*))) {
                log("REFUSED: invalid blip_controller code layout");
                return;
            }
            bool readable = true;
            for (std::size_t start = 0; start < program->length; start += blip::kPageSize) {
                auto size = program->length-start;
                if (size > blip::kPageSize) size = blip::kPageSize;
                if (!accessible(program->pages[start/blip::kPageSize], size)) { readable = false; break; }
            }
            if (!readable) { log("REFUSED: unreadable script page"); return; }
            auto byteAt = [&](std::size_t j) { return program->pages[j/blip::kPageSize][j%blip::kPageSize]; };
            if (program->pages[0] == lastPage && lastGuard+4 <= program->length) {
                bool patched = true;
                for (unsigned j = 0; j < 4; ++j)
                    if (byteAt(lastGuard+j) != replacement[j]) patched = false;
                if (patched) continue;
            }
            auto offset = blip::uniqueMatch(byteAt, program->length, blip::kGuard);
            if (offset >= program->length) {
                log("REFUSED: missing or ambiguous active-blip-count WAIT(2000) guard");
                patternFailure(L"The script pattern was not found or is ambiguous. BlipLimitFix has stopped. See BlipLimitFix.log.");
                return;
            }
            const unsigned countNative = (byteAt(offset+2)<<8) | byteAt(offset+3);
            const unsigned waitNative = (byteAt(offset+16)<<8) | byteAt(offset+17);
            if (countNative >= program->nativeCount || waitNative >= program->nativeCount ||
                countNative == waitNative) {
                log("REFUSED: invalid guard native indices");
                return;
            }
            const auto guardOffset = offset+4;
            // Validate every destination before changing anything, including page-crossing guards.
            for (unsigned j = 0; j < 4; ++j)
                if (!accessible(program->pages[(guardOffset+j)/blip::kPageSize]+(guardOffset+j)%blip::kPageSize, 1, true)) {
                    log("REFUSED: script guard is not writable");
                    return;
                }
            for (unsigned j = 0; j < 4; ++j)
                program->pages[(guardOffset+j)/blip::kPageSize][(guardOffset+j)%blip::kPageSize] = replacement[j];
            lastPage = program->pages[0];
            lastGuard = guardOffset;
            log("PATCHED: blip_controller +0x%zX: ceiling 150 -> %u", guardOffset, static_cast<unsigned>(limit));
            log("Native pool unchanged; native counts remain accurate");
        }
        // ScriptHook runs this callback between VM executions.
        scriptWait(lastPage ? 1000 : 100);
    }
}

bool initialize() {
    wchar_t path[MAX_PATH];
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return false;
    auto slash = std::wcsrchr(path, L'\\');
    if (!slash) return false;
    if (slash-path+1+sizeof(L"BlipLimitFix.log")/sizeof(wchar_t) > MAX_PATH) return false;
    std::wcscpy(slash+1, L"BlipLimitFix.log");
    if (logFile != INVALID_HANDLE_VALUE) CloseHandle(logFile);
    logFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    log("Compatibility: tested only on GTA V Enhanced 1.0.1158.16; other versions are untested");
    std::wcscpy(slash+1, L"BlipLimitFix.ini");
    const auto config = blip::readLimit(path, limit);
    if (config == blip::ConfigResult::Invalid) {
        log("REFUSED: [Blips] Limit must be a decimal integer from %u to %u",
            static_cast<unsigned>(blip::kMinLimit), static_cast<unsigned>(blip::kMaxLimit));
        return false;
    }
    if (config == blip::ConfigResult::Error) {
        log("REFUSED: could not read BlipLimitFix.ini");
        return false;
    }
    log("INI: Limit=%u%s", static_cast<unsigned>(limit),
        config == blip::ConfigResult::Default ? " (default; file or key missing)" : "");
    return true;
}
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        module = instance;
        DisableThreadLibraryCalls(instance);
        scriptRegister(instance, run);
    } else if (reason == DLL_PROCESS_DETACH) {
        scriptUnregister(instance);
        if (logFile != INVALID_HANDLE_VALUE) CloseHandle(logFile);
    }
    return TRUE;
}

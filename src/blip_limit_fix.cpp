#define WIN32_LEAN_AND_MEAN
#include <main.h>
#include <cstdarg>
#include <cwchar>
#include <cstdio>
#include "config.hpp"
#include "patch.hpp"
#include "memory.hpp"
#include "script.hpp"
#include <cstdint>

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

bool initialize();

void patternFailure(const wchar_t* detail) {
    MessageBoxW(nullptr, detail, L"BlipLimitFix: pattern search failed",
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

void run() {
    if (!initialize()) return;
    const auto moduleBase = GetModuleHandleW(nullptr);
    const auto scan = blip::findProgramArray(moduleBase);
    for (const auto* locator : {&scan.original, &scan.scrDbg, &scan.legacy})
        log("Native scan: locator=%s status=%u readable=%zu skipped=%zu ranges=%zu",
            locator == &scan.original ? "original-enhanced" :
                locator == &scan.scrDbg ? "scrDbg-enhanced" : "scrDbg-legacy",
            static_cast<unsigned>(locator->status),
            locator->scannedBytes, locator->skippedBytes, locator->readableRanges);
    if (scan.status == blip::memory::ScanStatus::Missing) {
        log("REFUSED: program-array locator not found");
        patternFailure(L"The game-code pattern was not found. BlipLimitFix has stopped without patching. See BlipLimitFix.log.");
        return;
    }
    if (scan.status == blip::memory::ScanStatus::Ambiguous) {
        log("REFUSED: ambiguous program-array locator");
        patternFailure(L"The game-code pattern is ambiguous. BlipLimitFix has stopped without patching. See BlipLimitFix.log.");
        return;
    }
    if (scan.status != blip::memory::ScanStatus::Found) {
        log("REFUSED: invalid image, changed locator, out-of-range array, scan fault, or locator disagreement");
        return;
    }
    const auto programs = scan.programs;
    log("Located program array dynamically; waiting for blip_controller");
    bool applied = false;
    unsigned transientFailures = 0;
    for (;;) {
        std::size_t offset = 0;
        const auto result = blip::patchController(programs, limit, offset);
        const bool pollAgain = blip::continueScriptPolling(result, transientFailures);
        switch (result) {
        case blip::ScriptResult::Patched:
            log("PATCHED: blip_controller +0x%zX: ceiling 150 -> %u",
                offset, static_cast<unsigned>(limit));
            log("Native pool unchanged; native counts remain accurate");
            applied = true;
            break;
        case blip::ScriptResult::Unchanged:
            if (!applied) log("blip_controller already has the configured ceiling");
            applied = true;
            break;
        case blip::ScriptResult::Waiting:
            applied = false;
            break;
        case blip::ScriptResult::Transient:
            applied = false;
            if (!pollAgain) {
                log("REFUSED: script memory did not stabilize after %u transient failures",
                    transientFailures);
                return;
            }
            if (transientFailures == 1)
                log("Script memory not ready or changed; retrying at %u ms intervals (limit %u failures)",
                    blip::kScriptRetryMs, blip::kScriptFailureLimit);
            break;
        case blip::ScriptResult::MissingGuard:
            log("REFUSED: active-blip-count WAIT(2000) guard not found");
            patternFailure(L"The script pattern was not found. BlipLimitFix has stopped. See BlipLimitFix.log.");
            return;
        case blip::ScriptResult::Ambiguous:
            log("REFUSED: ambiguous blip_controller program or guard");
            patternFailure(L"The script or its pattern is ambiguous. BlipLimitFix has stopped. See BlipLimitFix.log.");
            return;
        case blip::ScriptResult::Invalid:
            log("REFUSED: invalid script structure or native indices");
            return;
        case blip::ScriptResult::WriteFailed:
            log("REFUSED: script write fault; rollback was best effort and may be incomplete. No retry; restart the game.");
            return;
        }
        // Refresh program/page snapshots after every yield, including script reloads.
        scriptWait(applied ? 1000 : blip::kScriptRetryMs);
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
    log("Compatibility: game-tested only on GTA V Enhanced 1.0.1158.16; Legacy discovery has synthetic tests only; Legacy limits/capacity and other builds are unverified");
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

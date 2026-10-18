#include "config.hpp"
#include "patch.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace blip {
ConfigResult readLimit(const wchar_t* iniPath, std::uint16_t& limit) {
    if (!iniPath || !*iniPath) return ConfigResult::Error;

    // Resolve relative paths once: the profile API otherwise searches Windows.
    wchar_t path[32768];
    const DWORD pathLength = GetFullPathNameW(iniPath, 32768, path, nullptr);
    if (!pathLength || pathLength >= 32768) return ConfigResult::Error;
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return ConfigResult::Error;

    // The profile API cannot reliably distinguish missing keys from I/O errors.
    // Check readability first and deny writes/deletes during the profile lookup.
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            return ConfigResult::Error;
        limit = kDefaultLimit;
        return ConfigResult::Default;
    }

    char block[4096];
    DWORD bytesRead;
    do {
        if (!ReadFile(file, block, sizeof(block), &bytesRead, nullptr)) {
            CloseHandle(file);
            return ConfigResult::Error;
        }
    } while (bytesRead != 0);

    wchar_t value[64];
    DWORD length = GetPrivateProfileStringW(L"Blips", L"Limit", L"?", value, 64, path);
    if (length == 1 && value[0] == L'?') {
        // Two different defaults distinguish absence from an actual '?' value.
        length = GetPrivateProfileStringW(L"Blips", L"Limit", L"!", value, 64, path);
        if (length == 1 && value[0] == L'!') {
            CloseHandle(file);
            limit = kDefaultLimit;
            return ConfigResult::Default;
        }
    }
    CloseHandle(file);

    if (length == 63 || !parseLimit(std::wstring_view(value, length), limit))
        return ConfigResult::Invalid;
    return ConfigResult::Loaded;
}
}

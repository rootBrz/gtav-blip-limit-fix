#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "config.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
    wchar_t directory[MAX_PATH], file[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, directory));
    assert(GetTempFileNameW(directory, L"blp", 0, file));
    assert(DeleteFileW(file));
    std::uint16_t value = 1777;
    assert(blip::readLimit(file, value) == blip::ConfigResult::Default && value == 1900);
    unsigned passed = 1;
    struct Case { const char* text; blip::ConfigResult result; unsigned limit; };
    const Case cases[] = {
        {"[Blips]\r\nLimit=1997\r\n", blip::ConfigResult::Loaded, 1997},
        {"[Blips]\r\nLimit=150\r\n", blip::ConfigResult::Loaded, 150},
        {"[Blips]\r\nLimit=\"1900\"\r\n", blip::ConfigResult::Loaded, 1900},
        {"[Blips]\r\nOther=1997\r\n", blip::ConfigResult::Default, 1900},
        {"[Blips]\r\nLimit=2000\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=149\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=-150\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=1900junk\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=?\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=!\r\n", blip::ConfigResult::Invalid, 1777},
        {"[Blips]\r\nLimit=99999999999999999999999999999999999999999999999999999999999999999999999\r\n", blip::ConfigResult::Invalid, 1777},
    };
    for (const auto& item : cases) {
        assert(GetTempFileNameW(directory, L"blp", 0, file));
        HANDLE handle = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        assert(handle != INVALID_HANDLE_VALUE);
        DWORD written;
        const DWORD length = static_cast<DWORD>(std::strlen(item.text));
        assert(WriteFile(handle, item.text, length, &written, nullptr) && written == length);
        CloseHandle(handle);
        value = 1777;
        const auto result = blip::readLimit(file, value);
        if (result != item.result || value != item.limit) {
            std::printf("FAIL result=%u value=%u input=%s\n", static_cast<unsigned>(result), value, item.text);
            return 1;
        }
        assert(DeleteFileW(file));
        ++passed;
    }
    assert(GetTempFileNameW(directory, L"blp", 0, file));
    HANDLE held = CreateFileW(file, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    assert(held != INVALID_HANDLE_VALUE);
    value = 1777;
    assert(blip::readLimit(file, value) == blip::ConfigResult::Error && value == 1777);
    CloseHandle(held);
    assert(DeleteFileW(file));
    ++passed;
    value = 1777;
    assert(blip::readLimit(directory, value) == blip::ConfigResult::Error && value == 1777);
    ++passed;
    std::printf("PASS: %u native Windows INI cases, including limit=1997, missing, invalid, and unreadable files\n", passed);
}

#include "memory.hpp"
#include "patch.hpp"
#include "script.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

#ifdef NDEBUG
#error memory_test requires assertions enabled.
#endif

static_assert(sizeof(void*) == 8, "These tests exercise loaded x64 PE images.");

void testLocatedScript(const blip::ScriptProgram* const* programs);

namespace {

using blip::memory::ImageScan;
using blip::memory::ScanStatus;

struct Image {
    std::size_t page;
    std::size_t size;
    std::uint8_t* base;

    explicit Image(WORD sectionCount = 1) {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        page = info.dwPageSize;
        size = 8 * page;
        base = static_cast<std::uint8_t*>(VirtualAlloc(
            nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        assert(base != nullptr);
        assert(size <= (std::numeric_limits<DWORD>::max)());

        auto& dos = *reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        auto& header = nt();
        header.Signature = IMAGE_NT_SIGNATURE;
        header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        header.FileHeader.NumberOfSections = sectionCount;
        header.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        header.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
        header.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        header.OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(base);
        header.OptionalHeader.SectionAlignment = static_cast<DWORD>(page);
        header.OptionalHeader.FileAlignment = 0x200;
        header.OptionalHeader.SizeOfImage = static_cast<DWORD>(size);
        header.OptionalHeader.SizeOfHeaders = static_cast<DWORD>(page);
        header.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        header.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        assert(reinterpret_cast<std::uint8_t*>(&section(sectionCount - 1) + 1) <= base + page);
        for (WORD i = 0; i < sectionCount; ++i)
            setSection(i, (i + 1) * page, i + 1 == sectionCount ? size - (i + 1) * page : page);
    }

    ~Image() {
        const BOOL released = VirtualFree(base, 0, MEM_RELEASE);
        assert(released != FALSE);
    }

    Image(const Image&) = delete;
    Image& operator=(const Image&) = delete;

    IMAGE_NT_HEADERS64& nt() {
        return *reinterpret_cast<IMAGE_NT_HEADERS64*>(base + 0x80);
    }

    IMAGE_SECTION_HEADER& section(WORD index = 0) {
        return IMAGE_FIRST_SECTION(&nt())[index];
    }

    void setSection(WORD index, std::size_t offset, std::size_t length, bool executable = true) {
        auto& value = section(index);
        value = {};
        std::memcpy(value.Name, executable ? ".text" : ".data", 5);
        value.VirtualAddress = static_cast<DWORD>(offset);
        value.Misc.VirtualSize = static_cast<DWORD>(length);
        value.SizeOfRawData = static_cast<DWORD>(length);
        value.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
        if (executable) value.Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    }

    void protect(std::size_t offset, std::size_t length, DWORD protection) {
        DWORD old = 0;
        const BOOL changed = VirtualProtect(base + offset, length, protection, &old);
        assert(changed != FALSE);
    }

    DWORD protection(std::size_t offset) const {
        MEMORY_BASIC_INFORMATION region{};
        const SIZE_T queried = VirtualQuery(base + offset, &region, sizeof(region));
        assert(queried == sizeof(region));
        return region.Protect;
    }

    template<std::size_t N>
    void place(std::size_t offset, const std::array<int, N>& pattern) {
        assert(offset <= size && N <= size - offset);
        for (std::size_t i = 0; i < N; ++i)
            base[offset + i] = static_cast<std::uint8_t>(pattern[i] == -1 ? 0xa0 + i : pattern[i]);
    }

    template<std::size_t N>
    ImageScan scan(const std::array<int, N>& pattern) const {
        return blip::memory::findImagePattern(reinterpret_cast<HMODULE>(base), pattern.data(), N);
    }

    ImageScan scan() const { return scan(blip::kProgramLocator); }
};

void expectMissing(const ImageScan& result) {
    assert(result.status == ScanStatus::Missing);
    assert(result.match == nullptr);
}

void expectInvalid(const ImageScan& result) {
    assert(result.status == ScanStatus::Invalid);
    assert(result.match == nullptr);
}

void expectFound(const ImageScan& result, const Image& image, std::size_t offset) {
    assert(result.status == ScanStatus::Found);
    assert(result.match == image.base + offset);
    assert(result.imageSize == image.size);
}

void expectAmbiguous(const ImageScan& result) {
    assert(result.status == ScanStatus::Ambiguous);
    assert(result.match == nullptr);
}

void testSplitReadableSection() {
    // This is the reported failure: one executable section spans three VirtualQuery regions.
    for (const std::size_t boundaryPage : {2u, 3u}) {
        Image image;
        const auto offset = boundaryPage * image.page - blip::kProgramLocator.size() / 2;
        image.place(offset, blip::kProgramLocator);
        image.protect(2 * image.page, image.page, PAGE_READONLY);
        image.protect(3 * image.page, image.size - 3 * image.page, PAGE_EXECUTE_READ);
        const auto result = image.scan();
        expectFound(result, image, offset);
        assert(result.scannedBytes == image.size - image.page);
        assert(result.skippedBytes == 0);
        assert(result.readableRanges >= 1);
    }
}

void testHolesAndGuards() {
    for (const DWORD protection : {DWORD(PAGE_NOACCESS), DWORD(PAGE_READWRITE | PAGE_GUARD)}) {
        Image image;
        constexpr auto half = blip::kProgramLocator.size() / 2;
        std::array<std::uint8_t, blip::kProgramLocator.size()> bytes{};
        for (std::size_t i = 0; i < bytes.size(); ++i)
            bytes[i] = static_cast<std::uint8_t>(blip::kProgramLocator[i] == -1 ? 0xa0 + i : blip::kProgramLocator[i]);
        const auto hole = 3 * image.page;
        std::memcpy(image.base + hole - half, bytes.data(), half);
        std::memcpy(image.base + hole + image.page, bytes.data() + half, bytes.size() - half);
        image.place(hole + 73, blip::kProgramLocator); // A complete match in the inaccessible page must not count.
        image.protect(hole, image.page, protection);
        auto result = image.scan();
        expectMissing(result); // Neither a hidden match nor concatenation across the hole is allowed.
        assert(result.scannedBytes == image.size - 2 * image.page);
        assert(result.skippedBytes == image.page);
        assert(result.readableRanges >= 2);
        assert(image.protection(hole) == protection); // In particular, scanning must not consume PAGE_GUARD.

        const auto after = 5 * image.page + 37;
        image.place(after, blip::kProgramLocator);
        expectFound(image.scan(), image, after);
        assert(image.protection(hole) == protection);
        image.place(image.page + 51, blip::kProgramLocator);
        expectAmbiguous(image.scan());
        assert(image.protection(hole) == protection);
    }

    Image image;
    const auto hole = 3 * image.page;
    const BOOL decommitted = VirtualFree(image.base + hole, image.page, MEM_DECOMMIT);
    assert(decommitted != FALSE);
    image.place(5 * image.page + 11, blip::kProgramLocator);
    const auto result = image.scan();
    expectFound(result, image, 5 * image.page + 11);
    assert(result.skippedBytes == image.page);
}

void testUniquenessAndSections() {
    {
        Image image;
        expectMissing(image.scan());
        image.place(image.page + 17, blip::kProgramLocator);
        expectFound(image.scan(), image, image.page + 17);
        image.place(image.page + 117, blip::kProgramLocator);
        expectAmbiguous(image.scan());
    }
    {
        Image image;
        image.place(image.page + 17, blip::kProgramLocator);
        image.place(4 * image.page + 17, blip::kProgramLocator);
        image.protect(image.page, image.page, PAGE_READONLY);
        image.protect(4 * image.page, image.page, PAGE_EXECUTE_READ);
        expectAmbiguous(image.scan());
    }
    {
        Image image(2);
        image.setSection(0, image.page, image.page, false);
        image.setSection(1, 3 * image.page, image.page);
        image.place(image.page + 9, blip::kProgramLocator);
        expectMissing(image.scan()); // Readable or executable page protection does not make .data a code section.
        image.protect(image.page, image.page, PAGE_EXECUTE_READ);
        expectMissing(image.scan());
        image.place(3 * image.page + 9, blip::kProgramLocator);
        expectFound(image.scan(), image, 3 * image.page + 9);
        image.protect(image.page, image.page, PAGE_READWRITE);
        image.section(0).Characteristics |= IMAGE_SCN_MEM_EXECUTE;
        expectAmbiguous(image.scan());
    }
    {
        Image image(2);
        image.setSection(0, image.page, 3 * image.page);
        image.setSection(1, 2 * image.page, image.page);
        image.place(2 * image.page + 9, blip::kProgramLocator);
        expectInvalid(image.scan()); // Reject overlapping descriptors rather than count one address twice.
    }
    {
        Image image(2);
        image.place(image.page + 9, blip::kProgramLocator);
        image.setSection(1, image.size, image.page, false);
        expectInvalid(image.scan()); // An early valid match cannot hide malformed later non-code metadata.
    }
}

void testRangeBoundsAndWildcards() {
    Image image;
    constexpr auto length = blip::kProgramLocator.size();
    const auto offset = 2 * image.page - length;
    image.setSection(0, offset, length - 1);
    image.place(offset, blip::kProgramLocator);
    expectMissing(image.scan()); // Physically readable bytes beyond VirtualSize are not part of the search.
    image.setSection(0, offset, length);
    expectFound(image.scan(), image, offset);
    for (std::size_t i = 0; i < length; ++i)
        if (blip::kProgramLocator[i] == -1) image.base[offset + i] ^= 0xff;
    expectFound(image.scan(), image, offset);
    for (std::size_t i = 0; i < length; ++i) {
        if (blip::kProgramLocator[i] == -1) continue;
        image.base[offset + i] ^= 1;
        expectMissing(image.scan());
        image.base[offset + i] ^= 1;
    }

    image.setSection(0, image.page, image.page);
    image.protect(2 * image.page, image.page, PAGE_NOACCESS);
    expectFound(image.scan(), image, offset); // Include the final legal start without reading the next page.
    image.base[offset] = 0;
    for (std::size_t i = 0; i < length - 1; ++i)
        image.base[offset + 1 + i] = static_cast<std::uint8_t>(
            blip::kProgramLocator[i] == -1 ? 0xa0 + i : blip::kProgramLocator[i]);
    image.place(image.page + 31, blip::kGuard);
    expectFound(image.scan(blip::kGuard), image, image.page + 31);
    expectMissing(image.scan());
}

void testMalformedHeaders() {
    expectInvalid(blip::memory::findImagePattern(nullptr, blip::kProgramLocator.data(), blip::kProgramLocator.size()));
    {
        Image image;
        const auto module = reinterpret_cast<HMODULE>(image.base);
        expectInvalid(blip::memory::findImagePattern(module, nullptr, 1));
        expectInvalid(blip::memory::findImagePattern(module, blip::kProgramLocator.data(), 0));
        expectInvalid(image.scan(std::array<int, 1>{-2}));
        expectInvalid(image.scan(std::array<int, 1>{256}));
        image.protect(0, image.page, PAGE_NOACCESS);
        expectInvalid(image.scan());
    }
    {
        Image image;
        image.protect(0, image.page, PAGE_READWRITE | PAGE_GUARD);
        expectInvalid(image.scan());
        assert((image.protection(0) & PAGE_GUARD) != 0);
    }
    {
        Image image;
        auto* tail = image.base + image.size - sizeof(IMAGE_DOS_HEADER) / 2;
        const WORD magic = IMAGE_DOS_SIGNATURE;
        std::memcpy(tail, &magic, sizeof(magic));
        expectInvalid(blip::memory::findImagePattern(reinterpret_cast<HMODULE>(tail),
            blip::kProgramLocator.data(), blip::kProgramLocator.size()));
    }

    // Each malformed image starts fresh, so one validation failure cannot mask another.
    for (unsigned test = 0; test < 18; ++test) {
        Image image;
        auto& dos = *reinterpret_cast<IMAGE_DOS_HEADER*>(image.base);
        auto& nt = image.nt();
        switch (test) {
        case 0: dos.e_magic = 0; break;
        case 1: dos.e_lfanew = -1; break;
        case 2: dos.e_lfanew = (std::numeric_limits<LONG>::max)(); break;
        case 3: nt.Signature = 0; break;
        case 4: nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386; break;
        case 5: nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; break;
        case 6: nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64) - 1; break;
        case 7: nt.FileHeader.NumberOfSections = 0; break;
        case 8: nt.FileHeader.NumberOfSections = (std::numeric_limits<WORD>::max)(); break;
        case 9: nt.OptionalHeader.SizeOfImage = 0; break;
        case 10: nt.OptionalHeader.SizeOfImage = sizeof(IMAGE_DOS_HEADER); break;
        case 11: nt.OptionalHeader.SizeOfHeaders = 0; break;
        case 12: nt.OptionalHeader.SizeOfHeaders = sizeof(IMAGE_DOS_HEADER); break;
        case 13: nt.OptionalHeader.SizeOfHeaders = static_cast<DWORD>(image.size + image.page); break;
        case 14:
            dos.e_lfanew = static_cast<LONG>(image.size - sizeof(DWORD));
            std::memcpy(image.base + dos.e_lfanew, &nt.Signature, sizeof(DWORD));
            break;
        case 15: {
            const auto offset = image.page - sizeof(DWORD) - sizeof(IMAGE_FILE_HEADER);
            std::memcpy(image.base + offset, &nt, sizeof(nt));
            dos.e_lfanew = static_cast<LONG>(offset);
            image.protect(image.page, image.page, PAGE_NOACCESS);
            break;
        }
        case 16: {
            const auto offset = image.page - sizeof(IMAGE_NT_HEADERS64);
            std::memmove(image.base + offset, &nt, sizeof(nt));
            dos.e_lfanew = static_cast<LONG>(offset);
            image.protect(image.page, image.page, PAGE_NOACCESS); // The section table is inaccessible.
            break;
        }
        case 17: nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(image.size + image.page); break;
        }
        expectInvalid(image.scan());
    }
}

void testMalformedSections() {
    for (unsigned test = 0; test < 5; ++test) {
        Image image;
        auto& section = image.section();
        switch (test) {
        case 0: section.VirtualAddress = static_cast<DWORD>(image.size); break;
        case 1: section.Misc.VirtualSize = static_cast<DWORD>(image.size); break;
        case 2: section.VirtualAddress = 0xfffffff0u; section.Misc.VirtualSize = 0x100; break;
        case 3: section.Misc.VirtualSize = 0xffffffffu; break;
        case 4: section.VirtualAddress = 0; break; // A section cannot overlap PE headers.
        }
        expectInvalid(image.scan());
    }
}

void testAccessibleAndRead() {
    Image image;
    auto* source = image.base + 2 * image.page - 16;
    std::array<std::uint8_t, 32> expected{};
    for (std::size_t i = 0; i < expected.size(); ++i)
        source[i] = expected[i] = static_cast<std::uint8_t>(i + 1);
    image.protect(2 * image.page, image.page, PAGE_READONLY);
    image.protect(3 * image.page, image.page, PAGE_EXECUTE_READ);
    assert(blip::memory::accessible(image.base + image.page, 3 * image.page));
    assert(!blip::memory::accessible(image.base + image.page, 3 * image.page, true));
    assert(blip::memory::accessible(source, 16, true));
    assert(!blip::memory::accessible(source, 17, true));
    std::array<std::uint8_t, 32> copied{};
    assert(blip::memory::read(source, copied.data(), copied.size()));
    assert(copied == expected);

    auto* destination = image.base + 6 * image.page - 16;
    image.protect(6 * image.page, image.page, PAGE_EXECUTE_READWRITE);
    assert(blip::memory::accessible(destination, copied.size(), true));
    assert(blip::memory::read(source, destination, copied.size()));
    assert(std::memcmp(destination, expected.data(), expected.size()) == 0);
    assert(blip::memory::read(image.base + image.page, image.base + 5 * image.page, 3 * image.page));
    assert(std::memcmp(image.base + image.page, image.base + 5 * image.page, 3 * image.page) == 0);
    assert(!blip::memory::read(copied.data(), source, copied.size()));
    assert(!blip::memory::accessible(nullptr, 1));
    assert(!blip::memory::accessible(source, 0));
    assert(!blip::memory::read(nullptr, copied.data(), copied.size()));
    assert(!blip::memory::read(source, nullptr, copied.size()));
    assert(!blip::memory::read(source, copied.data(), 0));
    const auto* overflow = reinterpret_cast<const void*>((std::numeric_limits<std::uintptr_t>::max)() - 3);
    assert(!blip::memory::accessible(overflow, 8));
    assert(!blip::memory::read(overflow, copied.data(), 8));
    assert(!blip::memory::read(source, const_cast<void*>(overflow), 8));

    for (const DWORD protection : {DWORD(PAGE_NOACCESS), DWORD(PAGE_READWRITE | PAGE_GUARD), DWORD(PAGE_EXECUTE)}) {
        image.protect(2 * image.page, image.page, protection);
        assert(!blip::memory::accessible(source, copied.size()));
        assert(!blip::memory::accessible(source, copied.size(), true));
        assert(!blip::memory::read(source, copied.data(), copied.size()));
        assert(!blip::memory::read(copied.data(), source, copied.size()));
        assert(image.protection(2 * image.page) == protection);
    }
    const BOOL decommitted = VirtualFree(image.base + 2 * image.page, image.page, MEM_DECOMMIT);
    assert(decommitted != FALSE);
    assert(!blip::memory::accessible(source, copied.size()));
    assert(!blip::memory::read(source, copied.data(), copied.size()));
}

template<std::size_t N>
void placeLocator(Image& image, std::size_t offset, const std::array<int, N>& pattern,
                  std::int64_t arrayOffset) {
    image.place(offset, pattern);
    const auto delta = arrayOffset - 0xd8 - static_cast<std::int64_t>(offset) - 7;
    assert(delta >= (std::numeric_limits<std::int32_t>::min)() &&
           delta <= (std::numeric_limits<std::int32_t>::max)());
    const auto displacement = static_cast<std::int32_t>(delta);
    std::memcpy(image.base + offset + 3, &displacement, sizeof(displacement));
}

void testProgramLocators() {
    for (unsigned test = 0; test < 13; ++test) {
        Image image;
        const auto original = 4 * image.page + 32;
        const auto alternative = original + 128;
        const auto array = 2 * image.page; // Negative RIP displacement, full array within the image.
        if (test != 0 && test != 2 && test != 7)
            placeLocator(image, original, blip::kProgramLocator, array);
        if (test != 0 && test != 1 && test != 8)
            placeLocator(image, alternative, blip::kProgramLocatorScrDbg,
                         test == 4 ? array + 8 : array);
        if (test == 5 || test == 8)
            placeLocator(image, original + 256, blip::kProgramLocator, array);
        if (test == 6 || test == 7)
            placeLocator(image, alternative + 256, blip::kProgramLocatorScrDbg, array);
        if (test == 9)
            placeLocator(image, original, blip::kProgramLocator, -1);
        if (test == 10) image.nt().Signature = 0;
        if (test == 11)
            placeLocator(image, alternative, blip::kProgramLocatorScrDbg, image.size - 8);
        if (test == 12)
            placeLocator(image, alternative, blip::kProgramLocatorScrDbg, 0xd7);
        const auto result = blip::findProgramArray(reinterpret_cast<HMODULE>(image.base));
        const auto expected = test == 0 ? ScanStatus::Missing :
            test <= 3 ? ScanStatus::Found :
            test >= 5 && test <= 8 ? ScanStatus::Ambiguous : ScanStatus::Invalid;
        assert(result.status == expected);
        if (expected == ScanStatus::Found) {
            assert(reinterpret_cast<const std::uint8_t*>(result.programs) == image.base + array);
            std::size_t offset = 0;
            assert(blip::patchController(result.programs, blip::kDefaultLimit, offset) ==
                   blip::ScriptResult::Waiting);
            testLocatedScript(result.programs);
            image.protect(array, image.page, PAGE_NOACCESS);
            assert(blip::patchController(result.programs, blip::kDefaultLimit, offset) ==
                   blip::ScriptResult::Transient);
        } else {
            assert(result.programs == nullptr);
        }
    }
    std::puts("program locators: missing, original-only, scrDbg-only, agreement, conflict, ambiguity, invalid RIP/image, array reads passed");
}

void testLegacyLocators() {
    // Exercise Legacy alone and every Enhanced/Legacy combination through production discovery.
    for (unsigned mask = 4; mask < 8; ++mask) {
        for (unsigned test = 0; test < 12; ++test) {
            const auto selected = test >= 1 && test <= 6 ? (test - 1) % 3 : 2;
            if (test >= 1 && test <= 6 && !(mask & (1u << selected))) continue;
            if (test >= 4 && test <= 6 && mask == 4) continue; // No second locator to disagree.
            Image image;
            const auto array = 2 * image.page;
            auto place = [&](unsigned locator, std::size_t extra, std::int64_t target) {
                const auto at = 4 * image.page + 32 + 128 * locator + extra;
                switch (locator) {
                case 0: placeLocator(image, at, blip::kProgramLocator, target); break;
                case 1: placeLocator(image, at, blip::kProgramLocatorScrDbg, target); break;
                case 2: placeLocator(image, at, blip::kProgramLocatorLegacy, target); break;
                }
            };
            for (unsigned locator = 0; locator < 3; ++locator)
                if (mask & (1u << locator)) place(locator, 0, array);
            if (test >= 1 && test <= 3) place(selected, 512, array);
            if (test >= 4 && test <= 6) place(selected, 0, array + 8);
            if (test == 7) place(2, 0, -1);
            if (test == 8) place(2, 0, 0xd7);
            if (test == 9) place(2, 0, image.size - 8);
            if (test == 10) place(2, 0, (std::numeric_limits<std::int32_t>::max)());
            if (test == 11) image.nt().Signature = 0;
            const auto result = blip::findProgramArray(reinterpret_cast<HMODULE>(image.base));
            const auto expected = test == 0 ? ScanStatus::Found :
                test <= 3 ? ScanStatus::Ambiguous : ScanStatus::Invalid;
            assert(result.status == expected);
            if (test == 0) {
                assert(result.original.status == (mask & 1 ? ScanStatus::Found : ScanStatus::Missing));
                assert(result.scrDbg.status == (mask & 2 ? ScanStatus::Found : ScanStatus::Missing));
                assert(result.legacy.status == ScanStatus::Found);
                assert(reinterpret_cast<const std::uint8_t*>(result.programs) == image.base + array);
                testLocatedScript(result.programs);
                image.protect(array, image.page, PAGE_NOACCESS);
                std::size_t offset = 123;
                assert(blip::patchController(result.programs, 1900, offset) == blip::ScriptResult::Transient);
                assert(offset == 123);
            } else {
                assert(result.programs == nullptr);
            }
        }
    }
    std::puts("Legacy locators: Legacy-only, all Enhanced agreements/conflicts, ambiguity without fallback, signed RIP/image rejection and script pipeline passed");
}

void testCapturedImage(const char* path) {
    // A captured loaded image already stores sections at their RVAs. Never execute it.
    auto* file = std::fopen(path, "rb");
    assert(file);
    assert(std::fseek(file, 0, SEEK_END) == 0);
    const auto length = std::ftell(file);
    assert(length >= static_cast<long>(sizeof(IMAGE_DOS_HEADER)));
    assert(std::fseek(file, 0, SEEK_SET) == 0);
    auto* base = static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, static_cast<std::size_t>(length), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    assert(base);
    assert(std::fread(base, 1, static_cast<std::size_t>(length), file) == static_cast<std::size_t>(length));
    assert(std::fclose(file) == 0);
    const auto module = reinterpret_cast<HMODULE>(base);
    auto result = blip::findProgramArray(module);
    assert(result.status == ScanStatus::Found);
    assert(result.original.status == ScanStatus::Found && result.scrDbg.status == ScanStatus::Found);
    assert(result.legacy.status == ScanStatus::Missing); // No spurious Legacy match in the real Enhanced image.
    assert(result.original.match - base == 0x91c048);
    assert(result.scrDbg.match - base == 0x91bc09);
    assert(reinterpret_cast<const std::uint8_t*>(result.programs) - base == 0x3ed1000);
    std::array<const blip::ScriptProgram*, blip::kProgramSlots> slots;
    assert(blip::memory::read(result.programs, slots.data(), sizeof(slots)));
    const auto* programs = result.programs;
    const auto original = static_cast<std::size_t>(result.original.match - base);
    const auto alternative = static_cast<std::size_t>(result.scrDbg.match - base);
    const auto originalByte = base[original];
    const auto alternativeByte = base[alternative];
    base[original] = 0;
    result = blip::findProgramArray(module);
    assert(result.status == ScanStatus::Found && result.programs == programs);
    assert(result.original.status == ScanStatus::Missing && result.scrDbg.status == ScanStatus::Found);
    base[original] = originalByte;
    base[alternative] = 0;
    result = blip::findProgramArray(module);
    assert(result.status == ScanStatus::Found && result.programs == programs);
    assert(result.original.status == ScanStatus::Found && result.scrDbg.status == ScanStatus::Missing);
    base[original] = 0;
    result = blip::findProgramArray(module);
    assert(result.status == ScanStatus::Missing && result.programs == nullptr);
    base[original] = originalByte;
    base[alternative] = alternativeByte;
    assert(VirtualFree(base, 0, MEM_RELEASE));
    std::puts("captured PE: original RVA 0x91C048, scrDbg RVA 0x91BC09, registry RVA 0x3ED0F28, array RVA 0x3ED1000; agreement and both fallback directions passed");
}

} // namespace

void testScripts();

int main(int argc, char** argv) {
    testSplitReadableSection();
    testHolesAndGuards();
    testUniquenessAndSections();
    testRangeBoundsAndWildcards();
    testMalformedHeaders();
    testMalformedSections();
    testAccessibleAndRead();
    testProgramLocators();
    testLegacyLocators();
    if (argc == 2) testCapturedImage(argv[1]);
    testScripts();
    std::puts("memory tests passed");
}

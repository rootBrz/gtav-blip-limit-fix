#include "memory.hpp"

#include <cstring>

namespace blip::memory {
namespace {

bool rangeEnd(std::uintptr_t address, std::size_t size, std::uintptr_t& end) {
    if (!address || !size || size > ~std::uintptr_t{0} - address) return false;
    end = address + size;
    return true;
}

bool queryRegion(std::uintptr_t address, MEMORY_BASIC_INFORMATION& info,
                 std::uintptr_t& end) {
    if (VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info)) != sizeof(info))
        return false;
    const auto start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    return start <= address && rangeEnd(start, info.RegionSize, end) && address < end;
}

bool readable(const MEMORY_BASIC_INFORMATION& info, bool writable = false) {
    if (info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    const auto protection = info.Protect & 0xff;
    const bool canWrite = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
    const bool canRead = canWrite || protection == PAGE_READONLY || protection == PAGE_EXECUTE_READ;
    return canRead && (!writable || canWrite);
}

bool sameAllocation(std::uintptr_t base, std::uintptr_t address, std::size_t size) {
    std::uintptr_t end;
    if (!rangeEnd(address, size, end)) return false;
    while (address < end) {
        MEMORY_BASIC_INFORMATION info;
        std::uintptr_t regionEnd;
        if (!queryRegion(address, info, regionEnd) ||
            reinterpret_cast<std::uintptr_t>(info.AllocationBase) != base) return false;
        address = regionEnd < end ? regionEnd : end;
    }
    return true;
}

bool copyHeader(std::uintptr_t base, std::uintptr_t address, void* destination, std::size_t size) {
    if (!sameAllocation(base, address, size) ||
        !accessible(reinterpret_cast<const void*>(address), size)) return false;
    std::memcpy(destination, reinterpret_cast<const void*>(address), size);
    return true;
}

int memoryException(DWORD code) {
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
        code == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

void scanRange(std::uintptr_t start, std::size_t size,
               const ImagePattern* patterns, std::size_t count) {
    std::size_t minimumSize = size;
    std::size_t active = 0;
    for (std::size_t p = 0; p < count; ++p) {
        const auto& pattern = patterns[p];
        auto& result = pattern.result;
        if (result.status == ScanStatus::Invalid) continue;
        ++result.readableRanges;
        result.scannedBytes += size;
        if (result.status == ScanStatus::Ambiguous || size < pattern.size) continue;
        if (pattern.size < minimumSize) minimumSize = pattern.size;
        ++active;
    }
    if (!active) return;
    const auto bytes = reinterpret_cast<const std::uint8_t*>(start);
    for (std::size_t i = 0; i <= size - minimumSize; ++i) {
        for (std::size_t p = 0; p < count; ++p) {
            const auto& pattern = patterns[p];
            auto& result = pattern.result;
            if (result.status == ScanStatus::Invalid || result.status == ScanStatus::Ambiguous ||
                pattern.size > size - i) continue;
            std::size_t j = 0;
            for (; j < pattern.size; ++j)
                if (pattern.bytes[j] != -1 && bytes[i + j] != pattern.bytes[j]) break;
            if (j != pattern.size) continue;
            if (result.status == ScanStatus::Missing) {
                result.status = ScanStatus::Found;
                result.match = bytes + i;
            } else {
                result.status = ScanStatus::Ambiguous;
                result.match = nullptr;
                if (!--active) return;
            }
        }
    }
}

void scanImage(HMODULE module, const ImagePattern* patterns, std::size_t count) {
    if (!module) return;

    const auto base = reinterpret_cast<std::uintptr_t>(module);
    IMAGE_DOS_HEADER dos;
    if (!copyHeader(base, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < static_cast<LONG>(sizeof(dos))) return;
    std::uintptr_t ntAddress;
    if (!rangeEnd(base, static_cast<std::size_t>(dos.e_lfanew), ntAddress)) return;
    IMAGE_NT_HEADERS64 nt;
    if (!copyHeader(base, ntAddress, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > 96) return;

    const std::size_t imageSize = nt.OptionalHeader.SizeOfImage;
    const std::size_t headerSize = nt.OptionalHeader.SizeOfHeaders;
    const std::size_t sectionOffset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    const std::size_t sectionBytes = nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!headerSize || headerSize > imageSize || sectionOffset > headerSize ||
        sectionBytes > headerSize - sectionOffset || !sameAllocation(base, base, imageSize)) return;
    IMAGE_SECTION_HEADER sections[96];
    if (!copyHeader(base, base + sectionOffset, sections, sectionBytes)) return;

    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        const std::size_t size = section.Misc.VirtualSize;
        if (!size) continue;
        if (section.VirtualAddress < headerSize || section.VirtualAddress >= imageSize ||
            size > imageSize - section.VirtualAddress) return;
        // ponytail: the Windows 96-section limit bounds this overlap check.
        for (unsigned j = 0; j < i; ++j) {
            const auto& previous = sections[j];
            if (previous.Misc.VirtualSize &&
                section.VirtualAddress < static_cast<std::size_t>(previous.VirtualAddress) +
                    previous.Misc.VirtualSize &&
                previous.VirtualAddress < section.VirtualAddress + size) return;
        }
    }

    bool anyPattern = false;
    for (std::size_t p = 0; p < count; ++p) {
        const auto& pattern = patterns[p];
        if (!pattern.bytes || !pattern.size ||
            pattern.size > ~std::size_t{0} / sizeof(*pattern.bytes) ||
            !accessible(pattern.bytes, pattern.size * sizeof(*pattern.bytes))) continue;
        std::size_t j = 0;
        for (; j < pattern.size; ++j)
            if (pattern.bytes[j] < -1 || pattern.bytes[j] > 255) break;
        if (j != pattern.size) continue;
        pattern.result.imageSize = imageSize;
        pattern.result.status = ScanStatus::Missing;
        anyPattern = true;
    }
    if (!anyPattern) return;
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) || !section.Misc.VirtualSize) continue;
        auto address = base + section.VirtualAddress;
        const auto end = address + section.Misc.VirtualSize;
        std::uintptr_t readableStart = 0;
        while (address < end) {
            MEMORY_BASIC_INFORMATION info;
            std::uintptr_t regionEnd;
            if (!queryRegion(address, info, regionEnd) ||
                reinterpret_cast<std::uintptr_t>(info.AllocationBase) != base) {
                for (std::size_t p = 0; p < count; ++p) {
                    patterns[p].result.status = ScanStatus::Fault;
                    patterns[p].result.match = nullptr;
                }
                return;
            }
            if (regionEnd > end) regionEnd = end;
            if (readable(info)) {
                if (!readableStart) readableStart = address;
            } else {
                if (readableStart) {
                    scanRange(readableStart, address - readableStart, patterns, count);
                    readableStart = 0;
                }
                for (std::size_t p = 0; p < count; ++p)
                    if (patterns[p].result.status != ScanStatus::Invalid)
                        patterns[p].result.skippedBytes += regionEnd - address;
            }
            address = regionEnd;
        }
        if (readableStart)
            scanRange(readableStart, end - readableStart, patterns, count);
    }
}

} // namespace

bool accessible(const void* pointer, std::size_t size, bool writable) {
    auto address = reinterpret_cast<std::uintptr_t>(pointer);
    std::uintptr_t end;
    if (!rangeEnd(address, size, end)) return false;
    while (address < end) {
        MEMORY_BASIC_INFORMATION info;
        std::uintptr_t regionEnd;
        if (!queryRegion(address, info, regionEnd) || !readable(info, writable)) return false;
        address = regionEnd < end ? regionEnd : end;
    }
    return true;
}

bool read(const void* source, void* destination, std::size_t size) {
    if (!accessible(source, size) || !accessible(destination, size, true)) return false;
    __try {
        std::memcpy(destination, source, size);
        return true;
    } __except (memoryException(GetExceptionCode())) {
        return false;
    }
}

ImageScan findImagePattern(HMODULE module, const int* pattern, std::size_t patternSize) {
    ImageScan result;
    const ImagePattern query{pattern, patternSize, result};
    findImagePatterns(module, &query, 1);
    return result;
}

void findImagePatterns(HMODULE module, const ImagePattern* patterns, std::size_t count) {
    for (std::size_t p = 0; p < count; ++p) {
        patterns[p].result = {};
        patterns[p].result.status = ScanStatus::Invalid;
    }
    __try {
        scanImage(module, patterns, count);
    } __except (memoryException(GetExceptionCode())) {
        for (std::size_t p = 0; p < count; ++p) {
            patterns[p].result.status = ScanStatus::Fault;
            patterns[p].result.match = nullptr;
        }
    }
}

} // namespace blip::memory

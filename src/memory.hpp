#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace blip::memory {

enum class ScanStatus { Missing, Found, Ambiguous, Invalid, Fault };

struct ImageScan {
    ScanStatus status = ScanStatus::Missing;
    const std::uint8_t* match = nullptr;
    // Set only after validating headers, sections, and the complete image allocation.
    std::size_t imageSize = 0;
    // Executable bytes classified as readable or skipped; not individual byte loads.
    std::size_t scannedBytes = 0;
    std::size_t skippedBytes = 0;
    // Adjacent readable protections merge within each section, never across holes.
    std::size_t readableRanges = 0;
};

bool accessible(const void* address, std::size_t size, bool writable = false);
// Invalid ranges fail without access; expected memory faults return false.
bool read(const void* source, void* destination, std::size_t size);
// Only Found supplies a match. Fault fails closed; its counters may be partial.
ImageScan findImagePattern(HMODULE module, const int* pattern, std::size_t patternSize);

} // namespace blip::memory

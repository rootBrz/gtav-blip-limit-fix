#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace blip {

inline constexpr std::uint16_t kDefaultLimit = 1900;
inline constexpr std::uint16_t kMinLimit = 150;
inline constexpr std::uint16_t kMaxLimit = 1997;
inline constexpr std::uint32_t kScriptHash = 0x80cfe974; // joaat("blip_controller")
inline constexpr std::size_t kPageSize = 0x4000;
inline constexpr std::size_t kProgramSlots = 176;

// Native(0 args, 1 result), count predicate, JZ past WAIT(2000), jump back.
inline constexpr std::array<int, 21> kGuard = {
    0x2c, 0x01, -1, -1, 0x25, 0x96, 0x0c, 0x06,
    0x56, 0x0a, 0x00, 0x43, 0xd0, 0x07, 0x2c, 0x04, -1, -1, 0x55, 0xeb, 0xff
};
inline constexpr std::array<int, 25> kProgramLocator = {
    0x48, 0x8d, 0x05, -1, -1, -1, -1,
    0x0f, 0xb6, 0x4c, 0x02, 0x01, 0x48, 0x85, 0xc9, 0x74, -1,
    0x48, 0x39, 0xb4, 0xc8, 0xd8, 0x00, 0x00, 0x00
};

// PUSH_CONST_S16 limit; IGE leaves one boolean for the unchanged JZ.
constexpr std::array<std::uint8_t, 4> encodeLimit(std::uint16_t limit) {
    return {0x43, static_cast<std::uint8_t>(limit & 0xff),
            static_cast<std::uint8_t>(limit >> 8), 0x0b};
}

inline bool parseLimit(std::wstring_view text, std::uint16_t& value) {
    constexpr std::wstring_view whitespace = L" \t\r\n\f\v";
    const auto first = text.find_first_not_of(whitespace);
    if (first == std::wstring_view::npos) return false;
    const auto last = text.find_last_not_of(whitespace);
    unsigned parsed = 0;
    for (std::size_t i = first; i <= last; ++i) {
        if (text[i] < L'0' || text[i] > L'9') return false;
        const unsigned digit = static_cast<unsigned>(text[i] - L'0');
        if (parsed > (kMaxLimit - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed < kMinLimit) return false;
    value = static_cast<std::uint16_t>(parsed);
    return true;
}

// Negative pattern entries match any byte. Return size if absent, size+1 if ambiguous.
template<class ByteAt, std::size_t N>
std::size_t uniqueMatch(ByteAt byteAt, std::size_t size, const std::array<int, N>& pattern) {
    std::size_t found = size;
    if (N > size) return size;
    for (std::size_t i = 0; i <= size - N; ++i) {
        std::size_t j = 0;
        for (; j < N; ++j)
            if (pattern[j] >= 0 && byteAt(i + j) != pattern[j]) break;
        if (j != N) continue;
        if (found != size) return size + 1;
        found = i;
    }
    return found;
}

} // namespace blip

#include "guard.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string_view>
#include <vector>

// Execute the four-byte VM expression, including its stack effects.
static bool evaluate(const std::array<std::uint8_t, 4>& code, int count) {
    int stack[3] = {count};
    std::size_t depth = 1;
    std::size_t pc = 0;
    while (pc < code.size()) {
        switch (code[pc++]) {
        case 0x25:
            assert(pc < code.size() && depth < 3);
            stack[depth++] = code[pc++];
            break;
        case 0x43:
            assert(pc + 1 < code.size() && depth < 3);
            stack[depth++] = static_cast<std::int16_t>(code[pc] | (code[pc + 1] << 8));
            pc += 2;
            break;
        case 0x0c:
            assert(depth >= 2);
            stack[depth - 2] = stack[depth - 2] < stack[depth - 1];
            --depth;
            break;
        case 0x06:
            assert(depth >= 1);
            stack[depth - 1] = !stack[depth - 1];
            break;
        case 0x0b:
            assert(depth >= 2);
            stack[depth - 2] = stack[depth - 2] >= stack[depth - 1];
            --depth;
            break;
        default:
            assert(false);
        }
    }
    assert(pc == code.size() && depth == 1);
    return stack[0] != 0; // true means WAIT; false means create the mission blip.
}

template<std::size_t N>
static std::array<std::uint8_t, N> materialize(const std::array<int, N>& pattern) {
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i)
        bytes[i] = static_cast<std::uint8_t>(pattern[i] < 0 ? 0xa0 + i : pattern[i]);
    return bytes;
}

static void testLimits() {
    constexpr std::array<std::uint16_t, 3> limits = {150, 1900, 1997};
    constexpr std::array<std::wstring_view, 3> text = {L"150", L"1900", L"1997"};
    constexpr std::array<std::uint8_t, 4> original = {0x25, 0x96, 0x0c, 0x06};
    for (int count = 0; count <= 2000; ++count)
        assert(evaluate(original, count) == (count >= 150));

    for (std::size_t i = 0; i < limits.size(); ++i) {
        std::uint16_t parsed = 0;
        assert(blip::parseLimit(text[i], parsed));
        assert(parsed == limits[i]);
        const auto code = blip::encodeLimit(parsed);
        for (int count = 0; count <= 2000; ++count)
            assert(evaluate(code, count) == (count >= parsed));
        assert(!evaluate(code, parsed - 1));
        assert(evaluate(code, parsed));
        assert(evaluate(code, parsed + 1));

    }

    for (const auto invalid : {
             L"149", L"1998", L"2000", L"", L" \t\r\n\f\v", L"-150", L"+150",
             L"abc", L"0x76c", L"1900.0", L"1 900", L"1900junk", L"1900 junk",
             L"65536", L"4294967296", L"184467440737095516160000000000000000000"}) {
        std::uint16_t parsed = 12345;
        assert(!blip::parseLimit(invalid, parsed));
        assert(parsed == 12345);
    }
    std::uint16_t parsed = 0;
    assert(blip::parseLimit(L" \t\r\n\f\v1900 \t\r\n\f\v", parsed));
    assert(parsed == 1900);
    assert(blip::parseLimit(L"000150", parsed));
    assert(parsed == 150);
    constexpr wchar_t embeddedNull[] = {L'1', L'9', L'0', L'0', L'\0', L'1'};
    parsed = 12345;
    assert(!blip::parseLimit(std::wstring_view(embeddedNull, 6), parsed));
    assert(parsed == 12345);
}

template<std::size_t N>
static void testMatcher(const std::array<int, N>& pattern) {
    const auto bytes = materialize(pattern);
    std::vector<std::uint8_t> data(N * 2 + 7, 0);
    auto match = [&](std::size_t size) {
        return blip::uniqueMatch([&](std::size_t i) {
            assert(i < size && i < data.size());
            return data[i];
        }, size, pattern);
    };
    assert(match(0) == 0);
    std::copy(bytes.begin(), bytes.end(), data.begin());
    assert(match(N - 1) == N - 1); // Truncated match must not read past size.
    assert(match(N) == 0);
    std::fill(data.begin(), data.end(), 0);
    std::copy(bytes.begin(), bytes.end(), data.begin() + 7);
    assert(match(N + 7) == 7); // Last possible offset is included.
    std::copy(bytes.begin(), bytes.end(), data.begin() + N + 7);
    assert(match(data.size()) == data.size() + 1); // Ambiguity fails closed.
    data[7] ^= 1;
    assert(match(data.size()) == N + 7);
    data[N + 7] ^= 1;
    assert(match(data.size()) == data.size());
    std::copy(bytes.begin(), bytes.end(), data.begin());
    for (std::size_t i = 0; i < N; ++i)
        if (pattern[i] < 0) data[i] ^= 0xff;
    assert(match(N) == 0); // Native indices/displacements remain wildcards.
}


static void testPagedMatcher() {
    constexpr auto pageSize = blip::kPageSize;
    const auto bytes = materialize(blip::kProgramLocator);
    const std::size_t size = 2 * pageSize + bytes.size() - 3;
    std::array<std::vector<std::uint8_t>, 3> pages = {
        std::vector<std::uint8_t>(pageSize), std::vector<std::uint8_t>(pageSize),
        std::vector<std::uint8_t>(size - 2 * pageSize)
    };
    auto byteAt = [&](std::size_t i) -> std::uint8_t& {
        assert(i < size);
        return pages[i / pageSize][i % pageSize];
    };
    auto match = [&] { return blip::uniqueMatch(byteAt, size, blip::kProgramLocator); };
    const std::size_t first = pageSize - 6;
    for (std::size_t i = 0; i < bytes.size(); ++i) byteAt(first + i) = bytes[i];
    assert(match() == first);
    const std::size_t last = size - bytes.size();
    for (std::size_t i = 0; i < bytes.size(); ++i) byteAt(last + i) = bytes[i];
    assert(match() == size + 1);
    byteAt(first) ^= 1;
    assert(match() == last); // Last offset spans separately allocated pages.
    byteAt(last) ^= 1;
    assert(match() == size);
}

template<std::size_t N>
static void scanFile(const char* path, const std::array<int, N>& pattern) {
    std::ifstream input(path, std::ios::binary);
    assert(input);
    const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
    assert(!input.bad());
    const auto offset = blip::uniqueMatch([&](std::size_t i) { return bytes[i]; },
                                        bytes.size(), pattern);
    if (offset < bytes.size())
        std::printf("%s: unique match +0x%zX\n", path, offset);
    else
        std::printf("%s: %s\n", path, offset == bytes.size() ? "no match" : "ambiguous matches");
    assert(offset < bytes.size());
}

static void scanGuardFile(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input);
    const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
    assert(!input.bad());
    blip::GuardMatch match;
    const auto status = blip::findSemanticGuard([&](std::size_t i) { return bytes[i]; },
        bytes.size(), 55, blip::kDefaultLimit, match); // Captured script has 55 natives.
    assert(status == blip::GuardStatus::Found && !match.configured);
    std::printf("%s: semantic guard +0x%zX, predicate +0x%zX (%zu bytes)\n",
                path, match.windowOffset, match.patchOffset, match.patchSize);
}

int main(int argc, char** argv) {
    assert(argc <= 3);
    testLimits();
    testMatcher(blip::kProgramLocator);
    testMatcher(blip::kProgramLocatorScrDbg);
    testMatcher(blip::kProgramLocatorLegacy);
    testPagedMatcher();
    if (argc >= 2) scanFile(argv[1], blip::kProgramLocator);
    if (argc >= 3) scanGuardFile(argv[2]);
    std::puts("PASS: limit parsing/encoding, VM predicate stack balance and native locator scanners");
}

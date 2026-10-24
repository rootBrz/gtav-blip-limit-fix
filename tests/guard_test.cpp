#include "guard.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <vector>

using Bytes = std::vector<std::uint8_t>;
using blip::GuardMatch;
using blip::GuardStatus;

enum class Predicate { NotLess, GreaterEqual, Less, FusedGe, FusedLt };

struct Fixture {
    Bytes code;
    std::size_t count = 0;
    std::size_t constant = 0;
    std::size_t compare = 0;
    std::size_t condition = 0;
    std::size_t waitConstant = 0;
    std::size_t waitNative = 0;
    std::size_t back = 0;
    std::size_t exit = 0;
};

static void integer(Bytes& code, std::uint8_t op, std::uint32_t value) {
    code.push_back(op);
    const unsigned width = op == 0x25 ? 1 : op == 0x43 ? 2 : op == 0x64 ? 3 : 4;
    for (unsigned i = 0; i < width; ++i) code.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}

static std::size_t jump(Bytes& code, std::uint8_t op) {
    const auto pc = code.size();
    code.insert(code.end(), {op, 0, 0});
    return pc;
}

static void destination(Bytes& code, std::size_t pc, std::size_t target) {
    const auto delta = static_cast<int>(target) - static_cast<int>(pc + 3);
    assert(delta >= -32768 && delta <= 32767);
    const auto raw = static_cast<std::uint16_t>(delta);
    code[pc + 1] = static_cast<std::uint8_t>(raw);
    code[pc + 2] = static_cast<std::uint8_t>(raw >> 8);
}

static Fixture fixture(std::uint8_t constantOp = 0x25,
                       Predicate predicate = Predicate::NotLess,
                       std::size_t padding = 0, bool backwardBody = false,
                       std::uint16_t threshold = 150) {
    Fixture f;
    auto nops = [&] { f.code.insert(f.code.end(), padding, 0); };
    auto wait = [&] {
        f.waitConstant = f.code.size();
        integer(f.code, 0x43, 2000);
        nops();
        f.waitNative = f.code.size();
        f.code.insert(f.code.end(), {0x2c, 0x04, 0x00, 0x02});
        nops();
    };
    if (backwardBody) wait();
    f.count = f.code.size();
    f.code.insert(f.code.end(), {0x2c, 0x01, 0x00, 0x01});
    nops();
    f.constant = f.code.size();
    integer(f.code, constantOp, threshold);
    nops();
    f.compare = f.code.size();
    if (predicate == Predicate::NotLess) {
        f.code.push_back(0x0c);
        nops();
        f.code.push_back(0x06);
        nops();
    } else if (predicate == Predicate::GreaterEqual || predicate == Predicate::Less) {
        f.code.push_back(predicate == Predicate::GreaterEqual ? 0x0b : 0x0c);
        nops();
    }
    const bool falseBody = predicate == Predicate::Less || predicate == Predicate::FusedLt;
    const auto op = predicate == Predicate::FusedGe ? 0x5a : predicate == Predicate::FusedLt ? 0x5b : 0x56;
    f.condition = jump(f.code, static_cast<std::uint8_t>(op));
    std::size_t bridge = 0;
    if (backwardBody) {
        assert(falseBody);
    } else {
        if (falseBody) bridge = jump(f.code, 0x55);
        nops();
        wait();
        f.back = jump(f.code, 0x55);
        destination(f.code, f.back, f.count);
    }
    nops();
    f.exit = f.code.size();
    f.code.insert(f.code.end(), {0x2e, 0x00, 0x00});
    destination(f.code, f.condition, falseBody ? f.waitConstant : f.exit);
    if (!backwardBody && falseBody) destination(f.code, bridge, f.exit);
    return f;
}

static GuardStatus match(const Bytes& code, GuardMatch& out, std::uint16_t limit = 1900,
                         std::uint32_t natives = 55) {
    return blip::findSemanticGuard([&](std::size_t pc) {
        assert(pc < code.size());
        return code[pc];
    }, code.size(), natives, limit, out);
}

// This tiny consumer executes the actual predicate and branch, not just the
// emitted bytes. True means WAIT; false means the loop's creation-side exit.
static bool waits(const Bytes& bytes, std::size_t start, int count) {
    auto byteAt = [&](std::size_t pc) { assert(pc < bytes.size()); return bytes[pc]; };
    const blip::guard_detail::Code<decltype(byteAt)> code{byteAt, bytes.size()};
    std::array<std::int64_t, 8> stack{};
    std::size_t depth = 0;
    auto pc = start;
    for (unsigned steps = 0; steps < 1024; ++steps) {
        assert(pc < bytes.size());
        const auto op = bytes[pc];
        if (op == 0) { ++pc; continue; }
        std::uint32_t value = 0;
        std::size_t next = 0;
        if (code.integer(pc, value, next)) {
            assert(depth < stack.size());
            stack[depth++] = value;
            pc = next;
            continue;
        }
        if (op == 0x2c) {
            if (bytes[pc + 1] == 0x01) {
                assert(depth < stack.size());
                stack[depth++] = count;
                pc += 4;
                continue;
            }
            assert(bytes[pc + 1] == 0x04 && depth == 1 && stack[0] == 2000);
            return true;
        }
        if (op == 0x0b || op == 0x0c || op == 0x5a || op == 0x5b) {
            assert(depth >= 2);
            const bool less = stack[depth - 2] < stack[depth - 1];
            stack[depth - 2] = (op == 0x0c || op == 0x5b) ? less : !less;
            --depth;
            if (op == 0x0b || op == 0x0c) { ++pc; continue; }
        } else if (op == 0x06) {
            assert(depth >= 1);
            stack[depth - 1] = !stack[depth - 1];
            ++pc;
            continue;
        } else if (op == 0x2e) {
            assert(depth == 0);
            return false;
        } else {
            assert(op == 0x55 || op == 0x56);
        }
        const bool take = op == 0x55 || (--depth, stack[depth] == 0);
        if (take) assert(code.target(pc, pc));
        else pc += 3;
    }
    assert(false && "consumer failed to reach WAIT or exit");
    return false;
}

static Bytes patched(const Bytes& code, const GuardMatch& found) {
    assert(found.patchOffset >= found.windowOffset);
    assert(found.patchOffset + found.patchSize <= found.windowOffset + found.windowSize);
    assert(found.windowSize <= blip::kMaxGuardBytes && found.patchSize <= blip::kMaxGuardBytes);
    assert(std::equal(found.expected.begin(), found.expected.begin() + found.windowSize,
                      code.begin() + found.windowOffset));
    auto result = code;
    std::copy_n(found.replacement.begin(), found.patchSize, result.begin() + found.patchOffset);
    assert(result.size() == code.size());
    for (std::size_t i = 0; i < code.size(); ++i)
        if (i < found.patchOffset || i >= found.patchOffset + found.patchSize) assert(result[i] == code[i]);
    return result;
}

static void testForms() {
    for (const auto constant : {0x25, 0x43, 0x64, 0x28}) {
        for (const auto predicate : {Predicate::NotLess, Predicate::GreaterEqual, Predicate::Less,
                                     Predicate::FusedGe, Predicate::FusedLt}) {
            for (const auto padding : {0u, 2u}) {
                auto f = fixture(static_cast<std::uint8_t>(constant), predicate, padding);
                GuardMatch found;
                const auto status = match(f.code, found);
                const bool shortSpan = f.condition - (f.count + 4) < 4;
                assert(status == (shortSpan ? GuardStatus::Unsupported : GuardStatus::Found));
                assert(!found.configured);
                if (shortSpan) continue;
                const auto result = patched(f.code, found);
                assert(result[f.condition + 1] == f.code[f.condition + 1]);
                assert(result[f.condition + 2] == f.code[f.condition + 2]);
                for (const int count : {0, 149, 150, 1899, 1900, 1901, 2000}) {
                    assert(waits(f.code, f.count, count) == (count >= 150));
                    assert(waits(result, f.count, count) == (count >= 1900));
                }
                GuardMatch configured;
                assert(match(result, configured) == GuardStatus::Found && configured.configured);
            }
        }
    }
    for (const auto predicate : {Predicate::Less, Predicate::FusedLt}) {
        auto f = fixture(0x28, predicate, 2, true);
        GuardMatch found;
        assert(match(f.code, found) == GuardStatus::Found);
        assert(found.windowOffset == 0);
        const auto result = patched(f.code, found);
        assert(!waits(result, f.count, 1899));
        assert(waits(result, f.count, 1900));
    }
}

static void testNarrowAndConfigured() {
    auto narrow = fixture(0x25, Predicate::GreaterEqual);
    GuardMatch found;
    assert(match(narrow.code, found) == GuardStatus::Unsupported);
    assert(match(narrow.code, found, 256) == GuardStatus::Unsupported);
    assert(match(narrow.code, found, 255) == GuardStatus::Found && !found.configured);
    const auto result = patched(narrow.code, found);
    assert(!waits(result, narrow.count, 254));
    assert(waits(result, narrow.count, 255));
    assert(match(result, found, 255) == GuardStatus::Found && found.configured);
    assert(match(narrow.code, found, 150) == GuardStatus::Found && found.configured);
    for (const auto op : {0x43, 0x64, 0x28}) {
        const auto f = fixture(static_cast<std::uint8_t>(op), Predicate::GreaterEqual, 0, false, 1900);
        assert(match(f.code, found) == GuardStatus::Found && found.configured);
    }
    // Fused U8 needs another byte for an explicit comparator even at limit 255.
    const auto fused = fixture(0x25, Predicate::FusedGe);
    assert(match(fused.code, found, 255) == GuardStatus::Unsupported);
    const auto padded = fixture(0x25, Predicate::FusedGe, 1);
    assert(match(padded.code, found, 255) == GuardStatus::Found);
    const auto paddedResult = patched(padded.code, found);
    assert(paddedResult[padded.condition] == 0x56);
    assert(!waits(paddedResult, padded.count, 254));
    assert(waits(paddedResult, padded.count, 255));
}

// Bytes copied from a real Enhanced 1.0.1158.16 blip_controller (BlipLimitFix.log, +0x3FE):
// the ceiling there is 240, not 150.
static void testObservedGameGuard() {
    const Bytes code = {
        0x2c, 0x01, 0x00, 0x0a, 0x25, 0xf0, 0x0c, 0x06, 0x56, 0x0a, 0x00,
        0x43, 0xd0, 0x07, 0x2c, 0x04, 0x00, 0x2f, 0x55, 0xeb, 0xff, 0x2e, 0x00, 0x00};
    GuardMatch found;
    assert(match(code, found) == GuardStatus::Found);
    assert(!found.configured && found.ceiling == 240);
    assert(found.patchOffset == 4 && found.patchSize == 4);
    assert(waits(code, 0, 240) && !waits(code, 0, 239));
    const auto result = patched(code, found);
    assert(!waits(result, 0, 1899) && waits(result, 0, 1900));
    assert(match(result, found) == GuardStatus::Found && found.configured && found.ceiling == 1900);
}

static void testRefusals() {
    const auto good = fixture();
    GuardMatch found;
    // Any plausible ceiling is accepted (a build or mod may differ from vanilla 150)...
    auto code = good.code;
    code[good.constant + 1] = 240;
    assert(match(code, found) == GuardStatus::Found && !found.configured && found.ceiling == 240);
    // ...but zero and values above the supported maximum are not a blip-count ceiling.
    code = good.code;
    code[good.constant + 1] = 0;
    assert(match(code, found) == GuardStatus::Missing);
    const auto huge = fixture(0x43, Predicate::NotLess, 0, false, 2000);
    assert(match(huge.code, found) == GuardStatus::Missing);
    code = good.code;
    code[good.waitConstant + 1] ^= 1;
    assert(match(code, found) == GuardStatus::Missing);
    for (const auto signature : {0x00, 0x02, 0x05}) {
        code = good.code;
        code[good.count + 1] = static_cast<std::uint8_t>(signature);
        assert(match(code, found) == GuardStatus::Missing);
    }
    code = good.code;
    code[good.waitNative + 1] = 0x05;
    assert(match(code, found) == GuardStatus::Missing);
    code = good.code;
    code[good.count + 2] = 1; // Big-endian native index, not little endian.
    assert(match(code, found) == GuardStatus::Invalid);
    code = good.code;
    code[good.waitNative + 3] = code[good.count + 3];
    assert(match(code, found) == GuardStatus::Invalid);
    assert(match(good.code, found, 1900, 2) == GuardStatus::Invalid);
    for (const auto target : {good.count + 1, good.constant, good.waitConstant}) {
        code = good.code;
        destination(code, good.back, target);
        assert(match(code, found) == GuardStatus::Missing);
    }
    for (const auto target : {good.count, good.waitConstant + 1, good.back, good.code.size()}) {
        code = good.code;
        destination(code, good.condition, target);
        assert(match(code, found) == GuardStatus::Missing);
    }
    code = good.code;
    code.push_back(0x83);
    assert(match(code, found) == GuardStatus::Invalid);
    for (const auto length : {good.count + 3, good.constant + 1, good.condition + 2,
                              good.waitNative + 3, good.code.size() - 1}) {
        code.assign(good.code.begin(), good.code.begin() + length);
        assert(match(code, found) == GuardStatus::Invalid);
    }
    const auto tooLarge = fixture(0x28, Predicate::NotLess, 40);
    assert(match(tooLarge.code, found) == GuardStatus::Missing);
    // An exit chain must not conceal re-entry, an operand target, or a cycle.
    code.assign(good.code.begin(), good.code.begin() + good.exit);
    code.push_back(0);
    const auto firstExitJump = jump(code, 0x55);
    const auto secondExitEntry = code.size();
    code.push_back(0);
    const auto secondExitJump = jump(code, 0x55);
    const auto finalExit = code.size();
    code.insert(code.end(), {0x2e, 0, 0});
    destination(code, firstExitJump, secondExitEntry);
    destination(code, secondExitJump, finalExit);
    assert(match(code, found) == GuardStatus::Found && found.windowSize == code.size());
    for (const auto target : {good.count, good.waitConstant, good.count + 1, secondExitEntry}) {
        destination(code, secondExitJump, target);
        assert(match(code, found) == GuardStatus::Missing);
    }
    // NOPs before the count are a valid loop-header target and belong in the
    // snapshot even though the native instruction follows them.
    code = {0, 0};
    code.insert(code.end(), good.code.begin(), good.code.end());
    destination(code, good.back + 2, 0);
    assert(match(code, found) == GuardStatus::Found && found.windowOffset == 0);
}

static void testInstructionBoundaries() {
    const auto good = fixture();
    GuardMatch found;
    Bytes code{0x2d, 0, 0, 0, static_cast<std::uint8_t>(good.code.size())};
    code.insert(code.end(), good.code.begin(), good.code.end());
    code.insert(code.end(), {0x2e, 0, 0});
    assert(match(code, found) == GuardStatus::Missing); // ENTER name is metadata.
    code = {0x65, 4};
    code.insert(code.end(), good.code.begin(), good.code.end());
    assert(good.code.size() == 24); // Four SWITCH entries hide the entire loop.
    code.insert(code.end(), {0x2e, 0, 0});
    assert(match(code, found) == GuardStatus::Missing);
    // A genuine NATIVE-looking prefix inside a U32 immediate must not make a
    // candidate, nor should it stop the decoder finding the real next guard.
    code = {0x28, 0x2c, 0x01, 0x00, 0x01};
    code.insert(code.end(), good.code.begin(), good.code.end());
    assert(match(code, found) == GuardStatus::Found && found.patchOffset == 9);
    const auto opposite = fixture(0x28, Predicate::Less, 2);
    code = opposite.code;
    const auto bridge = opposite.condition + 3;
    destination(code, bridge, opposite.count);
    assert(match(code, found) == GuardStatus::Missing);
    code.assign(good.code.begin(), good.code.begin() + good.exit);
    code.insert(code.end(), {0x2d, 0, 0, 0, 3, 0, 0, 0, 0x2e, 0, 0});
    destination(code, good.condition, good.exit + 5);
    assert(match(code, found) == GuardStatus::Missing); // Branch into ENTER metadata.
    code = {0x2d, 0, 0, 0};
    assert(match(code, found) == GuardStatus::Invalid);
    code = {0x65, 1, 0, 0, 0, 0, 0};
    assert(match(code, found) == GuardStatus::Invalid);
    // Representative fixed widths, plus variable ENTER/SWITCH lengths, must
    // advance over operands without treating opcode-like bytes as instructions.
    code = {0x2d, 0, 0, 0, 3, 0xff, 0xff, 0xff,
            0x65, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x34, 0xff, 0x40, 0xff, 0x43, 0xff, 0xff,
            0x5d, 0xff, 0xff, 0xff, 0x64, 0xff, 0xff, 0xff,
            0x28, 0xff, 0xff, 0xff, 0xff, 0x68, 0xff, 0x82};
    code.insert(code.end(), good.code.begin(), good.code.end());
    assert(match(code, found) == GuardStatus::Found);
}

static void testIncomingEdges() {
    const auto good = fixture();
    GuardMatch found;
    for (const auto opcode : {0x55, 0x56, 0x57, 0x5a, 0x5b, 0x5c}) {
        auto code = good.code;
        const auto outside = jump(code, static_cast<std::uint8_t>(opcode));
        destination(code, outside, good.compare);
        assert(match(code, found) == GuardStatus::Missing);
        assert(found.windowSize == 0 && found.patchSize == 0);
        destination(code, outside, good.count + 4);
        assert(match(code, found) == GuardStatus::Found); // Whole predicate entry is unchanged.
        destination(code, outside, good.compare);
        assert(match(code, found, 150) == GuardStatus::Found && found.configured);
    }
    auto code = good.code;
    const auto target = good.constant + 1;
    code.insert(code.end(), {0x5d, static_cast<std::uint8_t>(target),
                            static_cast<std::uint8_t>(target >> 8),
                            static_cast<std::uint8_t>(target >> 16)});
    assert(match(code, found) == GuardStatus::Missing); // CALL into a rewritten operand.
    code = good.code;
    code.insert(code.end(), {0x65, 1, 0, 0, 0, 0});
    const auto offset = code.size();
    code.insert(code.end(), {0, 0});
    const auto displacement = static_cast<std::uint16_t>(static_cast<int>(target) -
                                                        static_cast<int>(offset + 2));
    code[offset] = static_cast<std::uint8_t>(displacement);
    code[offset + 1] = static_cast<std::uint8_t>(displacement >> 8);
    assert(match(code, found) == GuardStatus::Missing); // SWITCH case into an operand.
    const auto fused = fixture(0x28, Predicate::FusedGe);
    code = fused.code;
    const auto outside = jump(code, 0x55);
    destination(code, outside, fused.condition);
    assert(match(code, found) == GuardStatus::Missing); // Fused opcode becomes plain JZ.
}

static void testChangingReader() {
    const auto good = fixture();
    GuardMatch found;
    bool changed = false;
    unsigned reads = 0;
    const auto changing = [&](std::size_t pc) -> std::uint8_t {
        assert(++reads < 1000 && pc < good.code.size());
        if (pc == good.exit) changed = true;
        return changed && pc == good.count ? 0x83 : good.code[pc];
    };
    assert(blip::findSemanticGuard(changing, good.code.size(), 55, 1900, found) ==
           GuardStatus::Changed);
    assert(found.windowSize == 0 && found.patchSize == 0);

    Bytes prefixed(blip::kMaxGuardBytes, 0);
    prefixed.insert(prefixed.end(), good.code.begin(), good.code.end());
    unsigned countReads = 0;
    reads = 0;
    changed = false;
    const auto changingPrevious = [&](std::size_t pc) -> std::uint8_t {
        assert(++reads < 4000 && pc < prefixed.size());
        if (pc == blip::kMaxGuardBytes && ++countReads == 3) changed = true;
        return changed && pc == 0 ? 0x83 : prefixed[pc];
    };
    assert(blip::findSemanticGuard(changingPrevious, prefixed.size(), 55, 1900, found) ==
           GuardStatus::Changed);
    // The initial parse sees the old operand, but the subsequent expected-byte
    // snapshot sees a different predicate or branch. Neither may authorize a write.
    for (const auto operand : {good.constant + 1, good.condition + 1}) {
        bool seen = false;
        const auto changingSnapshot = [&](std::size_t pc) -> std::uint8_t {
            assert(pc < good.code.size());
            if (pc != operand) return good.code[pc];
            if (!seen) { seen = true; return good.code[pc]; }
            return operand == good.constant + 1 ? 151 : 0;
        };
        assert(blip::findSemanticGuard(changingSnapshot, good.code.size(), 55, 1900, found) ==
               GuardStatus::Changed);
        assert(found.windowSize == 0 && found.patchSize == 0);
    }
}

static void testAmbiguityAndPages() {
    const auto original = fixture();
    const auto configured = fixture(0x43, Predicate::GreaterEqual, 0, false, 1900);
    const auto unsupported = fixture(0x25, Predicate::GreaterEqual);
    GuardMatch found;
    for (const auto& second : {original, configured, unsupported}) {
        auto code = original.code;
        code.insert(code.end(), second.code.begin(), second.code.end());
        assert(match(code, found) == GuardStatus::Ambiguous);
        assert(found.windowSize == 0 && found.patchSize == 0);
    }
    const std::size_t offset = blip::kPageSize - 7;
    const std::size_t length = offset + original.code.size();
    std::array<Bytes, 2> pages{Bytes(blip::kPageSize), Bytes(length - blip::kPageSize)};
    auto at = [&](std::size_t pc) -> std::uint8_t& {
        assert(pc < length);
        return pages[pc / blip::kPageSize][pc % blip::kPageSize];
    };
    for (std::size_t i = 0; i < original.code.size(); ++i) at(offset + i) = original.code[i];
    assert(blip::findSemanticGuard(at, length, 55, 1900, found) == GuardStatus::Found);
    assert(found.windowOffset == offset && found.patchOffset == offset + 4);
    for (std::size_t i = 0; i < found.patchSize; ++i) at(found.patchOffset + i) = found.replacement[i];
    assert(blip::findSemanticGuard(at, length, 55, 1900, found) == GuardStatus::Found && found.configured);
}

static const char* statusName(GuardStatus status) {
    switch (status) {
    case GuardStatus::Missing: return "Missing";
    case GuardStatus::Found: return "Found";
    case GuardStatus::Ambiguous: return "Ambiguous";
    case GuardStatus::Invalid: return "Invalid";
    case GuardStatus::Unsupported: return "Unsupported";
    case GuardStatus::Changed: return "Changed";
    }
    return "Unknown";
}

int main(int argc, char** argv) {
    testForms();
    testNarrowAndConfigured();
    testObservedGameGuard();
    testRefusals();
    testInstructionBoundaries();
    testIncomingEdges();
    testChangingReader();
    testAmbiguityAndPages();
    if (argc > 3) {
        std::fprintf(stderr, "usage: %s [captured-script [native-count]]\n", argv[0]);
        return 2;
    }
    if (argc >= 2) {
        unsigned long natives = 55;
        if (argc == 3) {
            char* end = nullptr;
            natives = std::strtoul(argv[2], &end, 10);
            if (!argv[2][0] || *end || natives > 0xfffffffful) {
                std::fprintf(stderr, "invalid native count\n");
                return 2;
            }
        }
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) { std::perror(argv[1]); return 2; }
        const Bytes code{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
        GuardMatch found;
        const auto status = match(code, found, 1900, static_cast<std::uint32_t>(natives));
        std::printf("guard=%s length=%zu window=0x%zx+%zu patch=0x%zx+%zu configured=%d\n",
                    statusName(status), code.size(), found.windowOffset, found.windowSize,
                    found.patchOffset, found.patchSize, found.configured ? 1 : 0);
        if (status != GuardStatus::Found) return 1;
    }
    std::puts("semantic guard tests passed");
    return 0;
}

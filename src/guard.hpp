#pragma once

#include "patch.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace blip {

inline constexpr std::size_t kMaxGuardBytes = 256;

enum class GuardStatus { Missing, Found, Ambiguous, Invalid, Unsupported, Changed };

struct GuardMatch {
    std::size_t windowOffset = 0;
    std::size_t windowSize = 0;
    std::size_t patchOffset = 0;
    std::size_t patchSize = 0;
    bool configured = false;
    std::uint32_t ceiling = 0; // Threshold found in the script, before any rewrite.
    std::array<std::uint8_t, kMaxGuardBytes> expected{};
    std::array<std::uint8_t, kMaxGuardBytes> replacement{};
};

namespace guard_detail {

// Opcode values and instruction lengths: scrDbg, commit
// 2700d377e0d0b6452740eefbc5c098ba2bd38d0f,
// src/app/disasm/opcodes/OpcodesGTA5.hpp (enum and GetInsnSizeGTA5).
// Unknown opcodes are rejected rather than inheriting scrDbg's size-one default.
inline constexpr std::uint8_t kNop = 0x00;
inline constexpr std::uint8_t kNot = 0x06;
inline constexpr std::uint8_t kGe = 0x0b;
inline constexpr std::uint8_t kLt = 0x0c;
inline constexpr std::uint8_t kNative = 0x2c;
inline constexpr std::uint8_t kJump = 0x55;
inline constexpr std::uint8_t kJumpZero = 0x56;
inline constexpr std::uint8_t kGeJumpZero = 0x5a;
inline constexpr std::uint8_t kLtJumpZero = 0x5b;

template<class ByteAt>
struct Code {
    ByteAt& byteAt;
    std::size_t length;

    std::uint8_t at(std::size_t pc) const {
        return static_cast<std::uint8_t>(byteAt(pc));
    }

    // Zero means an unknown or truncated instruction. Never read an operand
    // before proving that the instruction's fixed header is available.
    std::size_t size(std::size_t pc) const {
        if (pc >= length) return 0;
        const auto op = at(pc);
        if (op > 0x82) return 0;
        std::size_t n = 1;
        if (op == 0x25 || (op >= 0x34 && op <= 0x3e) ||
            (op >= 0x40 && op <= 0x42) || (op >= 0x68 && op <= 0x6b)) n = 2;
        else if (op == 0x26 || op == 0x2e || (op >= 0x43 && op <= 0x5c)) n = 3;
        else if (op == 0x27 || op == kNative || (op >= 0x5d && op <= 0x64)) n = 4;
        else if (op == 0x28 || op == 0x29) n = 5;
        else if (op == 0x2d) {
            if (length - pc < 5) return 0;
            n = 5 + at(pc + 4);
        } else if (op == 0x65) {
            if (length - pc < 2) return 0;
            n = 2 + static_cast<std::size_t>(at(pc + 1)) * 6;
        }
        return n <= length - pc ? n : 0;
    }

    bool integer(std::size_t pc, std::uint32_t& value, std::size_t& next) const {
        const auto n = size(pc);
        if (!n) return false;
        const auto op = at(pc);
        if (op != 0x25 && op != 0x43 && op != 0x64 && op != 0x28) return false;
        value = 0;
        for (std::size_t i = 1; i < n; ++i)
            value |= static_cast<std::uint32_t>(at(pc + i)) << ((i - 1) * 8);
        if (op == 0x43 && (value & 0x8000)) value |= 0xffff0000u;
        next = pc + n;
        return true;
    }

    bool native(std::size_t pc, std::uint8_t signature, std::uint16_t& index) const {
        if (size(pc) != 4 || at(pc) != kNative || at(pc + 1) != signature) return false;
        // NATIVE packs argument count in bits 2..7, result count in bits 0..1.
        // Its native-table index is big endian; integer/branch operands are not.
        index = static_cast<std::uint16_t>((at(pc + 2) << 8) | at(pc + 3));
        return true;
    }

    // Both branches and SWITCH entries use a signed displacement measured
    // from the end of their two-byte offset (pinned DisassemblerGTA5.cpp).
    bool relativeTarget(std::size_t operand, std::size_t& destination) const {
        if (operand >= length || length - operand < 2) return false;
        const auto raw = static_cast<unsigned>(at(operand)) |
                         (static_cast<unsigned>(at(operand + 1)) << 8);
        const auto delta = raw < 0x8000 ? static_cast<int>(raw) : static_cast<int>(raw) - 0x10000;
        const auto after = operand + 2;
        if (delta < 0) {
            const auto back = static_cast<std::size_t>(-delta);
            if (back > after) return false;
            destination = after - back;
        } else {
            if (static_cast<std::size_t>(delta) >= length - after) return false;
            destination = after + static_cast<std::size_t>(delta);
        }
        return destination < length; // EOF is not an instruction boundary.
    }

    bool target(std::size_t pc, std::size_t& destination) const {
        return size(pc) == 3 && relativeTarget(pc + 1, destination);
    }
};

template<class ByteAt>
struct LocalGuard {
    const Code<ByteAt>& code;
    std::size_t first;
    std::size_t last;

    // first is a boundary from the linear decoder, not a guessed byte offset.
    // Every walk is bounded even if an input branch points backwards.
    bool boundary(std::size_t destination) const {
        if (destination < first || destination >= last) return false;
        for (auto pc = first; pc <= destination;) {
            if (pc == destination) return true;
            const auto n = code.size(pc);
            if (!n || n > last - pc) return false;
            pc += n;
        }
        return false;
    }

    std::size_t skipNops(std::size_t pc) const {
        while (pc < last && code.at(pc) == kNop) ++pc;
        return pc;
    }

    bool branch(std::size_t pc, std::size_t& destination) const {
        return pc < last && code.target(pc, destination) && boundary(destination);
    }

    bool match(std::size_t countPc, std::uint32_t nativeCount, std::uint16_t limit,
               GuardMatch& out, bool& fits, bool& invalidNative) const {
        std::uint16_t countIndex = 0;
        if (!code.native(countPc, 0x01, countIndex)) return false;
        const auto patchStart = countPc + 4;
        auto pc = skipNops(patchStart);
        std::uint32_t threshold = 0;
        // The vanilla value is not assumed: a game build or another mod may have set a
        // different ceiling. The count/compare/WAIT(2000)/loop-back shape is what identifies the guard.
        if (!code.integer(pc, threshold, pc) || threshold == 0 || threshold > kMaxLimit) return false;
        pc = skipNops(pc);
        if (pc >= last) return false;
        auto op = code.at(pc);
        bool waitWhenTrue = false;
        bool fused = false;
        if (op == kGeJumpZero || op == kLtJumpZero) {
            waitWhenTrue = op == kGeJumpZero;
            fused = true;
        } else {
            if (op != kGe && op != kLt) return false;
            waitWhenTrue = op == kGe;
            pc = skipNops(pc + 1);
            if (pc < last && code.at(pc) == kNot) {
                waitWhenTrue = !waitWhenTrue;
                pc = skipNops(pc + 1);
            }
            if (pc >= last || code.at(pc) != kJumpZero) return false;
        }
        const auto branchPc = pc;
        std::size_t taken = 0;
        if (!branch(branchPc, taken)) return false;
        const auto fallthrough = branchPc + 3;
        const auto bodyEntry = waitWhenTrue ? fallthrough : taken;
        auto body = bodyEntry;
        const auto exit = waitWhenTrue ? taken : fallthrough;
        if (!boundary(body) || !boundary(exit)) return false;
        body = skipNops(body);
        auto bodyPc = body;
        std::uint32_t delay = 0;
        if (!code.integer(bodyPc, delay, bodyPc) || delay != 2000) return false;
        bodyPc = skipNops(bodyPc);
        std::uint16_t waitIndex = 0;
        if (bodyPc >= last || !code.native(bodyPc, 0x04, waitIndex)) return false;
        bodyPc = skipNops(bodyPc + 4);
        std::size_t loopTarget = countPc;
        std::size_t bodyEnd = bodyPc;
        if (bodyPc != countPc) {
            if (bodyPc >= last || code.at(bodyPc) != kJump || !branch(bodyPc, loopTarget) ||
                skipNops(loopTarget) != countPc) return false;
            bodyEnd = bodyPc + 3;
        } else if (body >= countPc) {
            return false;
        }
        auto start = bodyEntry < countPc ? bodyEntry : countPc;
        if (loopTarget < start) start = loopTarget;
        const auto end = bodyEnd > branchPc + 3 ? bodyEnd : branchPc + 3;
        // Follow only transparent exit instructions. A second jump must not
        // conceal a route back into WAIT/the predicate; cycles fail closed.
        auto snapshotStart = start;
        auto snapshotEnd = end;
        auto exitPc = exit;
        bool exited = false;
        for (std::size_t steps = 0; steps < kMaxGuardBytes; ++steps) {
            if (exitPc >= last) return false;
            if (exitPc < snapshotStart) snapshotStart = exitPc;
            const auto exitEnd = exitPc + code.size(exitPc);
            if (exitEnd > snapshotEnd) snapshotEnd = exitEnd;
            if (snapshotEnd - snapshotStart > kMaxGuardBytes) return false;
            const auto exitOp = code.at(exitPc);
            if (exitOp == kNop) {
                ++exitPc;
            } else if (exitOp == kJump) {
                if (!branch(exitPc, exitPc)) return false;
            } else {
                if (exitPc >= start && exitPc < end) return false;
                exited = true;
                break;
            }
        }
        if (!exited) return false;
        start = snapshotStart;

        out = {};
        out.windowOffset = start;
        out.windowSize = snapshotEnd - start;
        out.patchOffset = patchStart;
        out.patchSize = branchPc - patchStart + (fused ? 1 : 0);
        out.configured = threshold == limit;
        out.ceiling = threshold;
        for (std::size_t i = 0; i < out.windowSize; ++i) out.expected[i] = code.at(start + i);
        invalidNative = countIndex >= nativeCount || waitIndex >= nativeCount || waitIndex == countIndex;
        const std::size_t expressionSize = limit <= 255 ? 3 : 4;
        fits = branchPc - patchStart >= expressionSize;
        if (!out.configured && fits) {
            // Right-align the comparison before the fixed branch. NOPs consume
            // the existing predicate span; no instruction or displacement moves.
            const auto offset = branchPc - patchStart - expressionSize;
            out.replacement[offset] = limit <= 255 ? 0x25 : 0x43;
            out.replacement[offset + 1] = static_cast<std::uint8_t>(limit);
            if (limit > 255) out.replacement[offset + 2] = static_cast<std::uint8_t>(limit >> 8);
            out.replacement[offset + expressionSize - 1] = waitWhenTrue ? kGe : kLt;
            if (fused) out.replacement[out.patchSize - 1] = kJumpZero;
        }
        return true;
    }
};

} // namespace guard_detail

// Recognizes a count/predicate/WAIT loop, not native hashes. Callers still must
// select the intended named/hashed program and revalidate its native table.
// ponytail: only straight WAIT bodies and transparent exits, within 256 bytes.
// Add forms only with bytecode evidence; this is not a general decompiler.
template<class ByteAt>
GuardStatus findSemanticGuard(ByteAt byteAt, std::size_t length, std::uint32_t nativeCount,
                              std::uint16_t limit, GuardMatch& out) {
    out = {};
    const guard_detail::Code<ByteAt> code{byteAt, length};
    // Validate the complete instruction stream first. Embedded bytes in an
    // immediate, ENTER name or SWITCH table must never become candidates.
    for (std::size_t pc = 0; pc < length;) {
        const auto n = code.size(pc);
        if (!n) return GuardStatus::Invalid;
        pc += n;
    }
    GuardStatus result = GuardStatus::Missing;
    std::size_t first = 0;
    for (std::size_t pc = 0, n = 0; pc < length; pc += n) {
        n = code.size(pc);
        if (!n) {
            out = {};
            return GuardStatus::Changed;
        }
        if (code.at(pc) != guard_detail::kNative) continue;
        // Keep a proven boundary no more than 255 bytes before this candidate.
        // This two-cursor walk needs no script-sized allocation or boundary map.
        while (pc - first >= kMaxGuardBytes) {
            const auto step = code.size(first);
            if (!step || step > pc - first) {
                out = {};
                return GuardStatus::Changed;
            }
            first += step;
        }
        const auto forward = length - pc < kMaxGuardBytes ? length : pc + kMaxGuardBytes;
        const guard_detail::LocalGuard<ByteAt> local{code, first, forward};
        GuardMatch candidate;
        bool fits = false;
        bool invalidNative = false;
        if (!local.match(pc, nativeCount, limit, candidate, fits, invalidNative)) continue;
        if (invalidNative) {
            out = {};
            return GuardStatus::Invalid;
        }
        // Decode the completed immutable snapshot again. Live reads used to
        // recognize the guard must not authorize different bytes copied later.
        const auto snapshotAt = [&](std::size_t offset) { return candidate.expected[offset]; };
        const guard_detail::Code<decltype(snapshotAt)> snapshot{snapshotAt, candidate.windowSize};
        for (std::size_t offset = 0; offset < candidate.windowSize;) {
            const auto step = snapshot.size(offset);
            if (!step) { out = {}; return GuardStatus::Changed; }
            offset += step;
        }
        const guard_detail::LocalGuard<decltype(snapshotAt)> immutable{
            snapshot, 0, candidate.windowSize};
        GuardMatch checked;
        bool checkedFits = false;
        bool checkedInvalidNative = false;
        if (!immutable.match(pc - candidate.windowOffset, nativeCount, limit, checked,
                             checkedFits, checkedInvalidNative) ||
            checkedInvalidNative || checkedFits != fits ||
            checked.windowOffset != 0 || checked.windowSize != candidate.windowSize ||
            checked.patchOffset + candidate.windowOffset != candidate.patchOffset ||
            checked.patchSize != candidate.patchSize || checked.configured != candidate.configured ||
            checked.ceiling != candidate.ceiling ||
            checked.replacement != candidate.replacement) {
            out = {};
            return GuardStatus::Changed;
        }
        if (result != GuardStatus::Missing) {
            out = {};
            return GuardStatus::Ambiguous;
        }
        out = candidate;
        result = candidate.configured || fits ? GuardStatus::Found : GuardStatus::Unsupported;
    }
    if (result == GuardStatus::Found && !out.configured) {
        // Re-encoding preserves addresses, not internal instruction boundaries
        // or stack entry contracts. No other control-flow edge may enter the
        // rewritten predicate's interior, including a replaced fused opcode.
        const auto interior = [&](std::size_t target) {
            return target > out.patchOffset && target < out.patchOffset + out.patchSize;
        };
        for (std::size_t pc = 0, n = 0; pc < length; pc += n) {
            n = code.size(pc);
            if (!n) {
                out = {};
                return GuardStatus::Changed;
            }
            const auto op = code.at(pc);
            std::size_t target = 0;
            bool unsafe = false;
            if (op >= 0x55 && op <= 0x5c) {
                if (n != 3) { out = {}; return GuardStatus::Changed; }
                unsafe = code.target(pc, target) && interior(target);
            } else if (op == 0x5d) {
                if (n != 4) { out = {}; return GuardStatus::Changed; }
                // CALL stores an absolute, little-endian U24 code address.
                target = static_cast<std::size_t>(code.at(pc + 1)) |
                         (static_cast<std::size_t>(code.at(pc + 2)) << 8) |
                         (static_cast<std::size_t>(code.at(pc + 3)) << 16);
                unsafe = interior(target);
            } else if (op == 0x65) {
                if (n < 2) { out = {}; return GuardStatus::Changed; }
                const auto count = code.at(pc + 1);
                if (n != 2 + static_cast<std::size_t>(count) * 6) {
                    out = {};
                    return GuardStatus::Changed;
                }
                for (std::size_t i = 0; i < count; ++i) {
                    const auto operand = pc + 2 + i * 6 + 4;
                    if (code.relativeTarget(operand, target) && interior(target)) {
                        unsafe = true;
                        break;
                    }
                }
            }
            if (unsafe) {
                out = {};
                return GuardStatus::Missing;
            }
        }
    }
    return result;
}

} // namespace blip

#pragma once

#include <cstdint>

namespace blip {
enum class ConfigResult { Default, Loaded, Invalid, Error };

// Default sets 1900 for a missing file or key; Loaded sets the parsed limit.
// Invalid (empty, malformed, out-of-range, or 63+ character value) and Error
// (path, open, or preflight read failure) leave limit unchanged. Nothing is written.
// Windows INI syntax applies: quotes and surrounding whitespace are stripped,
// and ignored/malformed section or key lines can appear as a missing key.
// The profile API has no reliable parse/I/O error status; a full read preflight
// catches file read failures, but not errors hidden inside the profile API.
ConfigResult readLimit(const wchar_t* iniPath, std::uint16_t& limit);
}

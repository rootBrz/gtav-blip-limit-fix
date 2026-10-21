# BlipLimitFix — GTA V Enhanced and Legacy discovery

ASI mod that raises the vanilla `blip_controller` script's 150-active-blip threshold so additional map blips do not block vanilla blip creation.

**Game-tested only on GTA V Enhanced 1.0.1158.16.** Legacy program-registry discovery is source-corroborated and covered by synthetic tests, not a live Legacy game test. Legacy script compatibility, engine capacity, and the default/maximum limits remain unverified; other versions and EGS are also unverified. This changes a script condition, not the engine pool; the measured 2,000-slot pool applies only to the tested Enhanced build.

## Install

1. Use **Story Mode only**, with BattlEye disabled, an ASI loader and [ScriptHookV](https://www.dev-c.com/gtav/scripthookv/) compatible with your game edition/build.
2. Close the game. Copy `BlipLimitFix.asi` and `BlipLimitFix.ini` into the game directory beside `GTA5_Enhanced.exe` (Enhanced) or `GTA5.exe` (Legacy, unverified). Preserve your existing INI when upgrading. The archive retains its existing `BlipLimitFix-Enhanced.zip` name for compatibility.
3. Start Story Mode. Check `BlipLimitFix.log` beside the ASI for `PATCHED:` or `UNCHANGED:`.

To uninstall, close the game and remove the ASI and INI. Hot unloading is not supported.

## Configuration

Edit `BlipLimitFix.ini`, then restart the game:

```ini
[Blips]
Limit=1900
```

- **150–1997** accepted. `150` retains the vanilla threshold; the default `1900` leaves headroom.
- `1997` leaves no headroom under the tested Enhanced pool/count relationship: at 2,000 occupied slots, the active-blip native returned 1,997. Both `1900` and `1997` derive from Enhanced measurements and are unverified on Legacy.
- A missing file or key uses `1900`. Invalid values or file-read errors stop patching and log the reason.
- Put comments on separate `;` lines. The mod never writes the INI.

## How it works

The native scanner validates the loaded x64 PE image and traverses readable spans of executable sections once, comparing all three program-registry locators in that pass. Matches can cross adjacent readable protection regions, but never inaccessible or guarded gaps. It checks the original Enhanced program-registry locator plus the [scrDbg Enhanced and Legacy locators](https://github.com/ShinyWasabi/scrDbg/blob/2700d377e0d0b6452740eefbc5c098ba2bd38d0f/src/app/game/gta5/GTA5.cpp): `44 88 05 ? ? ? ? 48 89 F9` (GEN9) and `48 8D 0D ? ? ? ? 41 8B D6 E8 ? ? ? ? FF 05` (GEN8). The [internal scrDbg GEN8 registry lookup](https://github.com/ShinyWasabi/scrDbg/blob/2700d377e0d0b6452740eefbc5c098ba2bd38d0f/src/lib/game/GTA5.cpp) corroborates the Legacy signature. Each locator retains independent status, scan statistics, and uniqueness checks. Each locator must be unique when present. Any locator alone can resolve the array; all present locators must agree. Ambiguity, scan faults, invalid images, changed locator bytes, invalid signed RIP-relative targets, or disagreement stop patching, never trigger fallback. If all are missing, the existing missing-pattern dialog refuses patching. All three use displacement offset 3, instruction length 7, and registry offset `0xD8`; the full 176-pointer array must fit inside the image and passes the existing guarded read before script inspection.

The script scanner checks both the name and hash of `blip_controller`, then decodes VM instructions instead of requiring an exact byte sequence. It requires one supported count-comparison/`WAIT(2000)` loop with the correct comparison polarity, branch destinations, and loop-back. Native-call argument/result counts and table indices are checked; native hashes are not resolved.

The decoder accepts supported integer encodings, comparison polarities, fused comparisons, and NOP padding within a 256-byte loop window. The replacement must fit the original predicate span. Following code and jump offsets stay unchanged; direct control-flow entries into the rewritten span's interior are refused. Before writing, the mod revalidates an immutable code snapshot, page identities, permissions, and selected registry slot. These checks narrow races; they do not lock the registry.

The pinned scrDbg source uses one [script-program layout](https://github.com/ShinyWasabi/scrDbg/blob/2700d377e0d0b6452740eefbc5c098ba2bd38d0f/src/app/game/gta5/types/ScriptProgramGTA5.hpp) for GEN8 and GEN9. Both discovery paths require the same bounded loop decoder, name/hash checks, page validation, and native-table readiness checks. A Legacy registry match alone does not establish a compatible script or engine capacity.

ScriptHook restarts the patch callback on each save load or reload. Each callback locates the native registry once, waits for `blip_controller`, and returns immediately after patching or recognizing the configured guard. There are no post-success VM rescans. Startup and transient retries use fresh snapshots without retaining stale page pointers across yields. Game files, native counts, and the engine pool remain unchanged.

Transient script-readiness, unreadable-memory, changed-code, and pre-write validation failures retry at a 100 ms poll interval, stopping after 100 transient failures. This is a cumulative per-callback failure budget, **not a ten-second stabilization window**. An absent script neither consumes nor resets it; a new callback starts with a fresh budget. Invalid structures/native indices, missing or ambiguous patterns, and insufficient predicate space remain terminal.

The in-place predicate update is **not atomic**. Destination checks prevent writes to known-unwritable memory, but independent allocation/protection changes can race them. A write fault triggers best-effort rollback and stops the callback without retrying; rollback itself can fail. ScriptHook scheduling avoids normal VM execution during the edit, not arbitrary changes by other mods.

Missing or ambiguous patterns show an error message box, then stop the callback after dismissal. Other validation failures remain log-only. Success shows no message box. The game is not terminated.

`Native scan:` log entries report readable/skipped executable bytes and readable spans. These help distinguish an inaccessible scan area from a changed signature; a missing pattern alone does not identify the cause.

Discovery assumes the inspected engine structures and VM instructions. Game updates can require maintenance; signature matching does not guarantee version independence.

## Engine blip-limit findings

Verified on **Enhanced 1.0.1158.16** using disassembly and a live allocation probe. Original executable SHA-256: `69da07ff67d05e9ded11289e597e8b8dc5855b0a429c085f37d148dc267cb2c5`.

Addresses below are RVAs, not file offsets. Add the loaded executable base to obtain a VA; the observed base was `0x140000000`.

| Engine location            | RVA                                      | Finding                                                                     |
| -------------------------- | ---------------------------------------- | --------------------------------------------------------------------------- |
| Blip-pointer array         | `0x03DEBD70`–`0x03DEFBF0` exclusive      | `0x3E80` bytes: 2,000 eight-byte slots                                      |
| Free-slot allocator        | `0x0055D890`                             | Searches slots in groups of five                                            |
| Allocator loop bound       | `0x0055D8E7`                             | `cmp rdx, 0x7D4`; 2004 is the unrolled-loop termination value, not capacity |
| Full-pool allocator result | `0x0055D8F0`                             | Returns index `-1`                                                          |
| Creation failure path      | `0x0055CEF7`                             | Returns blip handle `0`                                                     |
| Slot-index bounds          | `0x0055CED8`, `0x0056915C`, `0x005691AC` | Maximum valid index `0x7CF` (1999)                                          |

The live probe added **1,774 valid blips** alongside 226 existing slots, reaching exactly **2,000 occupied slots**. The next creation returned `0`. Removing one probe blip and yielding a frame allowed index 1999 to be reused; another creation then failed again. Cleanup restored the original 226 slots.

At full occupancy, `GET_NUMBER_OF_ACTIVE_BLIPS()` (`0x9A3FF3DE163034E8`) returned **1,997**: three occupied slots were excluded. This explains the INI maximum of 1997 rather than 2000. The default 1900 leaves headroom but does not reserve slots against other callers.

All 1,774 probe markers were visible in the map capture. This does not prove a universal 2,000-marker rendering limit or another build's capacity. Raising the engine capacity would require relocating its array and updating allocation/index bounds; this mod does neither.

Private probe logs, snapshots, and captures remain under ignored `analysis/`, including `capacity-verification.json` and `capacity-final.log`; they are not bundled.

## Build and checks

Requires **MSVC v145**, MSBuild, and the ScriptHookV SDK (`inc/main.h`, `lib/ScriptHookV.lib`). The default SDK directory is `../ScriptHookV_SDK_1.0.617.1a/`; override with `/p:ScriptHookSdkDir=<absolute-directory-with-trailing-separator>`.

```sh
msbuild BlipLimitFix.vcxproj /p:Configuration=Release /p:Platform=x64
```

Outputs: `dist/BlipLimitFix.asi` and `dist/BlipLimitFix.ini`. The MSVC runtime is statically linked; `ScriptHookV.dll` is required at runtime. SDK files are not bundled.

On Linux with the MSBuild wrapper and Wine:

```sh
make all           # defaults to ~/.local/bin/msbuild; override MSBUILD if needed
make check         # portable parser, VM-expression, instruction-decoder, and guard checks
make check-config  # MSVC-built Windows INI checks under Wine
make check-memory  # Windows memory-protection, PE validation, and script-patch regressions
```

Wine checks use an isolated prefix in `build/wine-smoke`. Build outputs and private analysis files are excluded from Git.

To exercise the production locator on a private loaded-image capture (sections stored at their RVAs, not an ordinary on-disk executable):

```sh
env WINEPREFIX="$PWD/build/wine-smoke" WINEDEBUG=-all WINEDLLOVERRIDES=mscoree,mshtml=d \
  wine build/memory_test.exe 'Z:\absolute\path\GTA5_Enhanced.runtime.exe'
```

The deterministic memory tests cover Enhanced/Legacy discovery, locator agreement/conflicts, signed RIP bounds, protected memory, script reloads, retry limits, and write preflight. Semantic guard tests cover supported equivalent encodings and reject malformed or ambiguous control flow. The optional capture check confirms the inspected Enhanced RVAs without executing game code. These checks do not establish live Legacy or EGS compatibility.

## Development

Almost entirely AI-generated, with human direction and in-game testing.

## License

Copyright (c) 2026 BlipLimitFix contributors.

Licensed under the [GNU GPL version 3 only](LICENSE), with this additional permission under section 7:

> You may link or combine this program with ScriptHookV and its SDK and convey the resulting work. This permission does not remove GPL requirements for this program or other covered code, and does not grant rights to third-party components beyond their own licenses.

ScriptHookV and its SDK are third-party dependencies and are not bundled.

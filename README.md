# BlipLimitFix — GTA V Enhanced

ASI mod that raises the vanilla `blip_controller` script's 150-active-blip threshold so additional map blips do not block vanilla blip creation.

**Tested only on GTA V Enhanced 1.0.1158.16.** Other versions are unverified. This changes a script condition, not the engine's 2,000-slot blip pool.

## Install

1. Use **Story Mode only**, with BattlEye disabled, an Enhanced-compatible ASI loader, and [ScriptHookV](https://www.dev-c.com/gtav/scripthookv/).
2. Close the game. Copy `BlipLimitFix.asi` and `BlipLimitFix.ini` beside `GTA5_Enhanced.exe`. Preserve your existing INI when upgrading.
3. Start Story Mode. Check `BlipLimitFix.log` beside the ASI for `PATCHED:`.

To uninstall, close the game and remove the ASI and INI. Hot unloading is not supported.

## Configuration

Edit `BlipLimitFix.ini`, then restart the game:

```ini
[Blips]
Limit=1900
```

- **150–1997** accepted. `150` retains the vanilla threshold; the default `1900` leaves headroom.
- `1997` leaves no headroom under the tested pool/count relationship: at 2,000 occupied slots, the active-blip native returned 1,997.
- A missing file or key uses `1900`. Invalid values or file-read errors stop patching and log the reason.
- Put comments on separate `;` lines. The mod never writes the INI.

## How it works

The mod finds the loaded script-program array through a signature, selects `blip_controller` by name hash, and finds its blip-count wait loop. It replaces the four-byte comparison without moving instructions or changing jump targets.

ScriptHook schedules the patch callback. The mod checks periodically for script reloads; no game files or native blip counts are modified.

Missing or ambiguous patterns show an error message box, then stop the callback after dismissal. Other validation failures remain log-only. Success shows no message box. The game is not terminated.

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
make check         # portable C++17 parser, VM-expression, and scanner checks
make check-config  # MSVC-built Windows INI checks under Wine
```

Wine checks use an isolated prefix in `build/wine-smoke`. Build outputs and private analysis files are excluded from Git.

# Changelog

Each release needs a `## <version>` section here matching `VERSION`. The release workflow publishes that section to GitHub and Nexus Mods, and fails if it is missing.

## 1.4.1

- Fixed: the game could freeze if BlipLimitFix failed to find the blip script's check. The error popup is no longer blocking, so the game keeps running.
- Added: if the check is not found, `BlipLimitFix.log` now records details about the script, so the problem can be diagnosed.
- No change to the blip limit or its behavior when the check is found.

## 1.4

- Same changes as 1.4.1. This build was packaged by hand.

## 1.3

- Fixed: the blip limit is now patched once per save load.

# Frida iOS Hook ChangeLog

## [Release 3.11] - 2025-02-01

### Added

- **Default dump output folder:** `workspaces/dumps` for decrypted IPA (created by setup).
- **Option `--dump-output-dir DIR`:** Custom output directory for dumped IPA (CLI and hook.py).
- **Setup:** Creates `workspaces` and `workspaces/dumps` when running `python3 setup.py`.
- New Frida scripts for SSL pinning bypass in Facebook and Instagram apps.
- SSH credential handling and port forwarding options in the CLI.
- `--ssh-port-forward` to forward port from local to device (ssh -R).
- Using sshpass for auto input SSH password.

### Changed

- **Dump IPA path:** Saves to `frida-ios-hook/workspaces/dumps` by default instead of `./dumps` (no longer depends on CWD).
- **Dump util (`core/utils/dump.py`):** `DUMP_OUTPUT_DIR` set from script location (`hook_root/workspaces/dumps`).
- **Dump log:** When dumping, log shows output dir (e.g. `IPA output dir: workspaces/dumps`).
- **WIKI:** Document default path, `-o`/`--output`, `--dump-output-dir`, and that setup creates workspaces/dumps.
- **README:** Feature section replaced with full options table from hook.py; changelog section updated to 3.11.
- Enhance iOSHook CLI with improved usage examples and option descriptions.
- Enhance option `--shell` / `--ssh` with better SSH connection handling.
- Refactor script loading and error handling for better stability.
- Update config (hook.conf / hook.json).

## [Release 3.10] - 2024-04-29

### Added
- Add --pid for attach to target app with PID

### Changed
- Update option --shell / --ssh 
- Update option -d / --dump-app
- Update frida version
- Update readme, changelog, requirement

### Fixed
- Fix issue #84

## [Release 3.9] - 2023-08-17

### Added
- Add backtrace to hooking.js

### Changed
- Update frida version
- Update readme, changelog, requirement

### Fixed
- Fix issue #85


## [Release 3.8] - 2022-12-11

### Added
- Add function check.deviceConnected
- Add reFlutter
### Changed
- Update function check.iproxyInstalled
- Update dumpDecryptIPA option
- Update readme, changelog, requirement
- Remove --list-appinfo option
- Update --cli option
### Fixed
- Fix issue in --shell option [issue 57](https://github.com/noobpk/frida-ios-hook/issues/57)
- Fix issue in --dump option [issue 67](https://github.com/noobpk/frida-ios-hook/issues/67)
- Fix and optimize hexbytescan option

## [Release 3.7] - 2022-06-17

### Added
- Add setup.py for build executable
- Add --ssh to option Get the shell of connect device
- Add suggestion script for option -s (--script)
### Changed
- Update readme, changelog
- Update frida-script
- Update hook.py
### Fixed
- Fix syntax in hook.json
- Fix psutil not found

## [Unrelease] - 2022-04-18

### Added
- Add setup.py for build executable
### Changed
- Update readme, changelog
- Remove old file

## [Unrelease] - 2022-03-17

### Added

### Changed
- Update ioshook. Check python3 command exists

## [Unrelease] - 2022-02-18

### Added

### Changed
- Update option hexbyte-scan

### Fixed

## [Unrelease] - 2022-01-24

### Added
- Add new script to frida-scripts
- Add info to script

### Changed
- Update option list-scripts
- Update README.md

### Fixed

## [Unrelease] - 2022-01-14

### Added
- New option CLI `--cli`

### Changed

### Fixed
- Fix method List All Application script not found

## [3.6] - 2022-01-11

### Added
- New option Show system log of device `--logcat`
- New option Get the shell of connect device `--shell`

### Changed
- Using `hook.json` to load configuration for the tool
- Optimize core `hook.py`

### Fixed

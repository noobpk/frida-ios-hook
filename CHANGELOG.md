# Frida iOS Hook ChangeLog

## [Unrelease] - 2025-10-06

### Added

- Add --ssh-port-forward for Forward the port from local to device
- Add using sshpass for auto input ssh password

### Changed
- Enhance option --shell / --ssh 
- Update config hook.json

## [Release 3.10] - 2025-29-04

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

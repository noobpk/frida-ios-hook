# Frida iOS Hook ChangeLog

## [Release 3.8] - 2022-12-


### Added
- Add function check.deviceConnected
### Changed
- Update function check.iproxyInstalled
- Update readme, changelog
### Fixed
- Fix issue in --shell option [issue 57](https://github.com/noobpk/frida-ios-hook/issues/57)

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

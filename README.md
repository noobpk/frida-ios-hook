<img width="538" alt="image" src="https://user-images.githubusercontent.com/31820707/103606590-5f006380-4f49-11eb-9f57-c1c78c76a506.png">

# Frida iOS hook

[![CodeQL](https://github.com/noobpk/frida-ios-hook/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/noobpk/frida-ios-hook/actions/workflows/codeql-analysis.yml)
![python](https://img.shields.io/badge/python-3.x-blue)
![frida](https://img.shields.io/badge/frida-16.1.4-orange)

📍 A tool that helps you can easy using frida. It support script for trace classes, functions, and modify the return values of methods on iOS platform.

👉 For Android platform: [frida-android-hook](https://github.com/noobpk/frida-android-hook)

👉 For Intercept Api was encrypted on iOS application: [frida-ios-intercept-api](https://github.com/noobpk/frida-ios-intercept-api)

## Env OS Support
| OS      | Supported          | Noted   |
| ------- | ------------------ | ------- |
| MacOS   | :white_check_mark: | Stable	 |
| Linux   | :white_check_mark: | Stable  |
| Windows | :white_check_mark: | Unstable|

## Compatible with
| iOS      |  Frida   | Frida-tools | Supported        | Stable Version |
| -------- | -------  | ----------- |----------------- | -------------- |
| 16.7.11  | 16.7.14   | 13.7.1      | :white_check_mark:| |
|  16.7.11  | 16.1.4   | 12.2.1      | :white_check_mark:| :white_check_mark:|

**Note:** Using stable versions to fix the [ObjC not defined issue](https://github.com/frida/frida/issues/3460) present in frida 17.0.1.

## Feature

Running with python3.x

Support both spawn & attach script to process.

```
[+] Options:
  -h, --help            Show basic help message and exit
  --cli                 Launch iOSHook interactive CLI
  -p PACKAGE, --package=PACKAGE
                        Bundle identifier of target app (spawn)
  -n NAME, --name=NAME  Display name of target app (attach)
  --pid=PID             Process ID of target app (attach)
  -s SCRIPT.JS, --script=SCRIPT.JS
                        Path to Frida JavaScript hooking script
  -c, --check-version   Check for iOSHook updates
  -u, --update          Update iOSHook to latest version
  Quick Method:
    -m METHOD, --method=METHOD
                        app-static | bypass-jb | bypass-ssl | i-url-req | i-crypto

  Information:
    --list-devices      List all connected Frida devices
    --list-apps         List all installed applications on device
    --list-scripts      List all available Frida scripts
    --logcat            Show system log of device (idevicesyslog)
    --conf              Open and edit hook.conf file
    --shell, --ssh      Open SSH shell to device (default USB via iproxy)
    --ssh-port-forward=LOCAL_PORT:DEVICE_PORT
                        Forward port from local to device (ssh -R)
    --network=HOST:PORT Connect via network SSH (default port 22)
    --local             Connect via USB using iproxy

  Dump decrypt IPA:
    -d, --dump-app      Dump and decrypt application IPA file
    -o OUTPUT_IPA, --output=OUTPUT_IPA
                        Output filename for decrypted IPA (without .ipa)

  Dump memory of Application:
    --dump-memory=OPTS  Dump memory of running application (e.g. --string)

  HexByte Scan IPA:
    --hexbyte-scan=MODE help | scan | patch | json
    --file=FILE.IPA     IPA file to scan/patch
    --pattern=PATTERN   Hex pattern for scan
    --address=ADDRESS   Address,bytes,distance for patch
    --task=TASK.json    JSON task file for hexbyte scan

  reFlutter:
    --reflutter=FLUTTER.IPA
                        Path to Flutter IPA for reFlutter analysis
```

## 📜 ChangeLog

Version: 3.10
```
	[+] Add:
		- Add --pid for attach to target app with PID
	[+] Change:
		- Update option --shell / --ssh 
    - Update option -d / --dump-app
    - Update frida version
    - Update readme, changelog, requirement
	[+] Fix
		- Fix issue #84
```
[See Full ChangeLog](https://github.com/noobpk/frida-ios-hook/blob/master/CHANGELOG.md)

## Install

```
	[+] Latest version

		https://github.com/noobpk/frida-ios-hook/releases

	[+] Develop version

		git clone -b dev https://github.com/noobpk/frida-ios-hook
```

## Environment

```
[+] Python >= v3.0 (Recommend to use pyenv or virtualenv)

1. cd frida-ios-hook/
2. python3 -m venv py-env
3. source py-env/bin/active
```

## Build

```
1. pip3 install -r requirements.txt
3. python3 setup.py
4. cd frida-ios-hook
5. ./ioshook -h (--help)
```

## Usage

[See Full Usage as Wiki](https://github.com/noobpk/frida-ios-hook/wiki)

If you run the script but it doesn't work, you can try the following:
```frida -U -f package -l script.js```

## 📺 Demo Feature

|Title|Link|
|:---|:---|
|Frida iOS Hook &#124; Basic Usage &#124; Install - List devices - List apps - List scripts - Logcat - Shell|[https://youtu.be/xSndHgTdv4w](https://youtu.be/xSndHgTdv4w)|
|Frida iOS Hook &#124; Basic Usage &#124; Dump Decrypt IPA - Dump Memory App - Hexbyte-Scan IPA|[https://youtu.be/AUsJ9_gnWAI](https://youtu.be/AUsJ9_gnWAI)|
|Frida iOS Hook &#124; Basic Usage &#124; App Static - Bypass Jailbreak - Bypass SSL - Intercept URL + Crypto|[https://youtu.be/nWhKDSzArf8](https://youtu.be/nWhKDSzArf8)|
|Frida iOS Hook &#124; Advance Usage &#124; Memory Dump - Radare2 - Iaito|[https://youtu.be/nUqE4EYWiEc](https://youtu.be/nUqE4EYWiEc)|

## Disclaimer
Because I am not a developer, so my coding skills might not be the best. Therefore, if this tool have any issue or not working for you, create an issue and i will try to fix it.
Any suggestions for new feature and discussions are welcome!

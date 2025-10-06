<img width="538" alt="image" src="https://user-images.githubusercontent.com/31820707/103606590-5f006380-4f49-11eb-9f57-c1c78c76a506.png">

# Frida iOS hook

[![CodeQL](https://github.com/noobpk/frida-ios-hook/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/noobpk/frida-ios-hook/actions/workflows/codeql-analysis.yml)
![python](https://img.shields.io/badge/python-3.x-blue)
![frida](https://img.shields.io/badge/frida-15.x-orange)

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
| iOS      |  Frida   | Frida-tools | Supported        |
| -------- | -------  | ----------- |----------------- |
|  16.7.11  | 16.7.14   | 13.7.1      | :white_check_mark:|

## Feature

Running with python3.x

Support both spawn & attach script to process.

```
[+] Options:
  -h, --help            Show basic help message and exit
  --cli                 iOSHook command line interface
  -p PACKAGE, --package=PACKAGE
                        Identifier of the target app
  -n NAME, --name=NAME  Name of the target app
  --pid=PID             PID of the target app
  -s SCRIPT.JS, --script=SCRIPT.JS
                        Frida Script Hooking
  -c, --check-version   Check iOSHook for the newest version
  -u, --update          Update iOSHook to the newest version

  Dump decrypt IPA:
    -d, --dump-app      Dump decrypt application.ipa
    -o OUTPUT_IPA, --output=OUTPUT_IPA
                        Specify name of the decrypted IPA

  Dump memory of Application:
    --dump-memory=DUMPMEMORY
                        Dump memory of application

  HexByte Scan IPA:
    --hexbyte-scan=HEXSCAN
                        Choose help - scan - patch - json
    --file=SCANFILE     File App.ipa
    --pattern=PATTERN   Pattern for hexbytescan
    --address=ADDRESS   Address for hexbytescan
    --task=TASK         Json File task for hexbytescan

  Information:
    --list-devices      List All Devices
    --list-apps         List The Installed apps
    --list-scripts      List All Scripts
    --logcat            Show system log of device
    --shell, --ssh      Get the shell of connect device
    --ssh-port-forward=LOCAL_PORT:DEVICE_PORT
                        Forward the port from local to device

  Quick Method:
    -m METHOD, --method=METHOD
                        app-static: Static Analysis Application(-n)
                        bypass-jb: Bypass Jailbreak Detection(-p)
                        bypass-ssl: Bypass SSL Pinning(-p)
                        i-url-req: Intercept URLRequest in App(-n)
                        i-crypto: Intercept Crypto in App(-p)

  reFlutter:
    --reflutter=FLUTTERFILE
                        File Flutter.ipa
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
## Frida-Script

Updated some frida scripts to help you with the pentest ios app. Filter script using spawn(S) or attach(A)

|N|Spawn/Attach|Script Name| Script Description| Script Version|
|:---|:---|:---|:---|:---|
|1|S|backtrace.js|Backtrace |1.0|
|2|S|bypass-flutter-ssl.js|Flutter bypass ssl pinning|1.0|
|3|S|bypass-jailbreak-1.js|Basic bypass jailbreak detection|1.0|
|4|S|bypass-ssl-ios13.js|iOS 13 bypass ssl pinning|1.0|
|5|S|dump-ios-url-scheme.js|Dump iOS url scheme when "openURL" is called|1.0|
|6|S|dump-ui.js|Dump the current on-screen User Interface structure|1.0|
|7|S+A|find-all-classes-methods.js|Dump all methods inside all classes|1.0|
|8|S+A|find-all-classes.js|Dump all classes used by the app|1.0|
|9|S+A|find-app-classes-methods.js|Dump all methods inside classes owned by the app only|1.0|
|10|S+A|find-app-classes.js|Dump classes owned by the app only|1.0|
|11|S+A|find-specific-method.js|Find a specific method in all classes|1.0|
|12|S+A|flutter_trace_function.js|iOS flutter trace function|1.0|
|13|S+A|hook-all-methods-of-all-classes-app-only.js|Hook all the methods of all the classes owned by the app|1.0|
|14|S+A|hook-all-methods-of-specific-class.js|Hook all the methods of a particular class|1.0|
|15|S+A|hook-specific-method-of-class.js|Hook a particular method of a specific class|1.0|
|16|S+A|intercept-nslog.js|Intercept calls to Apple's NSLog logging function|1.0|
|17|S+A|ios-app-static-analysis.js|iOS app static analysis|1.0|
|18|S|ios-biometric-bypass.js|iOS Biometric Bypass|1.0|
|19|S+A|ios-intercept-crypto-2.js|iOS Intercepts Crypto Operations 2|1.0|
|20|S+A|ios-intercept-crypto.js|iOS Intercepts Crypto Operations|1.0|
|21|S+A|ios-list-apps.js|iOS List Application|1.0|
|22|S+A|ios-url-scheme-fuzzing.js|iOS URL Scheme Fuzzing|1.0|
|23|S+A|pasteboard-monitoring.js|Monitor usage of pasteboard. Useful to show lack of secure attribute on sensitive fields allowing data copying.|1.0|
|24|S+A|raptor_frida_ios_autoIntercept.js|Raptor frida ios auto intercept|1.0|
|25|S+A|raptor_frida_ios_bypass1.js|Raptor frida ios bypass 1|1.0|
|26|S+A|raptor_frida_ios_bypass2.js|Raptor frida ios bypass 2|1.0|
|27|S+A|raptor_frida_ios_call.js|Raptor frida ios call|1.0|
|28|S+A|raptor_frida_ios_debug.js|Raptor frida ios debug|1.0|
|29|S+A|raptor_frida_ios_enum.js|Raptor frida ios enum|1.0|
|30|S+A|raptor_frida_ios_lowlevel1.js|Raptor frida ios low level 1|1.0|
|31|S+A|raptor_frida_ios_lowlevel2.js|Raptor frida ios low level 2|1.0|
|32|S+A|raptor_frida_ios_stalker.js|Raptor frida ios stalker|1.0|
|33|S+A|raptor_frida_ios_touchid.js|Raptor frida ios touchid|1.0|
|34|S+A|raptor_frida_ios_trace.js|Raptor frida ios trace|1.0|
|35|S+A|read-nsuserdefaults.js|Show contents of NSUserDefaults|1.0|
|36|S+A|read-plist-file.js|Show contents of a Plist file|1.0|
|37|S|replace-exported-method.js|Replace a module's exported function|1.0|
|38|S+A|show-all-methods-of-specific-class.js|Dump all methods of a particular class|1.0|
|39|S+A|show-argument-type-count-and-return-value-type.js|Show argument type & count and type of return value for a function in a class|1.0|
|40|S+A|show-instance-variables-for-specific-class.js|Show all instance variables of a particular class|1.0|
|41|S+A|show-modify-function-arguments.js|Show and modify arguments of a function inside a class|1.0|
|42|S+A|show-modify-method-return-value.js|Show and modify return value of a particular method inside a class|1.0|
|43|S+A|show_binarycookies.js|Show contents of Cookies.binarycookies file|1.0|

## Hexbytescan-Task
|N|Task Name| Task Description|
|:---|:---|:---|
|1|openssl_hook.json|OpenSSL 1.0.2 certificate pinning hook on arm64|
|2|openssl_1_1_0_hook.json|OpenSSL 1.1.0 certificate pinning hook for arm64, it modifies cmp instruction in tls_process_server_certificate method|
|3|openssl_hook_v2.json|OpenSSL 1.0.2 certificate pinning hook on arm64, improved pattern, possibly for different compiler version or slightly updated OpenSSL, use if first version does not find patch location. These hooks patch call to ssl_verify_cert_chain in ssl3_get_server_certificate.|

## Disclaimer
Because I am not a developer, so my coding skills might not be the best. Therefore, if this tool have any issue or not working for you, create an issue and i will try to fix it.
Any suggestions for new feature and discussions are welcome!

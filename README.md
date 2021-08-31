<img width="538" alt="image" src="https://user-images.githubusercontent.com/31820707/103606590-5f006380-4f49-11eb-9f57-c1c78c76a506.png">

# Frida iOS hook

A script that helps you trace classes, functions, and modify the return values of methods on iOS platform.

For Android platform: https://github.com/noobpk/frida-android-hook

Currently I'm moving the intercept api functionality to a separate repository : https://github.com/noobpk/frida-ios-intercept-api

## Env OS Support
| OS      | Supported          | Noted   |
| ------- | ------------------ | ------- |
| MacOS   | :white_check_mark: | main	 |
| Linux   | :white_check_mark: | sub  	 |
| Windows | :white_check_mark: | sub	 |

## Compatible with
| iOS      |   Frida  | Supported         |
| -------- | -------- | ----------------- |
|  13.2.3  | 14.2.13  | :white_check_mark:|
|  14.4.2  | 14.2.13  | :white_check_mark:|
|  14.4.2  | 15.0.18  | :white_check_mark:|

## Feature

Running with python3.x

Support both spawn & attach script to process.

```
[+] Options:

	-p(--package)			Identifier of application ex: com.apple.AppStore
	-n(--name) 			Name of application ex: AppStore
	-s(--script) 			Using script format script.js
	-c(--check-version) 		Check for the newest version
	-u(--upadte) 			Update to the newest version
	
	[*] Dump decrypt IPA:
	
    	-d, --dump         Dump decrypt application.ipa
    	-o OUTPUT_IPA, --output=OUTPUT_IPA
                           Specify name of the decrypted IPA
	
	[*] Dump memory of Application:
	
	--dump-memory		Dump memory of application
	
	[*] HexByte Scan IPA:
	--hexbyte-scan		Scan or Patch IPA with byte patterns
	-t TASK, --task=TASK
          			Task for hexbytescan
	
	[*] Information:

	--list-devices    List All Devices
	--list-apps       List The Installed apps
	--list-appinfo    List Info of Apps on Itunes
	--list-scripts    List All Scripts

	[*] Quick method:

	-m(--method)			Support commonly used methods
				- app-static(-n)
				- bypass-jb(-p)
				- bypass-ssl(-p)
				- i-url-req(-p)
				- i-crypto(-n)
```

## Update

Version: 3.5-beta
```
	[+] Change:
	
		[-] Update example usage
		
		[-] Optimize core hook.py
		
		[-] Update README.md
		
		
	[+] New:
	
		[-] Add new new option hexbytescan
	
```

## Install & Usage

```
	[+] Latest version
	
		https://github.com/noobpk/frida-ios-hook/releases
		
	[+] Develop version
	
		1. Git clone https://github.com/noobpk/frida-ios-hook
		2. cd frida-ios-hook/frida-ios-hook
		3. chmod +x ioshook
		4. ./ioshook --help(-h)
		5. rebellion :))
```

If you run the script but it doesn't work, you can try the following:
```frida -U -f package -l script.js```

## Demo Feature
1. Part 1 [List application, Dump decrypt application, Dump Memory application] : https://youtu.be/7D5OuKAUQ_s
2. Part 2 [Static Analysis Application, Intercept URL Request] : https://youtu.be/xd685sCMqSw
3. Part 3 [Bypass Jailbreak Detection] : https://youtu.be/DAJywMZ9nHg

## Frida-Script

Updated some frida scripts to help you with the pentest ios app. Filter script using spawn(S) or attach(A) 

|N|Spawn/Attach|Script Name| Script Description|
|:---|:---|:---|:---|
|1|S|bypass-jailbreak-1.js|Basic bypass jailbreak detection|
|2|S|dump-ios-url-scheme.js|Dump iOS url scheme when "openURL" is called|
|3|S|dump-ui.js|Dump the current on-screen User Interface structure|
|4|S+A|find-all-classes.js|Dump all classes used by the app|
|5|S+A|find-all-methods-all-classes.js|Dump all methods inside all classes|
|6|S+A|find-specific-method.js|Find a specific method in all classes|
|7|S+A|hook-all-methods-of-specific-class.js|Hook all the methods of a particular class|
|8|S+A|hook-specific-method-of-class.js|Hook a particular method of a specific class|
|9|S+A|ios-app-static-analysis.js|iOS app static analysis|
|10|S+A|ios-list-apps.js|iOS list information application|
|11|S+A|ios-url-scheme-fuzzing.js|iOS url scheme fuzzing|
|12|S|pasteboard-monitoring.js|Monitor usage of pasteboard. Useful to show lack of secure attribute on sensitive fields allowing data copying.|
|13|A|read-nsuserdefaults.js|Show contents fo NSUserDefaults|
|14|S+A|show-all-methods-of-specific-class.js|Dump all methods of a particular class|
|15|S+A|show-argument-type-count-and-return-value-type.js|Show argument type & count and type of return value for a function in a class|
|16|S+A|show-instance-variables-for-specific-class.js|Show all instance variables of a particular class|
|17|S+A|show-modify-function-arguments.js|Show and modify arguments of a function inside a class|
|18|S+A|show-modify-method-return-value.js|Show and modify return value of a particular method inside a class|
|19|A|show_binarycookies.js|Show contents of Cookies.binarycookies file|
|20|S|bypass-ssl-ios13.js|iOS13 bypass ssl pinning|
|21|S|flutter_trace_function.js|iOS flutter trace function|
|22|S+A|ios-intercept-crypto.js|Intercepts Crypto Operations|
|23|S+A|ios-intercept-crypto-2.js|Intercepts Crypto Operations 2|
|24|S|bypass-flutter-ssl.js|Flutter bypass ssl pinning|

## Hexbytescan-Task
|N|Task Name| Task Description|
|:---|:---|:---|
|1|openssl_hook.json|OpenSSL 1.0.2 certificate pinning hook on arm64|
|2|openssl_1_1_0_hook.json|OpenSSL 1.1.0 certifiate pinning hook for arm64, it modifies cmp instruction in tls_process_server_certificate method|
|3|openssl_hook_v2.json|OpenSSL 1.0.2 certificate pinning hook on arm64, improved pattern, possibly for different compiler version or slighlty updated OpenSSL, use if first version does not find patch location. These hooks patch call to ssl_verify_cert_chain in ssl3_get_server_certificate.|

## Disclaimer
Because I am not a developer, so my coding skills might not be the best. Therefore, if this tool have any issue or not working for you, create an issue and i will try to fix it.
Any suggestions for new feature and discussions are welcome!

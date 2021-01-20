<img width="538" alt="image" src="https://user-images.githubusercontent.com/31820707/103606590-5f006380-4f49-11eb-9f57-c1c78c76a506.png">

# Frida iOS hook

A script that helps you trace classes, functions, and modify the return values of methods on iOS platform.

For Android platform: https://github.com/noobpk/frida-android-hook

## Feature

Running with python3.x

Support both spawn & attach script to process.

```
[+] Options:

	-p(--package)			Identifier of application ex: com.apple.AppStore
	-n(--name) 			Name of application ex: AppStore
	-s(--script) 			Using script format javascript.js
	-d(--dump)			Dump decrypt application.ipa
	-c(--check-version) 		Check for the newest version
	-u(--upadte) 			Update to the newest version

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

Version: 3.3
```
	[+] Change:
	
		[-] Update new interface and command usage
		
		[-] Optimize core hook.py
		
		[-] Update README.md
		
		
	[+] New:
	
		[-] Add new method Intercept Crypto in application
	
```

## Install & Usage

```
	1. Git clone https://github.com/noobpk/frida-ios-hook
	2. cd frida-ios-hook/
	3. python3 hook.py --help(-h)
	4. rebellion :))
```

If you run the script but it doesn't work, you can try the following:
```frida -U -f package -l script.js```

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

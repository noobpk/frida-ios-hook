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
	-c(--check-version) 		Check for the newest version
	-u(--upadte) 			Update to the newest version

	[*] Information:

	--list-devices    List All Devices
	--list-apps       List The Installed apps
	--list-appinfo    List Info of Apps on Itunes
	--list-scripts    List All Scripts

	[*] Quick method:

	-m(--method)			Support commonly used methods
				-app-static(-n)
				-bypass-jb(-p)
				-bypass-ssl(-p)
```

## Update

Version: 3.2b
```
	[+] Change:
	
		[-] Update new interface and command usage
		
		[-] Update README.md
		
	[+] New:
	
		[-] Add option -c(--check-version) and -u(--update)
	
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

|Spawn/Attach|Script Name| Script Description|
|:---|:---|:---|
|S|bypass-jailbreak-1.js|Basic bypass jailbreak detection|
|S|dump-ios-url-scheme.js|Dump iOS url scheme when "openURL" is called|
|S|dump-ui.js|Dump the current on-screen User Interface structure|
|S+A|find-all-classes.js|Dump all classes used by the app|
|S+A|find-all-methods-all-classes.js|Dump all methods inside all classes|
|S+A|find-specific-method.js|Find a specific method in all classes|
|S+A|hook-all-methods-of-specific-class.js|Hook all the methods of a particular class|
|S+A|hook-specific-method-of-class.js|Hook a particular method of a specific class|
|S+A|ios-app-static-analysis.js|iOS app static analysis|
|S+A|ios-list-apps.js|iOS list information application|
|S+A|ios-url-scheme-fuzzing.js|iOS url scheme fuzzing|
|S|pasteboard-monitoring.js|Monitor usage of pasteboard. Useful to show lack of secure attribute on sensitive fields allowing data copying.|
|A|read-nsuserdefaults.js|Show contents fo NSUserDefaults|
|S+A|show-all-methods-of-specific-class.js|Dump all methods of a particular class|
|S+A|show-argument-type-count-and-return-value-type.js|Show argument type & count and type of return value for a function in a class|
|S+A|show-instance-variables-for-specific-class.js|Show all instance variables of a particular class|
|S+A|show-modify-function-arguments.js|Show and modify arguments of a function inside a class|
|S+A|show-modify-method-return-value.js|Show and modify return value of a particular method inside a class|
|A|show_binarycookies.js|Show contents of Cookies.binarycookies file|
|S|bypass-ssl-ios13.js|iOS13 bypass ssl pinning|
|S|flutter_trace_function.js|iOS flutter trace function|

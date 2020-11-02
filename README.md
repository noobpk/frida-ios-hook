# Frida ios hook
A script that helps you trace classes, functions, and modify the return values of methods on iOS platform

For Android platform: https://github.com/noobpk/frida-android-hook

<img width="1018" alt="image" src="https://user-images.githubusercontent.com/31820707/97841353-3aed8f80-1d18-11eb-9047-b31cad44b0c0.png">
## Update

[Version: 3.2]

​	[+] Update new interface and command usage

​	[+] New feature:

        [+] Add new options: 
        
            [-] -n(--name) for attach function in frida
            
            [-] -m(--method) using for option -n(--name)
            
            [-] --listdevices : List All Devices
            
            [-] --listappinfo : List Information of All Apps install on Itunes
            
            [-] --listscripts : List All Scripts

            [-] Update script for trace_class, trace_method, return_value

            [-] Add new script hooking.js

Updated some frida scripts to help you with the pentest ios app. Filter script using spawn or attach 

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

## Usage
1. Git clone https://github.com/noobpk/frida-ios-hook
1. cd frida-ios-hook/
1. ```python3 hook.py --help(-h)```

If you run the script but it doesn't work, you can try the following:
```frida -U -f package -l script.js```

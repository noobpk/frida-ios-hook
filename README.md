# Frida ios hook
A script that helps you trace classes, functions, and modify the return values of methods

## Update
Updated some frida scripts to help you with the pentest ios app

|Script Name| Script Description|
|:---|:---|
|bypass-jailbreak-1.js|Basic bypass jailbreak detection|
|dump-ios-url-scheme.js|Dump iOS url scheme when "openURL" is called|
|dump-ui.js|Dump the current on-screen User Interface structure|
|find-all-classes.js|Dump all classes used by the app|
|find-all-methods-all-classes.js|Dump all methods inside all classes|
|find-specific-method.js|Find a specific method in all classes|
|frida_python_script.py|Python script to run Frida scripts|
|frida_without_jailbreak_ipa.png|Screenshot from Reddit for using Frida without jailbreak|
|hook-all-methods-of-specific-class.js|Hook all the methods of a particular class|
|hook-specific-method-of-class.js|Hook a particular method of a specific class|
|ios-app-static-analysis.js|iOS app static analysis|
|pasteboard-monitoring.js|Monitor usage of pasteboard. Useful to show lack of secure attribute on sensitive fields allowing data copying.|
|read-nsuserdefaults.js|Show contents fo NSUserDefaults|
|show-all-methods-of-specific-class.js|Dump all methods of a particular class|
|show-argument-type-count-and-return-value-type.js|Show argument type & count and type of return value for a function in a class|
|show-instance-variables-for-specific-class.js|Show all instance variables of a particular class|
|show-modify-function-arguments.js|Show and modify arguments of a function inside a class|
|show-modify-method-return-value.js|Show and modify return value of a particular method inside a class|
|show_binarycookies.js|Show contents of Cookies.binarycookies file|

## Usage
1. Git clone https://github.com/noobpk/frida-ios-hook
1. cd frida-ios-hook/
1. ```python3 hook.py <package> <script>```

If you run the script but it doesn't work, you can try the following:
```frida -U -f package -l script.js```
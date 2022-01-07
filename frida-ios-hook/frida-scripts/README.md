# Frida scripts for iOS app testing

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

Reference: https://github.com/interference-security/frida-scripts/tree/master/iOS

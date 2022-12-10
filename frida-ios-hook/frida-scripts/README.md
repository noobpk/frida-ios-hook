# Frida scripts for iOS app testing

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

## Credit

➡️ [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts/tree/master/android)

➡️ [0xdea/frida-scripts](https://github.com/0xdea/frida-scripts/tree/master/android-snippets)

➡️ [Frida CodeShare](https://codeshare.frida.re/browse)

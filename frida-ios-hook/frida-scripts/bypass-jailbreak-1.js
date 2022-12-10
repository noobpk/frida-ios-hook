/* Description: Basic bypass jailbreak detection
 * Mode: S
 * Version: 1.0
 * Credit: https://github.com/noobpk/frida-ios-hook/tree/master/frida-ios-hook/frida-scripts
 * Author: @noobpk
 */
function bypassJailbreakDetection() {
	try {
		var className = "JailbreakDetection";
        var funcName = "+ isJail";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
          onLeave: function(retval) {
            console.log("[*] Class Name: " + className);
            console.log("[*] Method Name: " + funcName);
            console.log("\t[-] Type of return value: " + typeof retval);
            console.log("\t[-] Original Return Value: " + retval);
            retval.replace(0x0);
            console.log("\t[-] Type of return value: " + typeof retval);
            console.log("\t[-] Return Value: " + retval);
          }
        });

	} catch(err) {
		console.log("[-] Error: " + err.message);
	}
}

if (ObjC.available) {
	bypassJailbreakDetection();
} else {
 	send("error: Objective-C Runtime is not available!");
}

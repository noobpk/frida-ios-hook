/* Description: Hook a particular method of a specific class
 * Mode: S+A
 * Version: 1.0
 * Credit: http://www.mopsled.com/2015/log-ios-method-arguments-with-frida/ & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Source: http://www.mopsled.com/2015/log-ios-method-arguments-with-frida/
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
//Your class name here
function hook_specific_method_of_class(className, funcName)
{
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
      onEnter: function(args) {
        // args[0] is self
        // args[1] is selector (SEL "sendMessageWithText:")
        // args[2] holds the first function argument, an NSString
        console.log("[*] Detected call to: " + className + " -> " + funcName);
        //For viewing and manipulating arguments
        //console.log("\t[-] Value1: "+ObjC.Object(args[2]));
        //console.log("\t[-] Value2: "+(ObjC.Object(args[2])).toString());
        //console.log(args[2]);
      }
    });
}

//Your class name  and function name here
hook_specific_method_of_class("className", "funcName")

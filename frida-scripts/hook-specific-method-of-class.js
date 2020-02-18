//Source: http://www.mopsled.com/2015/log-ios-method-arguments-with-frida/
if (ObjC.available)
{
    try
    {
        //Your class name here
        var className = "YOUR_CLASS_NAME_HERE";
        //Your function name here
        var funcName = "YOUR_FUNC_NAME_HERE";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
          onLeave: function(retval) {
            console.log("[*] Detected call to: " + className + " -> " + funcName);
            //For viewing and manipulating arguments
            console.log("\t[-] Type of return value: " + typeof retval);
            console.log("\t[-] Original Return Value: " + retval);;
            //modify original return value
            //newretval = ptr("0x0") 
            // retval.replace(0x0) 
            // console.log("\t[-] New Return Value: " + retval);
          }
        });
    }
    catch(err)
    {
        console.log("[!] Exception2: " + err.message);
    }
}
else
{
    console.log("Objective-C Runtime is not available!");
}

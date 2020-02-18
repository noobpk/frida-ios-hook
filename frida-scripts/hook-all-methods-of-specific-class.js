console.log("[*] Started: Hook all methods of a specific class");
if (ObjC.available)
{
    try
    {
        //Your class name here
        var className = "YOUR_CLASS_NAME_HERE";
        var methods = eval('ObjC.classes.' + className + '.$methods');
        for (var i = 0; i < methods.length; i++)
        {
            try
            {
                console.log("[-] "+methods[i]);
                try
                {
                    console.log("\t[*] Hooking into implementation");
                    //eval('var className2 = "'+className+'"; var funcName2 = "'+methods[i]+'"; var hook = eval(\'ObjC.classes.\'+className2+\'["\'+funcName2+\'"]\'); Interceptor.attach(hook.implementation, {   onEnter: function(args) {    console.log("[*] Detected call to: " + className2 + " -> " + funcName2);  } });');
                    var className2 = className;
                    var funcName2 = methods[i];
                    var hook = eval('ObjC.classes.'+className2+'["'+funcName2+'"]');
                    Interceptor.attach(hook.implementation, {
                    onEnter: function(args) {
                    console.log("[*] Detected call to: " + className2 + " -> " + funcName2);
                    }
                    });
                    console.log("\t[*] Hooking successful");
                }
                catch(err)
                {
                    console.log("\t[!] Hooking failed: " + err.message);
                }
            }
            catch(err)
            {
                console.log("[!] Exception1: " + err.message);
            }
        }
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
console.log("[*] Completed: Hook all methods of a specific class");

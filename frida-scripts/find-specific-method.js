console.log("[*] Started: Find Specific Method");
if (ObjC.available)
{
    for (var className in ObjC.classes)
    {
        try
        {
            if (ObjC.classes.hasOwnProperty(className))
            {
                try
                {
                    var methods = eval('ObjC.classes.' + className + '.$methods');
                    for (var i = 0; i < methods.length; i++)
                    {
                        try
                        {
                            //Your function name goes here
                            if(methods[i].includes("FUNCTION_NAME_HERE"))
                            {
                                console.log("[+] Class: " + className);
                                console.log("\t[-] Method: "+methods[i]);
                            }
                        }
                        catch(err)
                        {
                            console.log("[!] Exception3: " + err.message);
                        }
                    }
                }
                catch(err)
                {
                    console.log("[!] Exception2: " + err.message);
                }
            }
        }
        catch(err)
        {
            console.log("[!] Exception1: " + err.message);
        }
    }
}
else
{
    console.log("Objective-C Runtime is not available!");
}
console.log("[*] Completed: Find Specific Method");

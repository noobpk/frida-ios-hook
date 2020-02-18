console.log("[*] Started: Find Methods")
if (ObjC.available)
{
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            console.log("[+] Class: " + className);
            var methods = eval('ObjC.classes.' + className + '.$methods');
            for (var i = 0; i < methods.length; i++)
            {
                console.log("\t[-] Method: "+methods[i]);
            }
        }
    }
}
else
{
    console.log("Objective-C Runtime is not available!");
}
console.log("[*] Completed: Find Methods")

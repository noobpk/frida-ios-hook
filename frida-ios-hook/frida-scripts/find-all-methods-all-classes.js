/*
Find All Methods in All Classes v1.1
*/
function find_all_methods_in_all_classes_of_app()
{
    console.log("[*] Started: Find Methods of All Classes")
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            console.log("[+] Class: " + className);
            //var methods = eval('ObjC.classes.' + className + '.$methods');
            var methods = ObjC.classes[className].$methods;
            for (var i = 0; i < methods.length; i++)
            {
                console.log("\t[-] Method: "+methods[i]);
            }
        }
    }
    console.log("[*] Completed: Find All Methods In All Classes")
}

if (ObjC.available)
{
    setTimeout(find_all_methods_in_all_classes_of_app, 1000);
}
else
{
    console.log("Objective-C Runtime is not available!");
}

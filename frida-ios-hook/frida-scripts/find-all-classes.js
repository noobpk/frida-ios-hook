/* Description: Dump all classes used by the app
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_classes_of_app()
{
    console.log("[*] Started: Find Classes")
    var count = 0
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            console.log(className);
            count = count + 1
        }
    }
    console.log("\n[*] Classes found: " + count);
    console.log("[*] Completed: Find Classes")
}

function show_classes_of_app()
{
	setImmediate(run_show_classes_of_app)
}

show_classes_of_app()

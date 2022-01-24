/* Description: Dump all methods inside all classes
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_classes_methods_of_app()
{
    console.log("[*] Started: Find Methods of All Classes")
	for (var className in ObjC.classes)
	{
		if (ObjC.classes.hasOwnProperty(className))
		{
			console.log("[+] Class: " + className);
			//var methods = ObjC.classes[className].$methods;
			var methods = ObjC.classes[className].$ownMethods;
			for (var i = 0; i < methods.length; i++)
			{
				console.log("\t[-] Method: " + methods[i]);
				try
				{
					console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
					console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[i]].returnType);
				}
				catch(err) {}
			}
		}
	}
	console.log("[*] Completed: Find Methods of All Classes")
}

function show_classes_methods_of_app()
{
	setImmediate(run_show_classes_methods_of_app)
}

show_classes_methods_of_app()

/* Description: Hook all the methods of a particular class
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function hook_class_method(class_name, method_name)
{
	var hook = ObjC.classes[class_name][method_name];
		Interceptor.attach(hook.implementation, {
			onEnter: function(args) {
			console.log("[*] Detected call to: " + class_name + " -> " + method_name);
		}
	});
}

function run_hook_all_methods_of_specific_class(className_arg)
{
	console.log("[*] Started: Hook all methods of a specific class");
	console.log("[+] Class Name: " + className_arg);
	//Your class name here
	var className = className_arg;
	//var methods = ObjC.classes[className].$methods;
	var methods = ObjC.classes[className].$ownMethods;
	for (var i = 0; i < methods.length; i++)
	{
		console.log("[-] "+methods[i]);
		console.log("\t[*] Hooking into implementation");
		//eval('var className2 = "'+className+'"; var funcName2 = "'+methods[i]+'"; var hook = eval(\'ObjC.classes.\'+className2+\'["\'+funcName2+\'"]\'); Interceptor.attach(hook.implementation, {   onEnter: function(args) {    console.log("[*] Detected call to: " + className2 + " -> " + funcName2);  } });');
		var className2 = className;
		var funcName2 = methods[i];
		hook_class_method(className2, funcName2);
		console.log("\t[*] Hooking successful");
	}
	console.log("[*] Completed: Hook all methods of a specific class");
}

function hook_all_methods_of_specific_class(className_arg)
{
	setImmediate(run_hook_all_methods_of_specific_class,[className_arg])
}

//Your class name goes here
hook_all_methods_of_specific_class("YOUR_CLASS_NAME_HERE")

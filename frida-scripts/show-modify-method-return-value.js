function show_modify_function_return_value(className_arg, funcName_arg)
{
    var className = className_arg;
    var funcName = funcName_arg;
    var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
    Interceptor.attach(hook.implementation, {
      onLeave: function(retval) {
        console.log("\n[*] Class Name: " + className);
        console.log("[*] Method Name: " + funcName);
        console.log("\t[-] Type of return value: " + typeof retval);
        //console.log(retval.toString());
        console.log("\t[-] Return Value: " + retval);
        //For modifying the return value
        var newretval = ptr("0x0") //your new return value here
        retval.replace(newretval)
        console.log("\t[-] New Return Value: " + newretval)
      }
    });
}
//YOUR_CLASS_NAME_HERE and YOUR_EXACT_FUNC_NAME_HERE
show_modify_function_return_value("YOUR_CLASS_NAME_HERE" ,"YOUR_EXACT_FUNC_NAME_HERE")

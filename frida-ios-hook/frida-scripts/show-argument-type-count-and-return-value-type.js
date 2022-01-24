/* Description: Show argument type & count and type of return value for a function in a class
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security

function show_method_args_return_type(className, methodName)
{
  console.warn("[*] Show number and type of arguments for the function")
  //ObjC.classes["DamnVulnerableAppUtilities"]["+ showAlertForJailbreakTestIsJailbroken:"].argumentTypes
  console.log(ObjC.classes[className][methodName].argumentTypes)

  console.warn("[*] Show type of return value for the function")
  //ObjC.classes["JailbreakDetectionVC"]["- isJailbroken"].returnType
  console.log(ObjC.classes[className][methodName].returnType)
}

//Your class name and method name here
show_method_args_return_type("CLASS_NAME_HERE", "METHOD_NAME_HERE")

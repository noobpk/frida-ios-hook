/* Description: Show contents of NSUserDefaults
 * Mode: S+A
 * Version: 1.0
 * Credit: Objection (https://github.com/sensepost/objection/blob/master/objection/commands/ios/nsuserdefaults.py) & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Credit: Objection (https://github.com/sensepost/objection/blob/master/objection/commands/ios/nsuserdefaults.py)
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
console.warn("[*] Started: Read NSUserDefaults PLIST file");
if (ObjC.available)
{
    try
    {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        var NSDictionary = NSUserDefaults.alloc().init().dictionaryRepresentation();
        console.log(NSDictionary.toString())
    }
    catch(err)
    {
        console.warn("[!] Exception: " + err.message);
    }
}
else
{
    console.warn("Objective-C Runtime is not available!");
}
console.warn("[*] Completed: Read NSUserDefaults PLIST file");

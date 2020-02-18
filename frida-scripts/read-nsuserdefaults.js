//Credit: https://github.com/sensepost/objection/blob/b39ee53b5ba2e9a271797d2f3931d79c46dccfdb/objection/commands/ios/nsuserdefaults.py
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

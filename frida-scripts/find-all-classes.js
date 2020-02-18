function show_classes_of_app()
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
show_classes_of_app()

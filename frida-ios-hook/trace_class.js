/*
Description:
Search for classes
* If no strings are specified in "search_class" array, the script will print all the classes.
* If one or more strings are specified in "search_class array", the script will only print classes which contains the strings in their name.
*/


var search_class = [''];

if (ObjC.available)
{
    console.log('*** Tracing classes ***')

    for (var className in ObjC.classes) {
        if (Array.isArray(search_class) && search_class.length) {
            for (var i = 0; i < search_class.length; i++) {
                if (className.toLowerCase().includes(search_class[i].toLowerCase())) {
                    console.log(className)
                }
            }
        }
        else {
            console.log(className);
        }
    }
}
else {
    console.log('Objective-C Runtime is not available!');
}

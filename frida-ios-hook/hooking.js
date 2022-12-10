/*
Description:
Hooks into methods
* Given one or more classes in "search_class", it hooks into all their methods.
* Given one or more methods in "search_method", it hooks into all methods of any classes that meet with the search criteria.
* Given a class and a method, it hooks into the method of this class.
* Neither class nor method full name is needed in order to hook. If a partial string is given, the script will hook into all the methods that have the string in their name.
*/

var search_class = [''];
var search_method = [''];

var colors = {
    "resetColor": "\x1b[0m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "red": "\x1b[31m"
}

function search_methods(className) {
    var methods_found = [];
    var methods = ObjC.classes[className].$ownMethods;
    if (Array.isArray(search_method) && search_method.length) { //search_method not empty
        for (var j = 0; j < search_method.length; j++) {
            if (methods.join(' ').toLowerCase().includes(search_method[j].toLowerCase())) {
                for (var i = 0; i < methods.length; i++){
                    if (methods[i].toLowerCase().includes(search_method[j].toLowerCase())) {
                        methods_found.push(methods[i]);
                    }
                }
            }
        }
    }
    else {
        var methods = ObjC.classes[className].$ownMethods;
        for (var i = 0; i < methods.length; i++){
            methods_found.push(methods[i]);
        }
    }
    return methods_found;
}

function search_classes(){
    var classes_found = [];
    for (var className in ObjC.classes) {
        if (Array.isArray(search_class) && search_class.length) {
            for (var i = 0; i < search_class.length; i++) {
                if (className.toLowerCase().includes(search_class[i].toLowerCase())) {
                    classes_found.push(className);
                }
            }
        }
    }
    return classes_found;
}

function print_arguments(args) {
/*
Frida's Interceptor has no information about the number of arguments, because there is no such
information available at the ABI level (and we don't rely on debug symbols).

I have implemented this function in order to try to determine how many arguments a method is using.
It stops when:
    - The object is not nil
    - The argument is not the same as the one before
 */
    var n = 100;
    var last_arg = '';
    for (var i = 2; i < n; ++i) {
        var arg = (new ObjC.Object(args[i])).toString();
        if (arg == 'nil' || arg == last_arg) {
            break;
        }
        last_arg = arg;
        console.log('\t[-] arg' + i + ': ' + (new ObjC.Object(args[i])).toString());
    }
}

if (ObjC.available)
{
    console.log(colors.green,"\n[*] Started: Hooking.... ",colors.resetColor);
    var classes_found = search_classes();
    for (var i = 0; i < classes_found.length; ++i) {
        var methods_found = 0;
        methods_found = search_methods(classes_found[i]);

        if (Object.keys(methods_found).length){
            console.log(classes_found[i]);
        }
        for (var j = 0; j < methods_found.length; ++j) {
            var _className = "" + classes_found[i];
            var _methodName = "" + methods_found[j];
            var hooking = ObjC.classes[_className][_methodName];
            console.log('   ' + methods_found[j]);

            Interceptor.attach(hooking.implementation, {
                onEnter: function (args) {
                    this._className = ObjC.Object(args[0]).toString();
                    this._methodName = ObjC.selectorAsString(args[1]);
                    console.log(colors.green,"[+] Detected call to: ",colors.resetColor);
                    console.log('   ' + this._className + ' --> ' + this._methodName);
                    console.log(colors.green,"[+] Dump Arugment in method: ",colors.resetColor);
                    // print_arguments(args);
                    // console.log(ObjC.Object(args[2]));
                    // var data = new ObjC.Object(args[2]);
                    console.log(colors.green,"[+] Arugment type: ",colors.resetColor);
                    // console.log(data.$className);
                    /* Converting NSData to String */
                    // var buf = data.bytes().readUtf8String(data.length());
                    console.log(colors.green,"[+] NSData to String: ",colors.resetColor);
                    // console.log(buf);
                    /* Converting NSData to Binary Data */
                    // var buf = data.bytes().readByteArray(data.length());
                    console.log(colors.green,"[+] NSData to Binary Data: ",colors.resetColor);
                    // console.log(hexdump(buf, { ansi: true }));

                },
                onLeave: function(returnValues) {
                    console.log(colors.green,"Return value of: ",colors.resetColor);
                    console.log('   ' + this._className + ' --> ' + this._methodName);
                    console.log(colors.green,"\t[-] Type of return value: ",colors.resetColor + Object.prototype.toString.call(returnValues));
                    console.log(colors.green,"\t[-] Return Value: ",colors.resetColor + returnValues);
                }
            });
        }

    }
    console.log('\n[*] Starting Intercepting');
}
else {
    console.log('Objective-C Runtime is not available!');
}

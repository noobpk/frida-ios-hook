
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
                onEnter: function (args, state) {
                    this._className = ObjC.Object(args[0]).toString();
                    this._methodName = ObjC.selectorAsString(args[1]);
                    console.log(colors.green,"[+] Detected call to: ",colors.resetColor);
                    console.log('   ' + this._className + ' --> ' + this._methodName);
                    console.log(colors.green,"[+] Dump Arugment in method: ",colors.resetColor);
                    //print_arguments(args);
                    // console.log(ObjC.Object(args[3]));
                    // var message1 = ObjC.Object(args[2]);
                    // var message2 = ObjC.Object(args[3]);
                    // var message3 = ObjC.Object(args[4]);

                    // console.log('msg1=' + message1.toString() + ",type: "+ message1.$className);
                    // console.log('msg2=' + message2.toString() + ",type: "+ message2.$className);
                    // console.log('msg3=' + message3.toString() + ",type: "+ message3.$className);
                    

                    this.buf = ObjC.Object(args[3]).toString();

                    var js = {};
                    var dict = new ObjC.Object(args[3]);
                    var enumerator = dict.keyEnumerator();
                    var key;
                    while((key = enumerator.nextObject()) !== null){
                        var value = dict.objectForKey_(key);
                        js[key] = value.toString();
                    }

                    console.log('js:', JSON.stringify(js));

                    send({from: '/http', payload: JSON.stringify(js)})
                    var op = recv('input', function(value) { // callback function
                        console.log("Forwarding mitm'ed content: " + value.payload);
                        var js = JSON.parse(value.payload);
                        console.log('js response:', js);
                        var param_dict = ObjC.classes.NSMutableDictionary.alloc().init();
                        var NSString = ObjC.classes.NSString;    
                        for(var key in js){
                            if(js.hasOwnProperty(key)){
                                console.log(key + " -> " + js[key]);
                                var valueObject = NSString.stringWithString_(js[key]); 
                                param_dict.setObject_forKey_(valueObject, key);
                            }
                        }
                        console.log('param_dict:', param_dict);
                        args[3] = param_dict;
                    });
                    op.wait();
                },
                onLeave: function(retval, state) {
                    
                }
            });
        }

    }
    console.log('\n[*] Starting Intercepting');
}
else {
    console.log('Objective-C Runtime is not available!');
}
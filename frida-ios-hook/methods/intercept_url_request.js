
var colors = {
            "resetColor": "\x1b[0m",
            "green": "\x1b[32m",
            "yellow": "\x1b[33m",
            "red": "\x1b[31m"
    }

if (ObjC.available) {
    console.log(colors.green,"[*] Started: Listening For Requests...",colors.resetColor);

    try {

        var className = "NSURLSession";
        var funcName = "- dataTaskWithRequest:completionHandler:";

        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        var OGCompletionHandler_DTWRM = null;

        Interceptor.attach(hook.implementation, {

            onEnter: function(args)
            {
                console.log("-".repeat(20));
                console.log(colors.green,"[+] HTTPMethod: ",colors.resetColor + ObjC.Object(args[2]).HTTPMethod() );
                console.log(colors.green,"[+] URL: ",colors.resetColor + ObjC.Object(args[2]).URL().absoluteString() );

                var httpbody_nsdata = ObjC.Object(args[2]).HTTPBody();
                var httpbody_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(httpbody_nsdata, 4);

                console.log(colors.green,"[+] HTTPBody (NSData): ",colors.resetColor + httpbody_nsdata);

                if (httpbody_nsstring += null) {
                    console.log (colors.green,"[+] HTTPBody (NSString): ",colors.resetColor + httpbody_nsstring);
                    console.log("");
                } else{
                    console.log(colors.yellow,"[!] HTTPBody Empty",colors.resetColor);
                }
                //SHOW RESPONSE - SOMETIME IT CAN MAKE APP CRASH :))
                var completionHandler = new ObjC.Block(args[3]);
                    OGCompletionHandler_DTWRM = completionHandler.implementation;

                    completionHandler.implementation = function(data_nsdata, response_nsurlresponse, error_nserror){
                            console.log(colors.green,"[+] Response Headers: ",colors.resetColor + ObjC.Object(response_nsurlresponse));
                            // Convert NSData to NSString
                            var data_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(data_nsdata, 4);

                            if (data_nsstring += null) {
                                console.log(colors.green,"[+] Response Data: ",colors.resetColor + data_nsstring);
                                console.log("");
                            } else{
                                console.log(colors.yellow,"[!] Response Data Empty",colors.resetColor);
                            }

                            // return original completion handler
                            return OGCompletionHandler_DTWRM(data_nsdata, response_nsurlresponse, error_nserror);
                    }
                console.log("-".repeat(20));
            }
        });

    }
    catch(error)
    {
        console.log(colors.red,"[!] Exception: ",colors.resetColor + error.message);
    }
    //NSURLRequest
    try {

        var className = "NSURLRequest";
        var funcName = "- initWithURL:";

        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');

        Interceptor.attach(hook.implementation, {


            onEnter: function(args) {
                console.log(colors.green,"NSURLRequest with URL: ",colors.resetColor + ObjC.Object(args[2]));
            },

        });

    } catch (error) {
        console.log(colors.red,"[!] Exception: ",colors.resetColor + error.message);
    }

    try {

        var className = "SRWebSocket";//"LGSRWebSocket";
        var funcName = "- send:";

        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');


        Interceptor.attach(hook.implementation, {


            onEnter: function(args) {
                var socketURL = ObjC.Object(args[0]).url().absoluteString().toString();
                var data = ObjC.Object(args[2]);

                console.log('LGSRWebSocket (' + ObjC.Object(args[0]) + ') ---> ' + socketURL);
                console.log('Data: ' + data);

                for (var i = 0; i < data.length(); i++) {
                    console.log(data.characterAtIndex_(i).toString(16) + ' --> ' + data.characterAtIndex_(i).toString());
                }
            },

        });

    } catch (error) {
        console.log(colors.red,"[!] Exception: ",colors.resetColor + error.message);
    }

    try {

        var className = "SRWebSocket";//"LGSRWebSocket";
        var funcName = "- _handleMessage:";

        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');

        Interceptor.attach(hook.implementation, {


            onEnter: function(args) {
                console.log(colors.green,"LGSRWebSocket received: ",colors.resetColor + ObjC.Object(args[2]));
            },

        });

    } catch (error) {
        console.log(colors.red,"[!] Exception: ",colors.resetColor + error.message);
    }
    //Cordova
    try {

        var className = "CDVInvokedUrlCommand";
        var funcName = "+ commandFromJson:";

        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');

        Interceptor.attach(hook.implementation, {


            onEnter: function(args) {
                console.log(colors.green,"CDVInvokedUrlCommand with data: ",colors.resetColor + ObjC.Object(args[2]));
            },

        });

    } catch (error) {
        console.log(colors.red,"[!] Exception: ",colors.resetColor + error.message);
    }
}

else {

console.log(colors.red,"Objective-C Runtime is not available!",colors.resetColor);

}

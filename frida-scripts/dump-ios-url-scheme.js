// Get a reference to the openURL selector
var openURL = ObjC.classes.UIApplication["- openURL:"];

// Intercept the method
Interceptor.attach(openURL.implementation, {
  onEnter: function(args) {
    // As this is an ObjectiveC method, the arguments are as follows:
    // 0. 'self'
    // 1. The selector (openURL:)
    // 2. The first argument to the openURL selector
    var myNSURL = new ObjC.Object(args[2]);
    // Convert it to a JS string
    var myJSURL = myNSURL.absoluteString().toString();
    // Log it
    console.log("Launching URL: " + myJSURL);
    //send(myJSURL);
  }
});

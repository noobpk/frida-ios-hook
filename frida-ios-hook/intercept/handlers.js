if(ObjC.available){
    var className = " "; 
    var funcName = " "; 
    var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
    Interceptor.attach(hook.implementation, { 
        onEnter: function (log, args, state) {
            console.log("read(" + "fd=" + args[0]+ ", buf=" + args[1]+ ", count=" + args[2] + ")");
            state.buf = args[1]
        },

            onLeave: function (log, retval, state) {
            send({from: '/http', payload: Memory.readUtf8String(state.buf)})
            var op = recv('input', function(value) { // callback function
                console.log("Forwarding mitm'ed content: " + value.payload)
                Memory.writeUtf8String(state.buf, value.payload)
            });
            op.wait();
        }
    }); 
    
 
    
} else {
    console.log("Objective-C Runtime is not available!");
}
var func_location_patterns = [
    ["A2 02 02 91 A3 12 44 A9 A6 C2 04 91 A5 1A 40 F9 E0 03 14 AA E1 03 13 AA ?? ?? ?? ?? F3 03 00 AA", 24],
    ["9F 02 00 71 E8 07 9F 1A 02 0C 40 A9 04 14 41 A9 06 10 40 F9 E0 03 08 AA E1 03 13 AA ?? ?? ?? ?? FD 7B 42 A9 F4 4F 41 A9 FF C3 00 91 C0 03 5F D6", 28],
];

var facebook_libs = ["FBSharedFramework", "FBSharedWithExceptionsEnabledFramework"];

function cheatVerifyWithMetrix() {
    for (var z = 0; z < facebook_libs.length; z++) {
        var fbSharedFramework = Process.findModuleByName(facebook_libs[z]);
        if (!fbSharedFramework) {
            continue;
        }
        for (var i = 0; i < func_location_patterns.length; i++) {
            var matches = Memory.scanSync(fbSharedFramework.base, fbSharedFramework.size, func_location_patterns[i][0]);
            if (matches.length == 0) {
                console.log("[i] verifyWithMetrics not found")
                continue;
            }
            var match = matches[0];
            var instructionAddress = Instruction.parse(match.address.add(func_location_patterns[i][1]));
            var verifyWithMetrix = new NativePointer(instructionAddress["operands"][0].value);
            var verifyWithMetrix_func = new NativeFunction(verifyWithMetrix, 'int', ['uint64', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(verifyWithMetrix, new NativeCallback(function(_bool, _x509_store_ctx_st, _str, _fail_cb, _succ_cb, _clock, _trace) {
                var result = verifyWithMetrix_func(_bool, _x509_store_ctx_st, _str, _succ_cb, _succ_cb, _clock, _trace);
                var result = 1;
                console.log("[i] verifyWithMetrics called!");
                return result;
            }, 'int', ['uint64', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
            console.log("[i] verifyWithMetrics hooked at " + verifyWithMetrix + "!");
            return;
        }
    }
}
cheatVerifyWithMetrix();

// Cheat FBLiger protection settings to disable fizz and SSL cache
var resetSettings = [
    "persistentSSLCacheEnabled",
    "crossDomainSSLCacheEnabled",
    "fizzEnabled",
    "fizzPersistentCacheEnabled",
    "quicFizzEarlyDataEnabled",
    "fizzEarlyDataEnabled",
    "enableFizzCertCompression"
];

function cheatFBLigerSettings() {
    var resolver = new ApiResolver('objc');
    for (var i = 0; i < resetSettings.length; i++) {
        var matches = resolver.enumerateMatchesSync("-[FBLigerConfig " + resetSettings[i] + "]");
        if (matches.length < 1) {
            console.log("[w] Failed to reset " + resetSettings[i] + ", address not found!");
            continue;
        }
        Interceptor.attach(matches[0]["address"], {
            onLeave: function(retval) {
                console.log("[i] -[FBLigerConfig *] called!");
                retval.replace(0);
            }
        });
        console.log("[i] -[FBLIgerConfig " + resetSettings[i] + "] reset!")
    }
}

// must be commented in new versions
//cheatFBLigerSettings();

// Cheat cerificate verification callcbacks from boringssl and FBSharedFramework
function cheatCallbacks() {
    var SSL_CTX_sess_set_new_cb_addr = DebugSymbol.findFunctionsNamed("SSL_CTX_sess_set_new_cb");
    var SSL_CTX_set_cert_verify_callback_addr = DebugSymbol.findFunctionsNamed("SSL_CTX_set_cert_verify_callback");
    var SSL_CTX_set_cert_verify_result_callback_addr = DebugSymbol.findFunctionsNamed("SSL_CTX_set_cert_verify_result_callback");
    var SSL_CTX_set_verify_addr = DebugSymbol.findFunctionsNamed("SSL_CTX_set_verify");
    var SSL_set_verify_addr = DebugSymbol.findFunctionsNamed("SSL_set_verify");
    var SSL_set_cert_cb_addr = DebugSymbol.findFunctionsNamed("SSL_set_cert_cb");
    var SSL_CTX_set_cert_cb_addr = DebugSymbol.findFunctionsNamed("SSL_CTX_set_cert_cb");
    var X509_STORE_CTX_set_verify_cb_addr = DebugSymbol.findFunctionsNamed("X509_STORE_CTX_set_verify_cb");


    for (var i = 0; i < SSL_CTX_set_cert_verify_callback_addr.length; i++) {
        Interceptor.replace(SSL_CTX_set_cert_verify_callback_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_CTX_set_cert_verify_callback(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_CTX_set_cert_verify_callback(...) hooked!");

    for (var i = 0; i < SSL_CTX_set_cert_verify_result_callback_addr.length; i++) {
        Interceptor.replace(SSL_CTX_set_cert_verify_result_callback_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_CTX_set_cert_verify_result_callback(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_CTX_set_cert_verify_result_callback(...) hooked!");

    for (var i = 0; i < SSL_CTX_set_verify_addr.length; i++) {
        Interceptor.replace(SSL_CTX_set_verify_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_CTX_set_verify(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_CTX_set_verify(...) hooked!");

    for (var i = 0; i < SSL_set_verify_addr.length; i++) {
        Interceptor.replace(SSL_set_verify_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_set_verify(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_set_verify(...) hooked!");

    for (var i = 0; i < SSL_set_cert_cb_addr.length; i++) {
        Interceptor.replace(SSL_set_cert_cb_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_set_cert_cb(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_set_cert_cb(...) hooked!");

    for (var i = 0; i < SSL_CTX_set_cert_cb_addr.length; i++) {
        Interceptor.replace(SSL_CTX_set_cert_cb_addr[i], new NativeCallback(function() {
            console.log("[i] SSL_CTX_set_cert_cb(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] SSL_CTX_set_cert_cb(...) hooked!");

    for (var i = 0; i < X509_STORE_CTX_set_verify_cb_addr.length; i++) {
        Interceptor.replace(X509_STORE_CTX_set_verify_cb_addr[i], new NativeCallback(function() {
            console.log("[i] X509_STORE_CTX_set_verify_cb(...) called!");
            return;
        }, 'void', []));
    }
    console.log("[i] X509_STORE_CTX_set_verify_cb(...) hooked!");
}
cheatCallbacks();

// Cheat SecTrustEvaluate, just in case :)
function cheatSecTrustEvaluate() {

    var SecTrustEvaluate_prt = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate_prt == null) {
        console.log("[e] Security!SecTrustEvaluate(...) not found!");
        return;
    }
    var SecTrustEvaluate = new NativeFunction(SecTrustEvaluate_prt, "int", ["pointer", "pointer"]);
    Interceptor.replace(SecTrustEvaluate_prt, new NativeCallback(function(trust, result) {
        console.log("[i] SecTrustEvaluate(...) called!");
        var osstatus = SecTrustEvaluate(trust, result);
        Memory.writeU8(result, 1);
        return 0;
    }, "int", ["pointer", "pointer"]));
    console.log("[i] SecTrustEvaluate(...) hooked!");
}
cheatSecTrustEvaluate();
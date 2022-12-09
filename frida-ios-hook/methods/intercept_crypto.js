/*************************************************************************************
 * Name: Intercepts Crypto Operations
 * OS: iOS
 * Author: @federicodotta
 * Source: https://github.com/federicodotta/Brida
 * Update: @noobpk
 **************************************************************************************/
var colors = {
            "resetColor": "\x1b[0m",
            "green": "\x1b[32m",
            "yellow": "\x1b[33m",
            "red": "\x1b[31m"
    }

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCrypt"),
    {
    onEnter: function(args) {

        console.log("")
        console.log(colors.green,"[*] ENTER CCCrypt",colors.resetColor);
        console.log(colors.yellow," [+] CCOperation: " + parseInt(args[0]),colors.resetColor);
        console.log(colors.yellow," [+] CCAlgorithm: " + parseInt(args[1]),colors.resetColor);
        console.log(colors.yellow," [+] CCOptions: " + parseInt(args[2]),colors.resetColor);

        if(ptr(args[3]) != 0 ) {

            console.log(colors.red," [+] Key: " + base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))),colors.resetColor);

        } else {
            console.log(colors.yellow," [!] Key: 0",colors.resetColor);
        }

        if(ptr(args[5]) != 0 ) {

            console.log(colors.red," [+] IV: " + base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)),colors.resetColor);

        } else {
            console.log(colors.yellow," [!] IV: 0",colors.resetColor);
        }

        this.dataInLength = parseInt(args[7]);

        if(ptr(args[6]) != 0 ) {

            console.log(colors.green," [+] Data in: ",colors.resetColor);
            console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[6]),this.dataInLength)));

        } else {
            console.log(colors.yellow," [!] Data in: null",colors.resetColor);
        }

        this.dataOut = args[8];
        this.dataOutLength = args[10];

    },

    onLeave: function(retval) {

        if(ptr(this.dataOut) != 0 ) {

            console.log(colors.green," [+] Data out: ",colors.resetColor);
            console.log(base64ArrayBuffer(Memory.readByteArray(this.dataOut,parseInt(ptr(Memory.readU32(ptr(this.dataOutLength),4))))));
            console.log(colors.red," [+] Decode Base64 Data out: ",colors.resetColor);
            console.log(base64_decode(base64ArrayBuffer(Memory.readByteArray(this.dataOut,parseInt(ptr(Memory.readU32(ptr(this.dataOutLength),4)))))))

        } else {
            console.log(colors.yellow," [!] Data out: null",colors.resetColor);
        }

        console.log(colors.green,"[*] EXIT CCCrypt",colors.resetColor);
        console.log("-".repeat(50))
    }

});

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorCreate"),
    {
    onEnter: function(args) {

        console.log("")
        console.log(colors.green,"[*] CCCryptorCreate ENTER",colors.resetColor);
        console.log(colors.yellow," [+] CCOperation: " + parseInt(args[0]),colors.resetColor);
        console.log(colors.yellow," [+] CCAlgorithm: " + parseInt(args[1]),colors.resetColor);
        console.log(colors.yellow," [+] CCOptions: " + parseInt(args[2]),colors.resetColor);

        if(ptr(args[3]) != 0 ) {

            console.log(colors.red," [+] Key: " + base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))),colors.resetColor);

        } else {
            console.log(colors.yellow," [!] Key: 0",colors.resetColor);
        }

        if(ptr(args[5]) != 0 ) {

            console.log(colors.red," [+] IV:" + base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)),colors.resetColor);

        } else {
            console.log(colors.yellow," [!] IV: 0",colors.resetColor);
        }

    },
    onLeave: function(retval) {

        console.log(colors.green,"[*] CCCryptorCreate EXIT",colors.resetColor);
        console.log("-".repeat(50))
    }

});


Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorUpdate"),
    {
    onEnter: function(args) {

        console.log(colors.green,"[*] CCCryptorUpdate ENTER",colors.resetColor);
        if(ptr(args[1]) != 0) {

            console.log(colors.green," [+] Data in: ",colors.resetColor);
            console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));

        } else {
            console.log(colors.yellow," [!] Data in: null",colors.resetColor);
        }

        //this.len = args[4];
        this.len = args[5];
        this.out = args[3];

    },

    onLeave: function(retval) {

        if(ptr(this.out) != 0) {

            console.log(colors.green," [+] Data out CCUpdate:",colors.resetColor);
            console.log(base64ArrayBuffer(Memory.readByteArray(this.out,parseInt(ptr(Memory.readU32(ptr(this.len),4))))));
            console.log(colors.red," [+] Decode Base64 Data out CCUpdate:",colors.resetColor);
            console.log(base64_decode(base64ArrayBuffer(Memory.readByteArray(this.out,parseInt(ptr(Memory.readU32(ptr(this.len),4)))))));
        } else {
            console.log(colors.yellow," [!] Data out: null",colors.resetColor);
        }

        console.log(colors.green,"[*] CCCryptorUpdate EXIT",colors.resetColor);
        console.log("-".repeat(50))
    }

});

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorFinal"),
    {
    onEnter: function(args) {

        console.log(colors.green,"[*] CCCryptorFinal ENTER",colors.resetColor);
        //this.len2 = args[2];
        this.len2 = args[3];
        this.out2 = args[1];
    },
    onLeave: function(retval) {
        if(ptr(this.out2) != 0) {

            console.log(colors.green," [+] Data out CCCryptorFinal:",colors.resetColor);
            console.log(base64ArrayBuffer(Memory.readByteArray(this.out2,parseInt(ptr(Memory.readU32(ptr(this.len2),4))))));
            console.log(colors.red," [+] Decode Base64 Data out CCCryptorFinal:",colors.resetColor);
            console.log(base64_decode(base64ArrayBuffer(Memory.readByteArray(this.out2,parseInt(ptr(Memory.readU32(ptr(this.len2),4)))))))

        } else {
            console.log(colors.yellow," [!] Data out: null",colors.resetColor);
        }

        console.log(colors.green,"[*] CCCryptorFinal EXIT",colors.resetColor);
        console.log("-".repeat(50))
    }

});

//CC_SHA1_Init(CC_SHA1_CTX *c);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Init"),
{
    onEnter: function(args) {
    console.log("*** CC_SHA1_Init ENTER ****");
    console.log("Context address: " + args[0]);
    }
});

//CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Update"),
{
    onEnter: function(args) {
    console.log("*** CC_SHA1_Update ENTER ****");
    console.log("Context address: " + args[0]);
    if(ptr(args[1]) != 0) {
        console.log("data:");
        console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));
    } else {
        console.log("data: null");
    }
    }
});

//CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Final"),
{
    onEnter: function(args) {
    this.mdSha = args[0];
    this.ctxSha = args[1];
    },
    onLeave: function(retval) {
    console.log("*** CC_SHA1_Final ENTER ****");
    console.log("Context address: " + this.ctxSha);
    if(ptr(this.mdSha) != 0) {
        console.log("Hash:");
        console.log(base64ArrayBuffer(Memory.readByteArray(ptr(this.mdSha),20)));

    } else {
        console.log("Hash: null");
    }
    }
});

// Native ArrayBuffer to Base64
// https://gist.github.com/jonleighton/958841
function base64ArrayBuffer(arrayBuffer) {
    var base64    = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    var bytes         = new Uint8Array(arrayBuffer)
    var byteLength    = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength    = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
    // Combine the three bytes into a single integer
    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

    // Use bitmasks to extract 6-bit segments from the triplet
    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
    b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
    c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
    d = chunk & 63               // 63       = 2^6 - 1

    // Convert the raw binary segments to the appropriate ASCII encoding
    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
    chunk = bytes[mainLength]

    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

    // Set the 4 least significant bits to zero
    b = (chunk & 3)   << 4 // 3   = 2^2 - 1

    base64 += encodings[a] + encodings[b] + '=='
    } else if (byteRemainder == 2) {
    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
    b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

    // Set the 2 least significant bits to zero
    c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

    base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }

    return base64
}

//Decode Base64
/*
 * JavaScript base64 / base64url encoder and decoder
 */

var b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"   // base64 dictionary
var b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"   // base64url dictionary
var b64pad = '='

/* base64_charIndex
 * Internal helper to translate a base64 character to its integer index.
 */
function base64_charIndex(c) {
    if (c == "+") return 62
    if (c == "/") return 63
    return b64u.indexOf(c)
}

/* base64_decode
 * Decode a base64 or base64url string to a JavaScript string.
 * Input is assumed to be a base64/base64url encoded UTF-8 string.
 * Returned result is a JavaScript (UCS-2) string.
 */
function base64_decode(data) {
    var dst = ""
    var i, a, b, c, d, z

    for (i = 0; i < data.length - 3; i += 4) {
        a = base64_charIndex(data.charAt(i+0))
        b = base64_charIndex(data.charAt(i+1))
        c = base64_charIndex(data.charAt(i+2))
        d = base64_charIndex(data.charAt(i+3))

        dst += String.fromCharCode((a << 2) | (b >>> 4))
        if (data.charAt(i+2) != b64pad)
            dst += String.fromCharCode(((b << 4) & 0xF0) | ((c >>> 2) & 0x0F))
        if (data.charAt(i+3) != b64pad)
            dst += String.fromCharCode(((c << 6) & 0xC0) | d)
    }

    dst = decodeURIComponent(escape(dst))
    return dst
}

/* Description: iOS Intercepts Crypto Operations 2
 * Mode: S+A
 * Version: 1.0
 * Credit:
 * Author:
 */
// Intercept the CCCrypt call.
Interceptor.attach(Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt'), {
    onEnter: function (args) {
        // Save the arguments
        this.operation   = args[0]
        this.CCAlgorithm = args[1]
        this.CCOptions   = args[2]
        this.keyBytes    = args[3]
        this.keyLength   = args[4]
        this.ivBuffer    = args[5]
        this.inBuffer    = args[6]
        this.inLength    = args[7]
        this.outBuffer   = args[8]
        this.outLength   = args[9]
        this.outCountPtr = args[10]

        console.log('CCCrypt(' +
            'operation: '   + this.operation    +', ' +
            'CCAlgorithm: ' + this.CCAlgorithm  +', ' +
            'CCOptions: '   + this.CCOptions    +', ' +
            'keyBytes: '    + this.keyBytes     +', ' +
            'keyLength: '   + this.keyLength    +', ' +
            'ivBuffer: '    + this.ivBuffer     +', ' +
            'inBuffer: '    + this.inBuffer     +', ' +
            'inLength: '    + this.inLength     +', ' +
            'outBuffer: '   + this.outBuffer    +', ' +
            'outLength: '   + this.outLength    +', ' +
            'outCountPtr: ' + this.outCountPtr  +')')

        if (this.operation == 0) {
            // Show the buffers here if this an encryption operation
            console.log("In buffer:")
            console.log(hexdump(ptr(this.inBuffer), {
                length: this.inLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("Key: ")
            console.log(hexdump(ptr(this.keyBytes), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("IV: ")
            console.log(hexdump(ptr(this.ivBuffer), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
        }
    },
    onLeave: function (retVal) {
        if (this.operation == 1) {
            // Show the buffers here if this a decryption operation
            console.log("Out buffer:")
            console.log(hexdump(ptr(this.outBuffer), {
                length: Memory.readUInt(this.outCountPtr),
                header: true,
                ansi: true
            }))
            console.log("Key: ")
            console.log(hexdump(ptr(this.keyBytes), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("IV: ")
            console.log(hexdump(ptr(this.ivBuffer), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
        }
    }
})

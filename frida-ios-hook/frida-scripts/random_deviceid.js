'use strict';

(function () {

  function randomUUIDv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      var v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    }).toUpperCase();
  }

  if (!ObjC.available) {
    console.log('[-] ObjC runtime not available');
    return;
  }

  const FAKE_IDFV = randomUUIDv4();
  console.log('[+] Fake IDFV:', FAKE_IDFV);

  ObjC.schedule(ObjC.mainQueue, function () {

    const NSUUID = ObjC.classes.NSUUID;
    const NSString = ObjC.classes.NSString;

    Interceptor.attach(
      NSUUID['- UUIDString'].implementation,
      {
        onLeave: function (retval) {
          try {
            const real = new ObjC.Object(retval).toString();

            // IDFV always has UUID format (36 chars)
            if (real.length === 36) {
              const fake = NSString.stringWithString_(FAKE_IDFV);
              retval.replace(fake);
            }
          } catch (e) {
            // avoid random crash
          }
        }
      }
    );

    console.log('[+] UUIDString spoof installed');
  });

})();

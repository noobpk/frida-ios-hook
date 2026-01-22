Interceptor.attach(
    ObjC.classes.UIDevice["- identifierForVendor"].implementation,
    {
      onLeave: function (retval) {
        var uuid = new ObjC.Object(retval).UUIDString().toString();
        console.log("IDFV:", uuid);
      }
    }
  );

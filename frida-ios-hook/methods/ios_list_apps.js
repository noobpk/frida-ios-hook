'use strict';

var NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
var NSNumber = ObjC.classes.NSNumber;
var SoftwareLibraryLookupOperation = ObjC.classes.SoftwareLibraryLookupOperation;

function list() {
    var pool = NSAutoreleasePool.alloc().init();
    try {
        var op = SoftwareLibraryLookupOperation.alloc().initWithBundleIdentifiers_(NULL);
        op.autorelease();
        op.run();
        return nsArrayMap(op.softwareLibraryItems(), parseSoftwareLibraryItem);
    } finally {
        pool.release();
    }
}

function parseSoftwareLibraryItem(item) {
    var result = {};
    nsDictionaryForEach(item.$ivars._propertyValues, function (key, value) {
        var parsedValue;
        if (value.isKindOfClass_(NSNumber)) {
            parsedValue = value.doubleValue();
        } else {
            parsedValue = value.toString();
        }
        result[key] = parsedValue;
    });
    return result;
}

function nsArrayMap(array, callback) {
    var result = [];
    var count = array.count().valueOf();
    for (var index = 0; index !== count; index++)
        result.push(callback(array.objectAtIndex_(index)));
    return result;
}

function nsDictionaryForEach(dict, callback) {
    var keys = dict.allKeys();
    var count = keys.count().valueOf();
    for (var i = 0; i !== count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = dict.objectForKey_(key);
        callback(key.toString(), value);
    }
}

/* Description: iOS URL Scheme Fuzzing
 * Mode: S+A
 * Version: 1.0
 * Credit: Frida CodeShare
 * Author: @dki
 */
/*
 * iOS URL Scheme Fuzzing
 * Usage: frida -U --codeshare dki/ios-url-scheme-fuzzing SpringBoard
 *
 * Return all registered URL schemes by app (iOS < 11)
 *      dumpSchemes();
 *
 * Open the specified URL
 *      openURL("somescheme://test");
 *
 * Find the executable name for a particular scheme
 *      bundleExecutableForScheme("somescheme");
 *
 * Emulate single home button click (for app backgrounding)
 *      homeSinglePress();
 *
 * Fuzz a particular URL - use {0} as placeholder for insertion points
 *      fuzz("somescheme://somepath?param={0}");
 *
 * Move all crash logs matching a particular string to /tmp
 *      moveCrashLogs("MyApp");
 *
 *
 * You'll typically want to call openURL for the target scheme once before
 * fuzzing to dismiss the prompt that appears the first time
 *
 * openURL("somescheme://test");
 * fuzzStrings.push("somefancyfuzzstring");
 * fuzz("somescheme://test/{0}");
 *
 */

// have Springboard open a URL with whatever handler has claimed it
function openURL(url) {
    var w = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
    var toOpen = ObjC.classes.NSURL.URLWithString_(url);
    return w.openSensitiveURL_withOptions_(toOpen, null);
}

// emulate single home button press
function homeSinglePress() {
    var version = ObjC.classes.UIDevice.currentDevice().systemVersion().toString();

    if (version.startsWith("9.")) { // iOS 9
        ObjC.schedule(ObjC.mainQueue, function() {
            ObjC.classes.SBUIController.sharedInstance().clickedMenuButton();
        });
    } else if (version.startsWith("10.") || version.startsWith("11.")) { // iOS 10//11
        ObjC.schedule(ObjC.mainQueue, function() {
            ObjC.classes.SBUIController.sharedInstance().handleHomeButtonSinglePressUp();
        });
    } else {
        console.log("Sorry, I only tested this on iOS 9 - 11! :(");
    }
}

// check for crash logs and move them to /tmp/ if they exist
// can result in false positives if the appname is a substring of another app
function moveCrashLogs(appname) {
    var match = appname + "*.ips";
    var pred = ObjC.classes.NSPredicate.predicateWithFormat_('SELF like "' + match + '"');
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var dirlist = fm.contentsOfDirectoryAtPath_error_("/private/var/mobile/Library/Logs/CrashReporter", NULL);
    var results = dirlist.filteredArrayUsingPredicate_(pred);
    if (results.count() > 0) {
        for (var i = 0; i < results.count(); i++) {
            var src = results.objectAtIndex_(i).toString();
            fm.moveItemAtPath_toPath_error_("/private/var/mobile/Library/Logs/CrashReporter/" + src, "/tmp/" + src, NULL);
        }
        return true;
    }
    return false;
}

// https://stackoverflow.com/questions/610406/javascript-equivalent-to-printf-string-format
// this is what happens when i port things from python D:
if (!String.format) {
    String.format = function(format) {
        var args = Array.prototype.slice.call(arguments, 1);
        return format.replace(/{(\d+)}/g, function(match, number) {
            return typeof args[number] != 'undefined' ?
                args[number] :
                match;
        });
    };
}

// add/remove default fuzz strings here, or at the command line
var fuzzStrings = ["0",
    "1",
    "-1",
    "null",
    "nil",
    "99999999999999999999999999999999999",
    Array(257).join("A"),
    Array(1026).join("A"),
    "'",
    "%20d",
    "%20n",
    "%20x",
    "%20s"
];

fuzzStrings.iter = function() {
    var index = 0;
    var data = this;
    return {
        next: function() {
            return {
                value: data[index],
                done: index++ == (data.length - 1)
            };
        },
        hasNext: function() {
            return index < data.length;
        }
    }
};

// query the name of the executable (process name) for a URL scheme
function bundleExecutableForScheme(scheme) {
    var apps = ObjC.classes.LSApplicationWorkspace.defaultWorkspace().applicationsAvailableForHandlingURLScheme_(scheme);
    // if there are multiple apps, punt
    if (apps.count() != 1) {
        return null;
    }

    var appProxy = apps.objectAtIndex_(0); // LSApplicationProxy
    var bundleExecutable = appProxy.bundleExecutable();
    if (bundleExecutable !== null) {
        return bundleExecutable.toString();
    }

    return null;
}

// dump all registered URL schemes, organized by process name
// this no longer works on iOS 11 :(
function dumpSchemes() {
    var map = {};
    var schemes = ObjC.classes.LSApplicationWorkspace.defaultWorkspace().publicURLSchemes();
    for (var i = 0; i < schemes.count(); i++) {
        var name = bundleExecutableForScheme(schemes.objectAtIndex_(i));
        if (!(name in map)) {
            map[name] = [];
        }
        map[name].push(schemes.objectAtIndex_(i).toString());
    }
    return map;
}

// fuzz a url for a registered scheme
// use {0} for placeholders: blah://test/{0}
function fuzz(url) {
    // find the process name for this url scheme
    var appname = bundleExecutableForScheme(url.split(':')[0]);
    if (appname === null) {
        console.log("Could not determine which app handles this URL!");
        return;
    }

    function Fuzzer(url, appname, iter) {
        this.url = url;
        this.appname = appname;
        this.iter = iter;
    }

    Fuzzer.prototype.checkForCrash = function(done) {
        // background in case it is still running
        homeSinglePress();

        // check for a crash
        if (moveCrashLogs(this.appname)) {
            console.log("Crashed!");
        }

        // fuzz next url
        if (!done) {
            this.fuzz();
        }
    };

    Fuzzer.prototype.fuzz = function() {
        var term = this.iter.next();

        // create the url
        var fuzzedURL = String.format(this.url, term.value);

        // this should launch the app
        if (openURL(fuzzedURL)) {
            console.log("Opened URL: " + fuzzedURL);
        } else {
            console.log("URL refused by SpringBoard: " + fuzzedURL);
        }

        // wait a few seconds before backgrounding
        ObjC.classes.NSThread.sleepForTimeInterval_(3);
        this.checkForCrash(term.done);
    };

    console.log("Watching for crashes from " + appname + "...");

    // start by clearing any current logs
    if (moveCrashLogs(appname)) {
        console.log("Moved one or more logs to /tmp/ before fuzzing!");
    }
    // get iterator for fuzz strings
    var iter = fuzzStrings.iter();
    var fuzzer = new Fuzzer(url, appname, iter);
    fuzzer.fuzz();
}

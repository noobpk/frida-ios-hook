console.log("[*] Started: Show Binary Cookies");

function show_binarycookies() {
    var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
    for (var i = 0; i < cookies.count(); i++) {
        console.log((cookies['- objectAtIndex:'](i)).toString())
    }
    console.log("");
    console.log("[*] Completed: Show Binary Cookies");
}
show_binarycookies()
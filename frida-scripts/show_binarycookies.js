function show_binarycookies()
{
    var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
    for (var i=0; i<cookies.count(); i++)
    {
        console.log((cookies['- objectAtIndex:'](i)).toString())
    }
}
//show_binarycookies()

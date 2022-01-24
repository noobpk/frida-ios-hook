/* Description: Show contents of Cookies.binarycookies file
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function show_binarycookies()
{
    var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
    for (var i=0; i<cookies.count(); i++)
    {
        console.log((cookies['- objectAtIndex:'](i)).toString())
    }
}

show_binarycookies()

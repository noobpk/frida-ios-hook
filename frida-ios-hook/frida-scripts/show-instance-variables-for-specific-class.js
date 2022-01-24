/* Description: Show all instance variables of a particular class
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security

//Example: var instance = ObjC.chooseSync(ObjC.classes.SensitiveInformationDetailsVC)[0]
//var instance = ObjC.chooseSync(ObjC.classes.CLASS_NAME_HERE)[0]
//instance.$ivars
//Example: (ObjC.chooseSync(ObjC.classes.SensitiveInformationDetailsVC)[0]).$ivars
(ObjC.chooseSync(ObjC.classes.CLASS_NAME_HERE)[0]).$ivars

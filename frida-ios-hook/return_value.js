/*
Description:
Replace methods return values
* Given an especific class, method and value it replaces the return value of the method.
* Method format: for example:  "- isJailbroken:"
* Data must be in the same array position (classNmes, methodNames, returnValues). For example: ['class1','class2']\['method1','method2']['retvalue1','retvalue2']
* If returnValues of a method is left empty, the method will be hooken but the script will not modify the return value.
*/


var classNames = [''];
var methodNames = [''];
var returnValues = [''];

function replace_value(value,typeValue,returnValue) {
	var newReturnValue = '';
	/*
	Generic
	*/
	if (!value) {
		newReturnValue = returnValue;
	}
	else {
		newReturnValue = ptr(value);
	}
	/*
	If return value is not an Object

	if (typeValue.includes('Object')) {
		newReturnValue = ptr(value);
	}
	else if (typeValue.includes('Array')) {
		console.log('array');
	}
	return newReturnValue;
	*/

	/*
	If more processing has to be done
	if (value == 1) {
		newReturnValue = function_to_obtain_return_value();
	}
	*/
	return newReturnValue;
}
// https://stackoverflow.com/questions/4456336/finding-variable-type-in-javascript

function getIndex(method) {
	for (var i = 0; i < methodNames.length; ++i) {
		if (methodNames[i].includes(method)){
			return i
		}
	}
}

function print_arguments(args) {
/*
Frida's Interceptor has no information about the number of arguments, because there is no such
information available at the ABI level (and we don't rely on debug symbols).

I have implemented this function in order to try to determine how many arguments a method is using.
It stops when:
	- The object is not nil
	- The argument is not the same as the one before
 */
	var n = 100;
	var last_arg = '';
	for (var i = 2; i < n; ++i) {
		var arg = (new ObjC.Object(args[i])).toString();
		if (arg == 'nil' || arg == last_arg) {
			break;
		}
		last_arg = arg;
		console.log('\t[-] arg' + i + ': ' + (new ObjC.Object(args[i])).toString());
	}
}

if (ObjC.available)
{
	console.log('\n[*] Starting Hooking');
	for (var i = 0; i < classNames.length; ++i) {
		console.log(classNames[i]);
		var _className = "" + classNames[i];
		var _methodName = "" + methodNames[i];
		var hooking = ObjC.classes[_className][_methodName];
		console.log('   ' + methodNames[i]);

		Interceptor.attach(hooking.implementation, {
			onEnter: function (args) {
				this._className = ObjC.Object(args[0]).toString();
				this._methodName = ObjC.selectorAsString(args[1]);
				console.log('Detected call to:');
				console.log('   ' + this._className + ' --> ' + this._methodName);

				//print_arguments(args);

			},
			onLeave: function(returnValue) {
				console.log('Return value of:');
				console.log('   ' + this._className + ' --> ' + this._methodName);
				var typeValue = Object.prototype.toString.call(returnValue);
				console.log("\t[-] Type of return value: " + typeValue);
				console.log("\t[-] Return Value: " + returnValue);

				var index = getIndex(this._methodName);
				var newReturnValue = replace_value(returnValues[index],typeValue,returnValue);
				returnValue.replace(newReturnValue);
				console.log("\t[-] New Return Value: " + returnValue);
			}
		});
	}
	console.log('\n[*] Starting Intercepting');
}
else {
	console.log('Objective-C Runtime is not available!');
}

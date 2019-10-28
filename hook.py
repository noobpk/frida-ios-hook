import frida
import time

print ('''\033[1;31m \n
_|      _|                      _|                  _|      
_|_|    _|    _|_|      _|_|    _|_|_|    _|_|_|    _|  _|  
_|  _|  _|  _|    _|  _|    _|  _|    _|  _|    _|  _|_|    
_|    _|_|  _|    _|  _|    _|  _|    _|  _|    _|  _|  _|  
_|      _|    _|_|      _|_|    _|_|_|    _|_|_|    _|    _|
        https://noobpk.github.io          _|                 
Trace Class/Func & Modify Return Value    _|   #noobteam
''')

print ("\033[1;34m[*]___author___: @noobpk\033[1;37m")
print ("\033[1;34m[*]___version___: 1.0\033[1;37m")
print ("")

def hook():
	device = frida.get_usb_device()
	app =  "com.ios.app"
	pid = device.spawn([app])
	device.resume(pid)
	time.sleep(1) #Without it Java.perform silently fails
	session = device.attach(pid)
	options = "trace_class.js"
	script = session.create_script(open(options).read())
	script.load()
	print("--------End-----------")
	input()

def main():
	hook()

if __name__ == '__main__':
    main()
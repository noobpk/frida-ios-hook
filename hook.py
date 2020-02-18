import frida
import time
import os
import sys
import argparse

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
print ("\033[1;34m[*]___version___: 1.1\033[1;37m")
print ("")

def parse_hook(filename):
	print('[*] Script: ' + filename)
	hook = open(filename, 'r')
	script = session.create_script(hook.read())
	script.load()

if __name__ == '__main__':
    try:
    	parser = argparse.ArgumentParser()
    	parser.add_argument('package', help='Spawn a new process and attach')
    	parser.add_argument('script', help='Print stack trace for each hook')
    	args = parser.parse_args()

    	print('[*] Spawning: ' + args.package)
    	pid = frida.get_usb_device().spawn(args.package)
    	session = frida.get_usb_device().attach(pid)
    	parse_hook(args.script)
    	frida.get_usb_device().resume(pid)
    	print('---------------Done-----------------')
    	sys.stdin.read()

    except KeyboardInterrupt:
        sys.exit(0)
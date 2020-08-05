import frida
import time
import os
import sys
import optparse
import threading
import codecs
import shutil
import tempfile
import subprocess
import re

import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
from module.listapp import *

print ('''\033[1;31m \n
_|    _|_|      _|_|_|      _|    _|                      _|        
    _|    _|  _|            _|    _|    _|_|      _|_|    _|  _|    
_|  _|    _|    _|_|        _|_|_|_|  _|    _|  _|    _|  _|_|      
_|  _|    _|        _|      _|    _|  _|    _|  _|    _|  _|  _|    
_|    _|_|    _|_|_|        _|    _|    _|_|      _|_|    _|    _|  
                https://noobpk.github.io          #noobteam      
            Trace Class/Func & Modify Return Value  
''')

print ("\033[1;34m[*]___author___: @noobpk\033[1;37m")
print ("\033[1;34m[*]___version___: 3.0\033[1;37m")
print ("")

def main():
    usage = "[>] python3 %prog [options] arg\n\n\r[>] Example for spawn or attach app with -s(--script) options:\npython3 hook.py -p com.apple.AppStore [-n App Store] -s trace_class.js\n\n\r[>] Example for attach app with -m(--method) options:\npython3 hook.py -n App Store -m app_info"
    parser = optparse.OptionParser(usage,add_help_option=False)
    parser.add_option('-h', "--help", action="help", dest="help", help="Show basic help message and exit")
    #Using options -p(--package) for spawn application and load script
    parser.add_option("-p", "--package", dest="package",
                    help="Identifier of the target app", metavar="PACKAGE", action="store", type="string")
    parser.add_option("-s", "--script", dest="script",
                    help="Frida Script Hooking", metavar="SCIPRT.JS")
    #Using options -n(--name) for attach script to application is running
    parser.add_option("-n", "--name", dest="name",
                    help="Name of the target app", metavar="NAME", action="store", type="string")                
    parser.add_option("-m", "--method", dest="method", type="choice", choices=['app_static','bypass_jb','bypass_ssl'],
                    help="__app_static: Static Ananlysis Application\n\r__bypass_jb: Bypass Jailbreak Detection   \n\r__bypass_ssl: Bypass SSL Pinning", metavar="<app_static | bypass_jb | bypass_ssl>")
    #Some options to get info from device and applications
    parser.add_option("--listdevices",
                    action="store_true", help="List All Devices", dest="listdevices")
    parser.add_option("--listapp",
                    action="store_true", help="List The Installed apps", dest="listapp")
    parser.add_option("--listappinfo",
                    action="store_true", help="List Info of Apps on Itunes", dest="listappinfo")                   
    options, args = parser.parse_args()
    try:
        if options.listdevices:
            print('[*] List All Devices: ')
            os.system('frida-ls-devices')

        elif options.listapp:
            device = get_usb_iphone()
            list_applications(device)

        elif options.listappinfo:
            print('[*] List Info of Apps on Itunes: ')
            process = 'itunesstored'
            method = "method/ios_list_apps.js"
            os.system('frida -U -n '+ process + ' -l ' + method)
            #sys.stdin.read()

        #Spawning application and load script
        elif options.package and options.script:
            print('[*] Spawning: ' + options.package)
            print('[*] Script: ' + options.script)
            time.sleep(2)
            pid = frida.get_usb_device().spawn(options.package)
            session = frida.get_usb_device().attach(pid)
            hook = open(options.script, 'r')
            script = session.create_script(hook.read())
            script.load()
            frida.get_usb_device().resume(pid)
            print('-----------Hook---Done!!--------')
            sys.exit(0)

        #Attaching script to application
        elif options.name and options.script:
            print('[*] Attaching: ' + options.name)
            print('[*] Script: ' + options.script)
            time.sleep(2)
            process = frida.get_usb_device().attach(options.name)
            hook = open(options.script, 'r')
            script = process.create_script(hook.read())
            script.load()
            sys.stdin.read()

        #Static Analysis Application
        elif options.name and options.method == "app_static":
            print('[*] Attaching: ' + options.name)
            print('[*] Method: ' + options.method)
            time.sleep(2)
            process = frida.get_usb_device().attach(options.name)
            method = open("method/static_analysis.js", 'r')
            script = process.create_script(method.read())
            script.load()
            sys.stdin.read()
        
        elif options.name and options.method == "bypass_jb":
            print('[!] The Method Is Updating!!')

        elif options.name and options.method == "bypass_ssl":
            print('[!] The Method Is Updating!!')

        else:
            print("[-] specify the options. use (-h) for more help!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("[-] Bye bro!!")
        sys.exit(0)

if __name__ == '__main__':
        main()

    
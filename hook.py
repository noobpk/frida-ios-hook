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
import fnmatch

import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
from module.listapp import *
from library.log import *

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
print ("\033[1;34m[*]___version___: 3.1a\033[1;37m")
print ("")

def main():

    try:

        usage = "[>] python3 %prog [options] arg\n\n\r[>] Example for spawn or attach app with -s(--script) options:\npython3 hook.py -p com.apple.AppStore [-n App Store] -s trace_class.js\n\n\r[>] Example for spawn or attach app with -m(--method) options:\npython3 hook.py -p com.apple.AppStore [-n App Store] -m app-static"
        parser = optparse.OptionParser(usage,add_help_option=False)
        info = optparse.OptionGroup(parser,"Information")
        quick = optparse.OptionGroup(parser,"Quick Method")

        parser.add_option('-h', "--help", action="help", dest="help", help="Show basic help message and exit")
        #Using options -p(--package) for spawn application and load script
        parser.add_option("-p", "--package", dest="package",
                        help="Identifier of the target app", metavar="PACKAGE", action="store", type="string")
        #Using options -n(--name) for attach script to application is running
        parser.add_option("-n", "--name", dest="name",
                        help="Name of the target app", metavar="NAME", action="store", type="string")

        parser.add_option("-s", "--script", dest="script",
                        help="Frida Script Hooking", metavar="SCIPRT.JS")

        quick.add_option("-m", "--method", dest="method", type="choice", choices=['app-static','bypass-jb','bypass-ssl'],
                        help="__app-static: Static Ananlysis Application(-n)\n\n\r\r__bypass-jb: Bypass Jailbreak Detection(-s)\n\n\r\r\r\r\r\r__bypass-ssl: Bypass SSL Pinning(-s)", metavar="<app-static | bypass-jb | bypass-ssl>")
        #Some options to get info from device and applications
        info.add_option("--listdevices",
                        action="store_true", help="List All Devices", dest="listdevices")
        info.add_option("--list-apps",
                        action="store_true", help="List The Installed apps", dest="listapp")
        info.add_option("--list-appinfo",
                        action="store_true", help="List Info of Apps on Itunes", dest="listappinfo")
        info.add_option("--list-scripts",
                        action="store_true", help="List All Scripts", dest="listscripts")

        parser.add_option_group(info)
        parser.add_option_group(quick)

        options, args = parser.parse_args()

        if options.listdevices:
            print('[*] List All Devices: ')
            os.system('frida-ls-devices')

        elif options.listapp:
            device = get_usb_iphone()
            list_applications(device)

        elif options.listappinfo:
            method = 'method/ios_list_apps.js'
            if os.path.isfile(method):
                print('[*] List Info of Apps on Itunes: ')
                process = 'itunesstored'
                os.system('frida -U -n '+ process + ' -l ' + method)
                #sys.stdin.read()
            else:
                logger.error('Script not found!')
        
        elif options.listscripts:
            path = 'frida-scripts/'
            if os.path.exists(path):
                print('[*] List All Scripts: ')
                for file_name in os.listdir(path):
                    if fnmatch.fnmatch(file_name, '*.js'):
                        print('[*]' + file_name)
            else:
                logger.error('Path frida-script not exists!')

        #Spawning application and load script
        elif options.package and options.script:
            if os.path.isfile(options.script):
                print('[*] Spawning: ' + options.package)
                print('[*] Script: ' + options.script)
                time.sleep(2)
                pid = frida.get_usb_device().spawn(options.package)
                session = frida.get_usb_device().attach(pid)
                hook = open(options.script, 'r')
                script = session.create_script(hook.read())
                script.load()
                frida.get_usb_device().resume(pid)
                sys.stdin.read()
            else:
                logger.error('Script not found!')

        #Attaching script to application
        elif options.name and options.script:
            if os.path.isfile(options.script):
                print('[*] Attaching: ' + options.name)
                print('[*] Script: ' + options.script)
                time.sleep(2)
                process = frida.get_usb_device().attach(options.name)
                hook = open(options.script, 'r')
                script = process.create_script(hook.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('Script not found!')

        #Static Analysis Application
        elif options.name and options.method == "app-static":
            method = 'method/static_analysis.js'
            if os.path.isfile(method):
                print('[*] Attaching: ' + options.name)
                print('[*] Method: ' + options.method)
                time.sleep(2)
                process = frida.get_usb_device().attach(options.name)
                method = open(method, 'r')
                script = process.create_script(method.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('Script not found!')
        
        elif options.name and options.method == "bypass-jb":
            print('[!] The Method Is Updating!!')

        #Bypass SSL Pinning
        elif options.package and options.method == "bypass-ssl":
            method = "method/bypass_ssl.js"
            if os.path.isfile(method):
                print('[*] Bypass SSL Pinning: ')
                print('[*] Spawning: ' + options.package)
                print('[*] Script: ' + method)
                os.system('frida -U -f '+ options.package + ' -l ' + method + ' --no-pause')
                #sys.stdin.read()
            else:
                logger.error('Script not found!')
        else:
            logger.info("Specify the options. use (-h) for more help!")
            # sys.exit(0)

    except Exception as e:
        logger.error("Something went wrong, please check your error message.\n Error - {0}".format(e))

    except KeyboardInterrupt:
        logger.info("Bye bro!!")
        # sys.exit(0)

if __name__ == '__main__':
        main()

    
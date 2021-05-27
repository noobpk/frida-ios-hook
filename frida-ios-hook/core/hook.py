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
import shlex
import subprocess
import psutil

import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
from utils.listapp import *
from utils.checkversion import *
from utils.log import *

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
print ("\033[1;34m[*]___version___: 3.5-beta\033[1;37m")
print ("")

def check_platform():
    try:
        platforms = {
        'linux'  : 'Linux',
        'linux1' : 'Linux',
        'linux2' : 'Linux',
        'darwin' : 'OS X',
        'win32'  : 'Windows'
        }
        if sys.platform not in platforms:
            sys.exit(logger.error("[x_x] Your platform currently does not support."))
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def check_ps_for_win32():
    try:
        if sys.platform == "win32":
            PROCESSNAME = "iTunes.exe"
            for proc in psutil.process_iter():
                try:
                    if proc.name() == PROCESSNAME:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    pass
            return sys.exit(logger.error("[x_x] Please install iTunes on MicrosoftStore or run iTunes frist."))              
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def run():
    #check platform support
    check_platform()
    #check process iTunes for Win32s
    check_ps_for_win32()
    #check python version
    if sys.version_info < (3, 0):
        logger.error("[x_x] iOS hook requires Python 3.x")
        sys.exit(0)
    else:
        handle_del_log()
        main()

def handle_del_log():
    try:
        pwd = os.getcwd()
        path = pwd + '/errors.log'
        file_stats = os.stat(path)
        if (file_stats.st_size > 1024000000): #delete errors.log if file size > 1024 MB
            os.remove(path)
        else:
            return True
    except Exception as e:
        logger.error("[x_x] Something went wrong when clear error log. Please clear error log manual.\n Message - {0}".format(e))

def dump_memory(option, process):
    try:
        util = "core/utils/dump-memory/fridump.py"
        if option != "-h":
            cmd = shlex.split("python3 " + util + ' ' + "-u" + ' ' + option + ' ' + '"' + process + '"')
        else:
            cmd = shlex.split("python3 " + util + ' ' + option)
        subprocess.call(cmd)
        sys.exit(0)
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def hexbyte_scan(option, task):
    try:
        util = "core/utils/hexbytescanner/hexbytescanner"
        if option != "-h":
            cmd = shlex.split("./"+util + ' ' + option + ' ' + task)
        else:
            cmd = shlex.split("./"+util)
        subprocess.call(cmd)
        sys.exit(0)
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def main():
    try:
        
        usage = "[>] ./ioshook %prog [options] arg\n\n\r[>] Example for spawn or attach app with -s(--script) options:\n./ioshook -p com.apple.AppStore / [-n 'App Store'] -s trace_class.js\n\n\r[>] Example for spawn or attach app with -m(--method) options:\n./ioshook -p com.apple.AppStore / [-n 'App Store'] -m app-static\n\n\r[>] Example dump decrypt ipa with -d(--dump) and -o(--output) options:\n./ioshook -p com.apple.AppStore / [-n 'App Store'] -d -o App_dump_name\n\n\r[>] Example dump memory of application with --dump-memory and -s(--string) options:\n./ioshook -n 'App Store' --dump-memory '-s(--string)'\n\n\r[>] Example Scan IPA with file task:\n./ioshook --hexbyte-scan 'scan AppStore.ipa' -t /hexbyscan-tasks/openssl_hook.json"
        parser = optparse.OptionParser(usage,add_help_option=False)
        info = optparse.OptionGroup(parser,"Information")
        quick = optparse.OptionGroup(parser,"Quick Method")
        dump = optparse.OptionGroup(parser,"Dump decrypt IPA")
        hexscan = optparse.OptionGroup(parser,"HexByte Scan IPA")
        dumpmemory = optparse.OptionGroup(parser,"Dump memory of Application")

        parser.add_option('-h', "--help", action="help", dest="help", help="Show basic help message and exit")
        #Using options -p(--package) for spawn application and load script
        parser.add_option("-p", "--package", dest="package",
                        help="Identifier of the target app", metavar="PACKAGE", action="store", type="string")
        #Using options -n(--name) for attach script to application is running
        parser.add_option("-n", "--name", dest="name",
                        help="Name of the target app", metavar="NAME", action="store", type="string")

        parser.add_option("-s", "--script", dest="script",
                        help="Frida Script Hooking", metavar="SCIPRT.JS")

        parser.add_option("-c", "--check-version", action="store_true", help="Check iOS hook for the newest version", dest="checkversion")
        parser.add_option("-u", "--update", action="store_true", help="Update iOS hook to the newest version", dest="update")

        quick.add_option("-m", "--method", dest="method", type="choice", choices=['app-static','bypass-jb','bypass-ssl','i-url-req','i-crypto'],
                        help="__app-static: Static Ananlysis Application(-n)\n\n\r\r__bypass-jb: Bypass Jailbreak Detection(-p)\n\n\r\r\r\r\r\r__bypass-ssl: Bypass SSL Pinning(-p)\n\n\n\n\n\n\n\n\n\r\r\r\r\r\r__i-url-req: Intercept URLRequest in App(-n)\n\n\n\n\n\n\n\n\n\r\r\r\r\r\r__i-crypto: Intercept Crypto in App(-p)", metavar="app-static / bypass-jb / bypass-ssl / i-url-req / i-crypto")
        #Some options to get info from device and applications
        info.add_option("--list-devices",
                        action="store_true", help="List All Devices", dest="listdevices")
        #Listapp option using the code of the AloneMonkey's repo frida-ios-dump - Link: https://github.com/AloneMonkey/frida-ios-dump
        info.add_option("--list-apps",
                        action="store_true", help="List The Installed apps", dest="listapps")
        info.add_option("--list-appinfo",
                        action="store_true", help="List Info of Apps on Itunes", dest="listappinfo")
        info.add_option("--list-scripts",
                        action="store_true", help="List All Scripts", dest="listscripts")
        #Dump decrypt IPA using the code of the AloneMonkey's repo frida-ios-dump - Link: https://github.com/AloneMonkey/frida-ios-dump
        dump.add_option("-d", "--dump", action="store_true", help="Dump decrypt application.ipa", dest="dumpapp")
        dump.add_option("-o", "--output", action="store" , dest="output_ipa", help="Specify name of the decrypted IPA", metavar="OUTPUT_IPA", type="string")

        #Dump memory of application using the code of Nightbringer21's repo fridump - Link: https://github.com/Nightbringer21/fridump
        dumpmemory.add_option("--dump-memory", action="store", help="Dump memory of application", dest="dumpmemory")

        #Hexbytescan of application using the code of karek314's repo hexbytescanner - Link: https://github.com/karek314/hexbytescanner
        hexscan.add_option("--hexbyte-scan", action="store", help="Scan or Patch IPA with byte patterns", dest="hexscan")
        hexscan.add_option("-t", "--task", action="store", help="Task for hexbytescan", dest="task")

        parser.add_option_group(dump)
        parser.add_option_group(dumpmemory)
        parser.add_option_group(hexscan)
        parser.add_option_group(info)
        parser.add_option_group(quick)

        options, args = parser.parse_args()
        
        methods = [
            "methods/ios_list_apps.js", #0
            "methods/static_analysis.js", #1
            "methods/bypass_ssl.js", #2
            "methods/bypass_jailbreak.js", #3
            "methods/intercept_url_request.js", #4
            "methods/intercept_crypto.js", #5
            "methods/dump.js" #6
        ]

        utils = [
            "core/utils/dump.py" #0
        ]

        if options.listdevices:
            logger.info('[*] List All Devices: ')
            os.system('frida-ls-devices')

        elif options.listapps:
            logger.info('[*] List All Apps on Devies: ')
            device = get_usb_iphone()
            list_applications(device)

        elif options.listappinfo:
            method = methods[0]
            if os.path.isfile(method):
                logger.info('[*] List Info of Apps on Itunes: ')
                process = 'itunesstored'
                os.system('frida -U -n '+ process + ' -l ' + method)
                #sys.stdin.read()
            else:
                logger.error('[?] Script not found!')
        
        elif options.listscripts:
            path = 'frida-scripts/'
            if os.path.exists(path):
                logger.info('[*] List All Scripts: ')
                for file_name in os.listdir(path):
                    if fnmatch.fnmatch(file_name, '*.js'):
                        print('[*] ' + file_name)
            else:
                logger.error('[?] Path frida-script not exists!')

        #Spawning application and load script
        elif options.package and options.script:
            if os.path.isfile(options.script):
                logger.info('[*] Spawning: ' + options.package)
                logger.info('[*] Script: ' + options.script)
                time.sleep(2)
                pid = frida.get_usb_device().spawn(options.package)
                session = frida.get_usb_device().attach(pid)
                hook = open(options.script, 'r')
                script = session.create_script(hook.read())
                script.load()
                frida.get_usb_device().resume(pid)
                sys.stdin.read()
            else:
                logger.error('[?] Script not found!')

        #Spawning application and load script with output
        
        #Attaching script to application
        elif options.name and options.script:
            if os.path.isfile(options.script):
                logger.info('[*] Attaching: ' + options.name)
                logger.info('[*] Script: ' + options.script)
                time.sleep(2)
                process = frida.get_usb_device().attach(options.name)
                hook = open(options.script, 'r')
                script = process.create_script(hook.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('[?] Script not found!')

        #Static Analysis Application
        elif options.name and options.method == "app-static":
            method = methods[1]
            if os.path.isfile(method):
                logger.info('[*] Attaching: ' + options.name)
                logger.info('[*] Method: ' + options.method)
                time.sleep(2)
                process = frida.get_usb_device().attach(options.name)
                method = open(method, 'r')
                script = process.create_script(method.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('[?] Script not found!')
        
        #Bypass jailbreak
        elif options.package and options.method == "bypass-jb":
            method = methods[3]
            if os.path.isfile(method):
                logger.info('[*] Bypass Jailbreak: ')
                logger.info('[*] Spawning: ' + options.package)
                logger.info('[*] Script: ' + method)
                time.sleep(2)
                pid = frida.get_usb_device().spawn(options.package)
                session = frida.get_usb_device().attach(pid)
                hook = open(method, 'r')
                script = session.create_script(hook.read())
                script.load()
                frida.get_usb_device().resume(pid)
                sys.stdin.read()
            else:
                logger.error('[?] Script for method not found!')

        #Bypass SSL Pinning
        elif options.package and options.method == "bypass-ssl":
            method = methods[2]
            if os.path.isfile(method):
                logger.info('[*] Bypass SSL Pinning: ')
                logger.info('[*] Spawning: ' + options.package)
                logger.info('[*] Script: ' + method)
                os.system('frida -U -f '+ options.package + ' -l ' + method + ' --no-pause')
                #sys.stdin.read()
            else:
                logger.error('[?] Script for method not found!')

        #Intercept url request in app
        elif options.name and options.method == "i-url-req":
            method = methods[4]
            if os.path.isfile(method):
                logger.info('[*] Intercept UrlRequest: ')
                logger.info('[*] Attaching: ' + options.name)
                logger.info('[*] Script: ' + method)
                time.sleep(2)
                process = frida.get_usb_device().attach(options.name)
                method = open(method, 'r')
                script = process.create_script(method.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('[?] Script for method not found!')

        #Intercept Crypto Operations
        elif options.package and options.method == "i-crypto":
            method = methods[5]
            if os.path.isfile(method):
                logger.info('[*] Intercept Crypto Operations: ')
                logger.info('[*] Spawning: ' + options.package)
                logger.info('[*] Script: ' + method)
                os.system('frida -U -f '+ options.package + ' -l ' + method + ' --no-pause')
                #sys.stdin.read()
            else:
                logger.error('[?] Script for method not found!')

        #check newversion
        elif options.checkversion:
            logger.info('[*] Checking for updates...')
            is_newest = check_version(speak=True)
            # if not is_newest:
            #     logger.info('[*] There is an update available for iOS hook')

        #update newversion
        elif options.update:
            logger.info('[*] Update in progress...')
            cmd = shlex.split("git reset --hard & git pull origin master")
            subprocess.call(cmd)
            sys.exit(0)

        #dump decrypt application
        elif (options.package or options.name) and options.dumpapp:
            logger.info('[*] Dumping...')
            util = utils[0]
            if options.name is None:
                if options.output_ipa is None:
                    cmd = shlex.split("python3 " + util + " " + options.package)
                else:
                    cmd = shlex.split("python3 " + util + " " + options.package + " -o " + options.output_ipa)
            else:
                if options.output_ipa is None:
                    cmd = shlex.split("python3 " + util + " " + "'" + options.name + "'")
                else:
                    cmd = shlex.split("python3 " + util + " " + "'" + options.name + "'" + " -o " + options.output_ipa)
            subprocess.call(cmd)
            sys.exit(0)

        #dump memory application
        elif options.name and options.dumpmemory:
            dump_memory(options.dumpmemory, options.name)

        #hexbytescan ipa
        elif options.hexscan:
            hexbyte_scan(options.hexscan, options.task)

        else:
            logger.warning("[!] Specify the options. use (-h) for more help!")
            # sys.exit(0)

    #EXCEPTION FOR FRIDA
    except frida.ServerNotRunningError:
        logger.error("Frida server is not running.")
    except frida.TimedOutError:
        logger.error("Timed out while waiting for device to appear.")
    except frida.TransportError:
        logger.error("[x_x] The application may crash or lose connection.")
    except (frida.ProcessNotFoundError,
            frida.InvalidOperationError):
        logger.error("[x_x] Unable to find process with name " + options.name + ". You need run app first.!!")
    #EXCEPTION FOR OPTIONPARSING

    #EXCEPTION FOR SYSTEM
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    except KeyboardInterrupt:
        logger.info("Bye bro!!")
        # sys.exit(0)

if __name__ == '__main__':
    run()


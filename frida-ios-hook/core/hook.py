import frida
import time
import os
import sys
import optparse
import subprocess
import re
import fnmatch
import shlex
from multiprocessing import Process, Event

from utils.listapp import *
from utils.checkversion import *
from utils.log import *
from utils.config import *
from utils.cli import *
from utils.suggestion import *

GLOBAL_CONFIG = config.loadConfig()

APP_FRIDA_SCRIPTS = GLOBAL_CONFIG['fridaScripts']
APP_METHODS = GLOBAL_CONFIG['methods']
APP_UTILS = GLOBAL_CONFIG['utils']
APP_SSH = GLOBAL_CONFIG['ssh']
APP_SSH_CRED = GLOBAL_CONFIG['sshCredential']

def dump_memory(option, process):
    try:
        util = APP_UTILS['Dump Memory']
        if option != "-h":
            cmd = shlex.split("python3 " + util + ' ' + "-u" + ' ' + option + ' ' + '"' + process + '"')
        else:
            cmd = shlex.split("python3 " + util + ' ' + option)
        completed_process = subprocess.call(cmd)
        sys.exit(0)
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def hexbyte_scan(mode, file, option):
    try:
        util = APP_UTILS['HexByte Scanner']
        if mode != "help":
            #check file
            if(os.path.isfile(file)):
                if mode == "json":
                    if(os.path.isfile(option)):
                        cmd = shlex.split("./"+util + ' ' + option + ' ' + file)
                        completed_process = subprocess.call(cmd)
                    else:
                        logger.error("[x_x] File "+option+" not found!")
                elif mode == "patch":
                    cmd = shlex.split("./"+util + ' ' + mode + ' ' + file + ' ' + option.replace(',', ' '))
                    completed_process = subprocess.call(cmd)
                elif mode == "scan":
                    cmd = shlex.split("./"+util + ' ' + mode + ' ' + file + ' ' + option)
                    completed_process = subprocess.call(cmd)
            else:
                logger.error("[x_x] File "+file+" not found!")
                sys.exit(0)
        else:
            cmd = shlex.split("./"+util)
            completed_process = subprocess.call(cmd)
        sys.exit(0)
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

def main():
    try:

        usage = '''
        [>] ./ioshook %prog [options] arg
        Example for spawn or attach app with -s(--script) options:
        [>] ./ioshook -p com.apple.AppStore / [-n 'App Store'] -s trace_class.js
        Example for spawn or attach app with -m(--method) options:
        [>] ./ioshook -p com.apple.AppStore / [-n 'App Store'] -m app-static
        Example dump decrypt ipa with -d(--dump-app) and -o(--output) options:
        [>] ./ioshook -p com.apple.AppStore / [-n 'App Store'] -d -o App_dump_name
        [+] ./ioshook -p com.apple.AppStore / [-n 'App Store'] -m app-static
        Example dump decrypt ipa with -d(--dump-app) and -o(--output) options:
        [+] ./ioshook -p com.apple.AppStore / [-n 'App Store'] -d -o App_dump_name
        Example dump memory of application with --dump-memory and -s(--string) options:
        [>] ./ioshook -n 'App Store' --dump-memory --string
        Example Hexbyte Scan IPA with pattern:
        [>] ./ioshook --hexbyte-scan scan --file AppStore.ipa --pattern E103??AA????E0
        Example Hexbyte Scan and Patch IPA with file task:
        [>] ./ioshook --hexbyte-scan json --file AppStore.ipa -t /hexbytescan-tasks/openssl_hook.json'''

        parser = optparse.OptionParser(usage, add_help_option=False)
        info = optparse.OptionGroup(parser,"Information")
        quick = optparse.OptionGroup(parser,"Quick Method")
        dumpapp = optparse.OptionGroup(parser,"Dump decrypt IPA")
        hexscan = optparse.OptionGroup(parser,"HexByte Scan IPA")
        dumpmemory = optparse.OptionGroup(parser,"Dump memory of Application")
        reflutter = optparse.OptionGroup(parser,"reFlutter")

        parser.add_option('-h', "--help", action="help", dest="help", help='''Show basic help message and exit''')
        parser.add_option("--cli", action="store_true", dest="cli", help='''iOSHook command line interface''')
        #Using options -p(--package) for spawn application and load script
        parser.add_option("-p", "--package", dest="package",
                        help='''Identifier of the target app''', metavar="PACKAGE", action="store", type="string")
        #Using options -n(--name) for attach script to application is running
        parser.add_option("-n", "--name", dest="name",
                        help='''Name of the target app''', metavar="NAME", action="store", type="string")
        parser.add_option("--pid", dest="pid",
                        help='''PID of the target app''', metavar="PID", action="store", type="string")
        #Using options -s(--script) for load script to application
        parser.add_option("-s", "--script", dest="script",
                        help='''Frida Script Hooking''', metavar="SCRIPT.JS")

        parser.add_option("-c", "--check-version", action="store_true", help='''Check iOSHook for the newest version''', dest="checkversion")
        parser.add_option("-u", "--update", action="store_true", help='''Update iOSHook to the newest version''', dest="update")

        quick.add_option("-m", "--method", dest="method", type="choice", choices=['app-static','bypass-jb','bypass-ssl','i-url-req','i-crypto'],
                        help='''app-static: Static Analysis Application(-n)
                        bypass-jb: Bypass Jailbreak Detection(-p)
                        bypass-ssl: Bypass SSL Pinning(-p)
                        i-url-req: Intercept URLRequest in App(-n)
                        i-crypto: Intercept Crypto in App(-p)''', metavar="METHOD")
        #Some options to get info from device and applications
        info.add_option("--list-devices",
                        action="store_true", help="List All Devices", dest="listdevices")
        #Listapp option using the code of the AloneMonkey's repo frida-ios-dump - Link: https://github.com/AloneMonkey/frida-ios-dump
        info.add_option("--list-apps",
                        action="store_true", help="List The Installed apps", dest="listapps")
        #The script list referenced from the repo of interference-security - Link: https://github.com/interference-security/frida-scripts/
        info.add_option("--list-scripts",
                        action="store_true", help="List All Scripts", dest="listscripts")
        info.add_option("--logcat", action="store_true", help="Show system log of device", dest="logcat")
        info.add_option("--shell", "--ssh", action="store_true", help="Get the shell of connect device", dest="shell")
        info.add_option("--ssh-port-forward", action="store", help="Forward the port from local to device", dest="sshportforward", metavar="LOCAL_PORT:DEVICE_PORT")
        #Dump decrypt IPA using the code of the AloneMonkey's repo frida-ios-dump - Link: https://github.com/AloneMonkey/frida-ios-dump
        dumpapp.add_option("-d", "--dump-app", action="store_true", help="Dump decrypt application.ipa", dest="dumpapp")
        dumpapp.add_option("-o", "--output", action="store" , dest="output_ipa", help="Specify name of the decrypted IPA", metavar="OUTPUT_IPA", type="string")

        #Dump memory of application using the code of Nightbringer21's repo fridump - Link: https://github.com/Nightbringer21/fridump
        dumpmemory.add_option("--dump-memory", action="store", help="Dump memory of application", dest="dumpmemory")

        #Hexbytescan of application using the code of karek314's repo hexbytescanner - Link: https://github.com/karek314/hexbytescanner
        hexscan.add_option("--hexbyte-scan", type="choice", choices=['help', 'scan', 'patch', 'json'], help="Choose help - scan - patch - json", dest="hexscan")
        hexscan.add_option("--file", action="store", help="File App.ipa", dest="scanfile")
        hexscan.add_option("--pattern", action="store", help="Pattern for hexbytescan", dest="pattern")
        hexscan.add_option("--address", action="store", help="Address for hexbytescan", dest="address")
        hexscan.add_option("--task", action="store", help="Json File task for hexbytescan", dest="task")
        #reFlutter of application using the code of ptswarm's repo reFlutter - Link: https://github.com/ptswarm/reFlutter
        reflutter.add_option("--reflutter", action="store", help="File Flutter.ipa", dest="flutterfile")

        parser.add_option_group(dumpapp)
        parser.add_option_group(dumpmemory)
        parser.add_option_group(hexscan)
        parser.add_option_group(info)
        parser.add_option_group(quick)
        parser.add_option_group(reflutter)

        options, args = parser.parse_args()

        if options.listdevices:
            logger.info('[*] List All Devices: ')
            cmd = shlex.split("frida-ls-devices")
            completed_process = subprocess.run(cmd)

        elif options.listapps:
            check.deviceConnected()
            logger.info('[*] List All Apps on Devies: ')
            device = get_usb_iphone()
            list_applications(device)

        elif options.listscripts:
            path = APP_FRIDA_SCRIPTS
            description_pattern = " * Description:"
            mode_pattern = " * Mode:"
            version_pattern = " * Version:"

            if os.path.exists(path):
                logger.info('[*] List All Scripts: ')
                print("# Frida scripts for iOS app testing")
                print(" ")
                files = os.listdir(path)
                sorted_files =  sorted(files)
                i = 0
                for file_name in sorted_files:
                    if fnmatch.fnmatch(file_name, '*.js'):
                        i +=1
                        f = open(path+file_name, "r")
                        for line in f:
                            if re.search(description_pattern, line):
                                description = re.sub(r'\n', '', line[16:])
                            if re.search(mode_pattern, line):
                                mode = re.sub(r'\s+', '', line[9:])
                            if re.search(version_pattern, line):
                                version = re.sub(r'\s+', '', line[12:])
                        print('|%d|%s|%s|%s|%s|' % (i, mode, file_name, description, version))
            else:
                logger.error('[x_x] Path frida-script not exists!')

        #Spawning application and load script
        elif options.package and options.script:
            check.deviceConnected()
            if not os.path.isfile(options.script):
                logger.warning('[!] Script '+options.script+' not found. Try suggestion in frida-script!')
                findingScript = suggestion_script(options.script)
                if (findingScript == False):
                    logger.error('[x_x] No matching suggestions!')
                    sys.exit(0)
                logger.info('[*] iOSHook suggestion use '+findingScript)
                answer = input('[?] Do you want continue? (y/n): ') or "y"
                if answer == "y":
                    options.script =  APP_FRIDA_SCRIPTS + findingScript
                elif answer == "n":
                    sys.exit(0)
                else:
                    logger.error('[x_x] Nothing done. Please try again!')
                    sys.exit(0)
            if os.path.isfile(options.script):
                logger.info('[*] Spawning: ' + options.package)
                logger.info('[*] Script: ' + options.script)
                time.sleep(2)
                device = frida.get_usb_device()
                pid = device.spawn(options.package)
                time.sleep(1)
                session = device.attach(pid)
                hook = open(options.script, 'r')
                script = session.create_script(hook.read())
                script.load()
                device.resume(pid)
                sys.stdin.read()
            else:
                logger.error('[x_x] Script not found!')

        #Spawning application and load script with output

        #Attaching script to application with name
        elif options.name and options.script:
            check.deviceConnected()
            if not os.path.isfile(options.script):
                logger.warning('[!] Script '+options.script+' not found. Try suggestion in frida-script!')
                findingScript = suggestion_script(options.script)
                if (findingScript == False):
                    logger.error('[x_x] No matching suggestions!')
                    sys.exit(0)
                logger.info('[*] iOSHook suggestion use '+findingScript)
                answer = input('[?] Do you want continue? (y/n): ') or "y"
                if answer == "y":
                    options.script =  APP_FRIDA_SCRIPTS + findingScript
                elif answer == "n":
                    sys.exit(0)
                else:
                    logger.error('[x_x] Nothing done. Please try again!')
                    sys.exit(0)
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
                logger.error('[x_x] Script not found!')
        #Attaching script to application with pid
        elif options.pid and options.script:
            check.deviceConnected()
            if not os.path.isfile(options.script):
                logger.warning('[!] Script '+options.script+' not found. Try suggestion in frida-script!')
                findingScript = suggestion_script(options.script)
                if (findingScript == False):
                    logger.error('[x_x] No matching suggestions!')
                    sys.exit(0)
                logger.info('[*] iOSHook suggestion use '+findingScript)
                answer = input('[?] Do you want continue? (y/n): ') or "y"
                if answer == "y":
                    options.script =  APP_FRIDA_SCRIPTS + findingScript
                elif answer == "n":
                    sys.exit(0)
                else:
                    logger.error('[x_x] Nothing done. Please try again!')
                    sys.exit(0)
            if os.path.isfile(options.script):
                logger.info('[*] Attaching PID: ' + options.pid)
                logger.info('[*] Script: ' + options.script)
                time.sleep(2)
                process = frida.get_usb_device().attach(int(options.pid))
                hook = open(options.script, 'r')
                script = process.create_script(hook.read())
                script.load()
                sys.stdin.read()
            else:
                logger.error('[x_x] Script not found!')
        
        #Static Analysis Application
        elif options.name and options.method == "app-static":
            check.deviceConnected()
            method = APP_METHODS['Application Static Analysis']
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
                logger.error('[x_x] Script not found!')

        #Bypass jailbreak
        elif options.package and options.method == "bypass-jb":
            check.deviceConnected()
            method = APP_METHODS['Bypass Jailbreak Detection']
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
                logger.error('[x_x] Script for method not found!')

        #Bypass SSL Pinning
        elif options.package and options.method == "bypass-ssl":
            check.deviceConnected()
            method = APP_METHODS['Bypass SSL Pinning']
            if os.path.isfile(method):
                logger.info('[*] Bypass SSL Pinning: ')
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
                # os.system('frida -U -f '+ options.package + ' -l ' + method)
            else:
                logger.error('[x_x] Script for method not found!')

        #Intercept url request in app
        elif options.name and options.method == "i-url-req":
            check.deviceConnected()
            method = APP_METHODS['Intercept URL Request']
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
                logger.error('[x_x] Script for method not found!')

        #Intercept Crypto Operations
        elif options.package and options.method == "i-crypto":
            check.deviceConnected()
            method = APP_METHODS['Intercept Crypto']
            if os.path.isfile(method):
                logger.info('[*] Intercept Crypto Operations: ')
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
                logger.error('[x_x] Script for method not found!')

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
            completed_process = subprocess.call(cmd)
            sys.exit(0)

        #dump decrypt application
        elif (options.package or options.name) and options.dumpapp:
            check.deviceConnected()
            check.iproxyInstalled()
            ARRAY_SSH_USER = APP_SSH['user']
            ARRAY_SSH_PWD = APP_SSH['password']
            SSH_IP = APP_SSH['ip']
            SSH_PORT = APP_SSH['port']
            choose_ssh_user = input('[?] Choose SSH user ({0} / {1}): '.format(ARRAY_SSH_USER[0], ARRAY_SSH_USER[1]))
            if choose_ssh_user in ARRAY_SSH_USER:
                SSH_USER = choose_ssh_user
            else:
                logger.error("[x_x] SSH user not found in list!")
                input_ssh_user = input('[?] Input your SSH user: ')
                SSH_USER = input_ssh_user
            choose_ssh_pwd = input('[?] Choose SSH password ({0} / {1}): '.format(ARRAY_SSH_PWD[0], ARRAY_SSH_PWD[1]))
            if choose_ssh_pwd in ARRAY_SSH_PWD:
                SSH_PWD = choose_ssh_pwd
            else:
                logger.error("[x_x] SSH password not found in list!")
                input_ssh_pwd = input('[?] Input your SSH password: ')
                SSH_PWD = input_ssh_pwd

            logger.info('[*] Dumping...')
            util = APP_UTILS['Dump Decrypt Application']
            if options.name is None:
                cmd = shlex.split("python3 " + util + " -u " + SSH_USER + " -p " + SSH_PWD + " -H " + SSH_IP + " -P " + str(SSH_PORT) + " " + options.package + " -o " + str(options.output_ipa))
            else:
                cmd = shlex.split("python3 " + util + " -u " + SSH_USER + " -p " + SSH_PWD + " -H " + SSH_IP + " -P " + str(SSH_PORT) + " " + options.name + " -o " + str(options.output_ipa))
            completed_process = subprocess.call(cmd)
            sys.exit(0)

        #dump memory application
        elif options.name and options.dumpmemory:
            check.deviceConnected()
            dump_memory(options.dumpmemory, options.name)

        #hexbytescan ipa
        elif options.hexscan:
            if(options.hexscan == 'help' and options.scanfile is None and options.task is None):
                hexbyte_scan(options.hexscan, '', '')
            #Read json file task
            elif options.hexscan == 'json' and options.scanfile and options.task:
                hexbyte_scan(options.hexscan, options.scanfile, options.task)
            #patch ipa file with address
            elif options.hexscan == 'patch' and options.scanfile and options.address:
                hexbyte_scan(options.hexscan, options.scanfile, options.address)
            #scan ipa file with pattern
            elif options.hexscan == 'scan' and options.scanfile and options.pattern:
                hexbyte_scan(options.hexscan, options.scanfile, options.pattern)
            elif(options.scanfile and options.task):
                logger.info("[*] Please use with command: ./ioshook --hexbyte-scan json --file " + options.scanfile + " --task " + options.task)
            elif(options.scanfile and options.address):
                logger.info("[*] Please use with command: ./ioshook --hexbyte-scan patch --file " + options.scanfile + " --address patchAddress,patchBytes,patchDistance")
            elif(options.scanfile and options.pattern):
                logger.info("[*] Please use with command: ./ioshook --hexbyte-scan scan --file " + options.scanfile + " --address " + options.addpatternress)
        
        #refluter ipa
        elif options.flutterfile:
            if(os.path.isfile(options.flutterfile)):
                logger.info("[*] Rename " + options.flutterfile + " to " + options.flutterfile.replace(' ', '_'))
                os.rename(options.flutterfile, options.flutterfile.replace(' ', '_'))
                file = options.flutterfile.replace(' ', '_')
                cmd = shlex.split("reflutter " + file)
                subprocess.call(cmd)
                sys.exit(0)

            else:
                logger.error("[x_x] File "+options.flutterfile+" not found!")
                sys.exit(0)
        
        #ios system log
        elif options.logcat:
            check.deviceConnected()
            cmd = shlex.split('idevicesyslog')
            completed_process = subprocess.call(cmd)
            sys.exit(0)

        #ios get the shell
        elif options.shell:
            check.deviceConnected()
            check.iproxyInstalled()
            isExist = check.existSSHCred()
            ARRAY_SSH_USER = APP_SSH['user']
            SSH_IP = APP_SSH['ip']
            SSH_PORT = APP_SSH['port']
            if not isExist:
                choose_ssh_user = input('[?] Choose SSH user ({0} / {1}): '.format(ARRAY_SSH_USER[0], ARRAY_SSH_USER[1]))
                if choose_ssh_user in ARRAY_SSH_USER:
                    SSH_USER = choose_ssh_user
                else:
                    logger.error("[x_x] SSH user not found in list!")
                    input_ssh_user = input('[?] Input your SSH user: ')
                    SSH_USER = input_ssh_user
                    logger.info("[*] Open SSH Shell on device")
                    cmd = shlex.split("ssh " + SSH_USER + "@" + SSH_IP + " -p " + str(SSH_PORT))
                    completed_process = subprocess.call(cmd)
                    sys.exit(0)
            else:
                SSH_USER = APP_SSH_CRED['user']
                SSH_PWD = APP_SSH_CRED['password']
                logger.info("[*] Open SSH Shell on device")
                cmd = shlex.split("sshpass -p " + SSH_PWD + " ssh " + SSH_USER + "@" + SSH_IP + " -p " + str(SSH_PORT))
                completed_process = subprocess.call(cmd)
                sys.exit(0)

        #ssh port forward
        elif options.sshportforward:
            check.deviceConnected()
            check.iproxyInstalled()
            isExist = check.existSSHCred()
            ARRAY_SSH_USER = APP_SSH['user']
            SSH_IP = APP_SSH['ip']
            SSH_PORT = APP_SSH['port']
            if not isExist:
                choose_ssh_user = input('[?] Choose SSH user ({0} / {1}): '.format(ARRAY_SSH_USER[0], ARRAY_SSH_USER[1]))
                if choose_ssh_user in ARRAY_SSH_USER:
                    SSH_USER = choose_ssh_user
                else:
                    logger.error("[x_x] SSH user not found in list!")
                    input_ssh_user = input('[?] Input your SSH user: ')
                    SSH_USER = input_ssh_user
            else:
                SSH_USER = APP_SSH_CRED['user']
                SSH_PWD = APP_SSH_CRED['password']

            if re.match(r'^\d+:\d+$', options.sshportforward):
                LOCAL_PORT = options.sshportforward.split(':')[0]
                DEVICE_PORT = options.sshportforward.split(':')[1]
                logger.info("[*] Forward port " + LOCAL_PORT + " to device port " + DEVICE_PORT)
                cmd = shlex.split("sshpass -p " + SSH_PWD + " ssh -R " + DEVICE_PORT + ":" + SSH_IP+ ":" + LOCAL_PORT + " " + SSH_USER + "@" + SSH_IP + " -p " + str(SSH_PORT))
                completed_process = subprocess.call(cmd)
                sys.exit(0)
            else:
                logger.error("[x_x] Please use with command: ./ioshook --ssh-port-forward LOCAL_PORT:DEVICE_PORT")
                sys.exit(0)
            ARRAY_SSH_USER = APP_SSH['user']
            SSH_IP = APP_SSH['ip']
            SSH_PORT = APP_SSH['port']
            choose_ssh_user = input('[?] Choose SSH user ({0} / {1}): '.format(ARRAY_SSH_USER[0], ARRAY_SSH_USER[1]))
            if choose_ssh_user in ARRAY_SSH_USER:
                SSH_USER = choose_ssh_user
            else:
                logger.error("[x_x] SSH user not found in list!")
                input_ssh_user = input('[?] Input your SSH user: ')
                SSH_USER = input_ssh_user
            logger.info("[*] Open SSH Shell on device - Default password is `alpine` ")
            cmd = shlex.split("ssh " + SSH_USER + "@" + SSH_IP + " -p " + str(SSH_PORT))
            completed_process = subprocess.call(cmd)
            sys.exit(0)

        #ioshook cli
        elif options.cli:
            logger.info("Welcome to iOSHook CLI! Type ? to list commands")
            iOSHook_CLI().cmdloop()
        else:
            logger.warning("[!] Specify the options. use (-h) for more help!")
            sys.exit(0)

    #EXCEPTION FOR FRIDA
    except frida.ServerNotRunningError:
        logger.error("[x_x] Frida server is not running.")
    except frida.TimedOutError:
        logger.error("[x_x] Timed out while waiting for device to appear.")
    except frida.TransportError:
        logger.error("[x_x] The application may crash or lose connection.")
    except frida.ProcessNotFoundError:
        logger.error("[x_x] Unable to find process with PID " + str(options.pid) + " or with name " + str(options.name) + ". You need run app first.!!")
    except frida.InvalidOperationError:
        logger.error("[x_x] Invalid operation. Please check your command.")
    #EXCEPTION FOR OPTIONPARSING

    #EXCEPTION FOR SYSTEM
    except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    except KeyboardInterrupt:
        logger.info("Bye bro!!")
        # sys.exit(0)

def run():
    #check python version
    if sys.version_info < (3, 0):
        logger.error("[x_x] iOS hook requires Python 3.x")
        sys.exit(0)
    else:
        # handle_first_run()
        deleteLog()
        main()

if __name__ == '__main__':
    run()

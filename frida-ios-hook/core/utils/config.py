import os
import sys
import json
import socket
from shutil import which
import shlex
import subprocess
from utils.log import *
import psutil

APP_AUTHOR = ''
APP_VERSION = ''
APP_SSH = ''
APP_PLATFORM_SUPORT = ''
APP_FIRST_RUN = ''
APP_PACKAGES = ''
APP_CONFIG = 'core/hook.json'

class config():

    def loadConfig():

        global APP_VERSION, APP_AUTHOR, APP_SSH, APP_PLATFORM_SUPORT, APP_FIRST_RUN, APP_PACKAGES

        try:
            if os.path.isfile(APP_CONFIG):
                with open(APP_CONFIG, 'r') as f:
                    data = f.read()

                obj = json.loads(data)

                APP_AUTHOR = obj['author']
                APP_VERSION = obj['version']
                APP_CLI_VERSION = obj['cliVersion']
                APP_METHODS = obj['methods']
                APP_UTILS = obj['utils']
                APP_SSH = obj['ssh']
                APP_PLATFORM_SUPORT = obj['platformSupport']
                APP_FIRST_RUN = obj['firstRun']
                APP_PACKAGES = obj['packages']
                APP_FRIDA_SCRIPTS = obj['fridaScripts']
                return {
                    "version" : APP_VERSION,
                    "cliVersion": APP_CLI_VERSION,
                    "author": APP_AUTHOR,
                    "methods": APP_METHODS,
                    "utils": APP_UTILS,
                    "ssh": APP_SSH,
                    'platformSupport': APP_PLATFORM_SUPORT,
                    'firstRun': APP_FIRST_RUN,
                    'packages': APP_PACKAGES,
                    'fridaScripts': APP_FRIDA_SCRIPTS
                }
            else:
                logger.error('Configuration File Not Found.')
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def loadBanner():
        print ('''\033[1;31m \n
        _|    _|_|      _|_|_|      _|    _|                      _|        
            _|    _|  _|            _|    _|    _|_|      _|_|    _|  _|    
        _|  _|    _|    _|_|        _|_|_|_|  _|    _|  _|    _|  _|_|      
        _|  _|    _|        _|      _|    _|  _|    _|  _|    _|  _|  _|    
        _|    _|_|    _|_|_|        _|    _|    _|_|      _|_|    _|    _|  
                        https://noobpk.github.io          #noobboy      
                    Trace Class/Func & Modify Return Value  
        ''')

        print ("\033[1;34m[*]___author___: @" + APP_AUTHOR + "\033[1;37m")
        print ("\033[1;34m[*]___version___: " + APP_VERSION + "\033[1;37m")
        print ("")

config.loadConfig()
config.loadBanner()

class check():

    def initLoad():
        try:
            if APP_FIRST_RUN == True:
                logger.info("[*] This is the first time you are running iOSHook. We are need install some package.")
                if sys.platform == 'darwin':
                    for name, cmd in APP_PACKAGES['darwin'].items():
                        logger.info("[*] Install " + name)
                        cmd = shlex.split("brew install " + cmd)
                        subprocess.call(cmd)
                elif sys.platform == 'linux':
                    for name, cmd in APP_PACKAGES['linux'].items():
                        logger.info("[*] Install " + name)
                        cmd = shlex.split("sudo apt-get install " + cmd)
                        subprocess.call(cmd)
                elif sys.platform == 'win32':
                    logger.warning("[*] You are running iOSHook on Windows. Please download on https://libimobiledevice.org/#downloads and install package then set system variable.!!")

                with open(APP_CONFIG, "r") as f:
                    data = json.load(f)
                    data['fristRun'] = False

                with open(APP_CONFIG, "w") as f:
                    f.write(json.dumps(data, sort_keys=False, indent=4))

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def platform():
        try:
            if sys.platform not in APP_PLATFORM_SUPORT:
                sys.exit(logger.error("[x_x] Your platform currently does not support."))
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def pswin32():
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

    def iproxyInstalled():
        try:
            if(which('iproxy') is not None):
                # iproxyPortOpen
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((APP_SSH['ip'],APP_SSH['port']))
                if result == 0:
                   logger.info("[*] Iproxy process for" + APP_SSH['port'] + "port alive.")
                else:
                    logger.error("[*] Iproxy process for" + APP_SSH['port'] + "port dead.")
                    sock.close()
                    sys.exit(0)
            else:
                logger.info('[*] iproxy not install. try \"brew install usbmuxd\"')
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

check.initLoad()
check.platform()
check.pswin32()

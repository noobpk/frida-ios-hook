import os
import sys
import json
import socket
from shutil import which
import shlex
import subprocess
from utils.log import *
import psutil
import time

APP_AUTHOR = ''
APP_VERSION = ''
APP_SSH = ''
APP_SSH_CRED = ''
APP_PLATFORM_SUPPORT = ''
APP_FIRST_RUN = ''
APP_PACKAGES = ''
APP_CONFIG = 'core/hook.json'

class config():

    def loadConfig():

        global APP_VERSION, APP_AUTHOR, APP_SSH, APP_SSH_CRED, APP_PLATFORM_SUPPORT, APP_FIRST_RUN, APP_PACKAGES

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
                APP_SSH_CRED = obj['sshCredential']
                APP_PLATFORM_SUPPORT = obj['platformSupport']
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
                    "sshCredential": APP_SSH_CRED,
                    "platformSupport": APP_PLATFORM_SUPPORT,
                    "firstRun": APP_FIRST_RUN,
                    "packages": APP_PACKAGES,
                    "fridaScripts": APP_FRIDA_SCRIPTS
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
                elif sys.platform.startswith('linux'):
                    for name, cmd in APP_PACKAGES['linux'].items():
                        logger.info("[*] Install " + name)
                        cmd = shlex.split("sudo apt-get install " + cmd)
                        subprocess.call(cmd)
                elif sys.platform == 'win32':
                    logger.warning("[*] You are running iOSHook on Windows. Please download on https://libimobiledevice.org/#downloads and install package then set system variable.!!")

                with open(APP_CONFIG, "r") as f:
                    data = json.load(f)
                    data['firstRun'] = False

                with open(APP_CONFIG, "w") as f:
                    f.write(json.dumps(data, sort_keys=False, indent=4))

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def platform():
        try:
            if sys.platform not in APP_PLATFORM_SUPPORT:
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
                return sys.exit(logger.error("[x_x] Please install iTunes on MicrosoftStore or run iTunes first."))
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def iproxyInstalled():
        try:
            if(which('iproxy') is not None):
                # iproxyPortOpen
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((APP_SSH['ip'], APP_SSH['port']))
                if result == 0:
                    logger.info("[*] Iproxy process for port " + str(APP_SSH['port']) + " is alive.")
                    sock.close()
                    is_kill_iproxy = input('[?] Do you want kill iproxy (yes/no): ')
                    yes_choices = ['yes', 'y']
                    no_choices = ['no', 'n']
                    if is_kill_iproxy.lower() in yes_choices:
                        logger.info("[*] Kill iproxy process")
                        cmd = shlex.split("killall iproxy")
                        subprocess.Popen(cmd)
                        time.sleep(2) 
                        logger.info("Bye bro!!")
                        sys.exit(0)
                else:
                    logger.error("[*] Iproxy process for port " + str(APP_SSH['port']) + " is dead.")
                    while True:
                        iproxy_device_port = input('[?] Input your device port (default 22): ')
                        if iproxy_device_port == '':
                            iproxy_device_port = 22
                            logger.info("[*] Start iproxy: iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                            cmd = shlex.split("iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                            subprocess.Popen(cmd)
                            time.sleep(2)
                            break
                        elif not iproxy_device_port.isdigit():
                            logger.error("[x_x] Please enter valid port number.")
                        iproxy_start = input('[?] Do you want start iproxy 2222 22 (yes/no): ')
                        yes_choices = ['yes', 'y']
                        no_choices = ['no', 'n']
                        if iproxy_start.lower() in yes_choices:
                            logger.info("[*] Start iproxy ")
                            cmd = shlex.split("iproxy " + str(APP_SSH['port']) + " 22")
                            subprocess.Popen(cmd)
                            time.sleep(2)
                            break
                        elif iproxy_start.lower() in no_choices:
                            iproxy_device_port = input('[?] Input your device port (default 22): ')
                            if iproxy_device_port == '':
                                iproxy_device_port = 22
                                logger.info("[*] Start iproxy ")
                                cmd = shlex.split("iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                                subprocess.Popen(cmd)
                                time.sleep(2)
                                break
                            else:
                                logger.info("[*] Start iproxy ")
                                cmd = shlex.split("iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                                subprocess.Popen(cmd)
                                time.sleep(2)
                                break
                            sys.exit(0)
                            break
                        else:
                            logger.info("[*] Start iproxy: iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                            cmd = shlex.split("iproxy " + str(APP_SSH['port']) + " " + str(iproxy_device_port))
                            subprocess.Popen(cmd)
                            time.sleep(2)
                            break
                        
            else:
                logger.info('[*] iproxy not install. try \"brew install usbmuxd\"')
                sys.exit(0)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def deviceConnected():
        try:
            if(which('idevice_id') is not None):
                cmd = shlex.split("idevice_id -l")
                result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                result.wait()
                out, err = result.communicate()
                deviceId = str(out, 'UTF-8')
                if (len(deviceId) == 0):
                    logger.info('[*] Please connect device then run again.')
                    sys.exit(0)
            else:
                logger.info('[*] ideviceinstaller not install. try \"brew install ideviceinstaller\"')
                sys.exit(0)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def existSSHCred():
        try:
            if APP_SSH_CRED['user'] == '' or APP_SSH_CRED['password'] == '':
                return False
            else:
                return True
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

check.initLoad()
check.platform()
check.pswin32()

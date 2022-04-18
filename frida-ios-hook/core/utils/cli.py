import fnmatch
from cmd import Cmd

from utils.listapp import *
from utils.checkversion import *
from utils.log import *
from utils.config import *

GLOBAL_CONFIG = config.loadConfig()

APP_VERSION = GLOBAL_CONFIG['version']
APP_CLI_VERSION = GLOBAL_CONFIG['cliVersion']
APP_FRIDA_SCRIPTS = GLOBAL_CONFIG['fridaScripts']
APP_METHODS = GLOBAL_CONFIG['methods']
APP_UTILS = GLOBAL_CONFIG['utils']
APP_SSH = GLOBAL_CONFIG['ssh']

class iOSHook_CLI(Cmd):
    try:
        prompt = 'iOSHook> '

        #DO COMMAND
        def do_version(self, arg):
            logger.info('[*] iOSHook version: ' + APP_VERSION)
            logger.info('[*] iOSHook CLI version: ' + APP_CLI_VERSION)

        def do_listdevices(self, arg):
            logger.info('[*] List All Devices: ')
            print(arg)
            os.system('frida-ls-devices')

        def do_listapps(self, arg):
            logger.info('[*] List All Apps on Devies: ')
            device = get_usb_iphone()
            list_applications(device)

        def do_listappinfo(self, arg):
            method = APP_METHODS['List All Application']
            if os.path.isfile(method):
                logger.info('[*] List Info of Apps on Itunes: ')
                process = 'itunesstored'
                os.system('frida -U -n '+ process + ' -l ' + method)
                #sys.stdin.read()
            else:
                logger.error('[?] Script not found!')

        def do_listscripts(self, arg):
            path = APP_FRIDA_SCRIPTS
            if os.path.exists(path):
                logger.info('[*] List All Scripts: ')
                for file_name in os.listdir(path):
                    if fnmatch.fnmatch(file_name, '*.js'):
                        print('[*] ' + file_name)
            else:
                logger.error('[?] Path frida-script not exists!')

        def do_logcat(self, arg):
            logger.info('[*] Device System Log: ')
            cmd = shlex.split('idevicesyslog')
            subprocess.call(cmd)

        def do_shell(self, arg):
            logger.info('[*] Get Device Shell: ')
            SSH_USER = APP_SSH['user']
            SSH_IP = str(APP_SSH['ip'])
            SSH_PORT = str(APP_SSH['port'])
            cmd = shlex.split("ssh " + SSH_USER + "@" + SSH_IP + " -p " + SSH_PORT)
            subprocess.call(cmd)

        def do_exit(self, arg):
            logger.info("Bye bro!!")
            return True
        
        #HELP DOCUMENT
        def help_version(self):
            logger.info('Show Version')

        def help_listdevices(self):
            logger.info('List All Devices')

        def help_listapps(self):
            logger.info('List The Installed Apps')

        def help_listappinfo(self):
            logger.info('List Info of Apps on Itunes. When script was loaded, input list() excute')
        def help_listscripts(self):
            logger.info('List All Scripts')

        def help_logcat(self):
            logger.info('Show System Log of Device')

        def help_shell(self):
            logger.info('Get The Shell of Connect Device')

        def help_exit(self):
            print('Exit iOSHook CLI')

        def emptyline(self):
            pass

        do_EOF = do_exit
        help_EOF = help_exit

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

# if __name__ == '__main__':
#     MyPrompt().cmdloop()
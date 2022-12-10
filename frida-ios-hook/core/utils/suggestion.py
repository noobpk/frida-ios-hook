import os
from utils.config import *

GLOBAL_CONFIG = config.loadConfig()
APP_FRIDA_SCRIPTS = GLOBAL_CONFIG['fridaScripts']

list_Script = os.listdir(APP_FRIDA_SCRIPTS)

def suggestion_script(word):
    i = 0
    while i < len(list_Script):
        if word[0] == list_Script[i][0] and word[1] == list_Script[i][1]:
            return list_Script[i]
        i += 1
    else:
        return False

# if __name__ == '__main__':
#     suggestion_script()

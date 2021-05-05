import sys
import string
import logging
import os
import re
from io import open

# Progress bar function
def printProgress (times, total, prefix ='', suffix ='', decimals = 2, bar = 100):
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if times == total:
        print("\n")


# A very basic implementations of Strings
def strings(filename, directory, min=4):
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory, filename)
    with open(path, encoding='Latin-1') as infile:
        str_list = re.findall("[\x20-\x7E]+\x00", infile.read())
        with open(strings_file, "a") as st:
            for string in str_list:
                if len(string) > min:
                    logging.debug(string)
                    st.write(string + "\n")

# Method to receive messages from Javascript API calls
def on_message(message, data):
   print("[on_message] message:", message, "data:", data)

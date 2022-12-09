import pytest
import subprocess
import shlex
import os

PATH = os.path.dirname(__file__)

def test_main():
    cmd = shlex.split('./ioshook -h')
    subprocess.call(cmd, cwd=PATH+'/frida-ios-hook')
    assert False

def test_option_list_devices():
    cmd = shlex.split('./ioshook --list-devices')
    subprocess.call(cmd, cwd=PATH+'/frida-ios-hook')

def test_option_list_apps():
    cmd = shlex.split('./ioshook --list-apps')
    subprocess.call(cmd, cwd=PATH+'/frida-ios-hook')

def test_option_list_apps():
    cmd = shlex.split('./ioshook --list-apps')
    subprocess.call(cmd, cwd=PATH+'/frida-ios-hook')

def test_option_list_app_info():
    cmd = shlex.split('./ioshook --list-appinfo')
    # subprocess.call(cmd, cwd=PATH+'/frida-ios-hook')

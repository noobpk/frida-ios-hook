#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author : AloneMonkey
# blog: www.alonemonkey.com
# Modified by noobpk

import sys
import codecs
import frida
import threading
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re

import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
from log import *

script_dir = os.path.dirname(os.path.realpath(__file__))

DUMP_JS = os.path.join(script_dir, '../../methods/dump.js')
BYPASS_JB_JS = os.path.join(script_dir, '../../methods/bypass_jailbreak.js')

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
# Default output directory for dumped IPAs
DUMP_OUTPUT_DIR = os.path.join(os.getcwd(), 'dumps')
file_dict = {}

finished = threading.Event()
dump_success = threading.Event()


def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device


def generate_ipa(path, display_name, output_dir=None):
    """
    Generate IPA file from dumped payload.
    
    Args:
        path: Path to the payload directory
        display_name: Display name for the IPA file
        output_dir: Output directory for the IPA file (default: DUMP_OUTPUT_DIR)
    """
    if output_dir is None:
        output_dir = DUMP_OUTPUT_DIR
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info('Created output directory: {}'.format(output_dir))
        except os.error as err:
            logger.error('Failed to create output directory {}: {}'.format(output_dir, err))
            # Fallback to current directory
            output_dir = os.getcwd()
            logger.warning('Using current directory instead: {}'.format(output_dir))
    
    ipa_filename = display_name + '.ipa'
    ipa_path = os.path.join(output_dir, ipa_filename)

    logger.info('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', ipa_path, target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
        
        # Verify the IPA was created
        if os.path.exists(ipa_path):
            file_size = os.path.getsize(ipa_path)
            logger.info('✅ IPA generated successfully: {}'.format(ipa_path))
            logger.info('   File size: {:.2f} MB'.format(file_size / (1024 * 1024)))
        else:
            logger.warning('IPA file was not created at expected path: {}'.format(ipa_path))
        
        dump_success.set()
    except Exception as e:
        logger.error('Error generating IPA: {}'.format(e))
        print(e)
        finished.set()

def on_message(message, data, ssh_connection):
    t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        t.desc = os.path.basename(filename).decode("utf-8")
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'
            local_file_path = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))

            # Try SCP first
            scp_success = False
            try:
                with SCPClient(ssh_connection.get_transport(), progress = progress, socket_timeout = 60) as scp:
                    scp.get(scp_from, scp_to)
                scp_success = True
            except Exception as scp_error:
                error_msg = str(scp_error)
                if 'Permission denied' in error_msg:
                    logger.warning('SCP Permission denied for: {}'.format(os.path.basename(dump_path)))
                    logger.info('Attempting to fix permissions via SSH...')
                    
                    # Try to fix permissions via SSH command
                    try:
                        # Try to chmod the file on the device
                        stdin, stdout, stderr = ssh_connection.exec_command('chmod 644 "{}"'.format(dump_path))
                        exit_status = stdout.channel.recv_exit_status()
                        if exit_status == 0:
                            logger.info('Fixed permissions, retrying SCP...')
                            # Retry SCP after fixing permissions
                            with SCPClient(ssh_connection.get_transport(), progress = progress, socket_timeout = 60) as scp:
                                scp.get(scp_from, scp_to)
                            scp_success = True
                        else:
                            error_output = stderr.read().decode('utf-8')
                            logger.warning('Could not fix permissions: {}'.format(error_output))
                    except Exception as fix_error:
                        logger.warning('Failed to fix permissions via SSH: {}'.format(fix_error))
                    
                    # If still failed, try copying to /tmp first (if not already there)
                    if not scp_success and not dump_path.startswith('/tmp/'):
                        tmp_path = '/tmp/' + os.path.basename(dump_path)
                        logger.info('Attempting to copy file to /tmp for easier access...')
                        try:
                            # Copy file to /tmp on device
                            stdin, stdout, stderr = ssh_connection.exec_command('cp "{}" "{}" && chmod 644 "{}"'.format(dump_path, tmp_path, tmp_path))
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                logger.info('Copied to /tmp, trying SCP from there...')
                                with SCPClient(ssh_connection.get_transport(), progress = progress, socket_timeout = 60) as scp:
                                    scp.get(tmp_path, scp_to)
                                scp_success = True
                                # Clean up /tmp file
                                try:
                                    ssh_connection.exec_command('rm "{}"'.format(tmp_path))
                                except:
                                    pass
                            else:
                                error_output = stderr.read().decode('utf-8')
                                logger.warning('Could not copy to /tmp: {}'.format(error_output))
                        except Exception as copy_error:
                            logger.warning('Failed to copy to /tmp: {}'.format(copy_error))
                    
                    # If all else fails, try using cat via SSH (slower but works)
                    if not scp_success:
                        logger.warning('SCP failed, trying alternative method via SSH cat...')
                        try:
                            stdin, stdout, stderr = ssh_connection.exec_command('cat "{}"'.format(dump_path))
                            file_data = stdout.read()
                            if file_data:
                                with open(local_file_path, 'wb') as f:
                                    f.write(file_data)
                                logger.info('Successfully retrieved file via SSH cat')
                                scp_success = True
                            else:
                                error_output = stderr.read().decode('utf-8')
                                logger.error('SSH cat failed: {}'.format(error_output))
                        except Exception as cat_error:
                            logger.error('SSH cat method also failed: {}'.format(cat_error))
                else:
                    logger.error('SCP error: {}'.format(scp_error))
            
            if not scp_success:
                logger.error('Failed to retrieve file: {}'.format(os.path.basename(dump_path)))
                logger.error('This file will be missing from the IPA. Continuing with other files...')
                # Continue processing other files instead of failing completely
                return

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh_connection.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()

def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1


def get_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)

    return applications


def load_js_file(session, filename, ssh_connection):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    # Create a closure to pass ssh_connection to on_message
    def message_handler(message, data):
        on_message(message, data, ssh_connection)
    
    # Handle script crashes and errors
    # Note: Frida uses 'destroyed' event, not 'detached'
    def on_destroyed():
        if dump_success.is_set():
            logger.info('Script destroyed after dump completion (expected).')
        else:
            logger.warning('Script was destroyed. Process may have crashed or script was unloaded.')
        finished.set()
    
    script.on('message', message_handler)
    script.on('destroyed', on_destroyed)
    script.load()

    return script


def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)


def open_target_app(device, name_or_bundleid):
    if not name_or_bundleid:
        logger.error('Target app name or bundle identifier is required')
        return None, '', '', 0
    
    logger.info('Start the target app {}'.format(name_or_bundleid))

    pid = 0
    session = None
    display_name = ''
    bundle_identifier = ''
    
    # Find the app in the list of installed applications
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier
            break

    if not bundle_identifier:
        logger.error('App "{}" not found. Please check the app name or bundle identifier.'.format(name_or_bundleid))
        return None, '', '', 0

    try:
        # If app is not running (pid == 0), spawn it
        if pid == 0:
            logger.info('App is not running. Spawning...')
            # FIXED: device.spawn() takes a string, not a list (compatible with Frida 12+)
            pid = device.spawn(bundle_identifier)
            logger.info('Spawned app with PID: {}'.format(pid))
            
            # Attach to the spawned process BEFORE resuming
            # This allows us to hook early initialization code and bypass anti-debugging
            session = device.attach(pid)
            logger.info('Attached to process')
            
            # Set up session crash detection
            def on_session_detached(reason, crash):
                if dump_success.is_set():
                    logger.info('Session detached after dump completion (reason: {}).'.format(reason))
                elif reason == 'process-terminated':
                    logger.error('')
                    logger.error('⚠️  CRITICAL: App crashed immediately after spawn!')
                    logger.error('   This app has very strong anti-debugging protection.')
                    logger.error('   Even with bypass script, the app detected Frida and crashed.')
                    logger.error('')
                    logger.error('   ✅ SOLUTION: Launch the app MANUALLY on your device first,')
                    logger.error('      then run the dump command again.')
                    logger.error('      When attached to running app, anti-debugging is bypassed.')
                elif crash:
                    logger.error('Session crashed: {}'.format(crash))
                else:
                    logger.warning('Session detached: {}'.format(reason))
                finished.set()
            session.on('detached', on_session_detached)
            
            # Inject bypass script BEFORE resuming to prevent anti-debugging crashes
            # This is critical for apps that detect Frida immediately on startup
            bypass_script = None
            if os.path.isfile(BYPASS_JB_JS):
                try:
                    logger.info('Injecting bypass script to prevent anti-debugging detection...')
                    with codecs.open(BYPASS_JB_JS, 'r', 'utf-8') as f:
                        bypass_source = f.read()
                    bypass_script = session.create_script(bypass_source)
                    bypass_script.load()
                    logger.info('Bypass script loaded successfully')
                    time.sleep(0.5)  # Brief delay to let bypass hooks take effect
                except Exception as bypass_error:
                    logger.warning('Failed to load bypass script: {}. Continuing without it...'.format(bypass_error))
            
            # Resume the process after attaching (and bypass injection)
            # Note: Some apps may fail to resume if they have security checks
            try:
                device.resume(pid)
                logger.info('Resumed process')
                # Give the app more time to initialize before we start dumping
                # Apps with anti-debugging may need this delay
                time.sleep(3)  # Increased delay to let app initialize with bypass in place
            except Exception as resume_error:
                logger.warning('Failed to resume process: {}. Continuing anyway...'.format(resume_error))
                # Continue even if resume fails - the process might already be running
                time.sleep(3)
        else:
            # App is already running, just attach to it
            logger.info('App is already running with PID: {}. Attaching...'.format(pid))
            session = device.attach(pid)
            logger.info('Attached to running process')
            
            # Set up session crash detection
            def on_session_detached(reason, crash):
                if dump_success.is_set():
                    logger.info('Session detached after dump completion (reason: {}).'.format(reason))
                elif crash:
                    logger.error('Session crashed: {}'.format(crash))
                else:
                    logger.warning('Session detached: {}'.format(reason))
                finished.set()
            session.on('detached', on_session_detached)
            
    except frida.ProcessNotFoundError as e:
        logger.error('Process not found: {}. The app may have crashed or been terminated.'.format(e))
        return None, display_name, bundle_identifier, 0
    except frida.InvalidOperationError as e:
        logger.error('Invalid operation: {}. The app may not be debuggable or may require special permissions.'.format(e))
        return None, display_name, bundle_identifier, 0
    except frida.TransportError as e:
        logger.error('Transport error: {}. Connection to device may have been lost.'.format(e))
        return None, display_name, bundle_identifier, 0
    except Exception as e:
        error_msg = str(e)
        if 'os/kern' in error_msg.lower() or 'failure' in error_msg.lower():
            logger.error('Kernel-level error: {}. This may indicate:'.format(e))
            logger.error('  1. The app requires special permissions or entitlements')
            logger.error('  2. The device may need to be fully jailbroken')
            logger.error('  3. The app may have anti-debugging protections')
            logger.error('  4. Try killing the app first and then running the dump again')
        else:
            logger.error('Failed to spawn/attach to app: {}'.format(e))
        return None, display_name, bundle_identifier, 0

    return session, display_name, bundle_identifier, pid


def start_dump(session, ipa_name, display_name, ssh_connection, device, pid, output_dir=None):
    logger.info('Dumping {} to {}'.format(display_name, TEMP_DIR))
    
    # Wait a bit longer for app to fully initialize before injecting dump script
    # Some apps with anti-debugging need more time
    logger.info('Waiting for app to initialize (this helps prevent crashes)...')
    time.sleep(3)  # Increased delay for apps with anti-debugging
    
    # Check if process is still alive before proceeding
    try:
        # Try to enumerate processes to verify our target is still running
        processes = device.enumerate_processes()
        process_found = False
        for proc in processes:
            if proc.pid == pid:
                process_found = True
                logger.info('Process {} is still running'.format(pid))
                break
        if not process_found:
            logger.error('Process {} is no longer running. App may have crashed.'.format(pid))
            return False
    except Exception as e:
        logger.warning('Could not verify process status: {}'.format(e))
        # Continue anyway - the attach might still work
    
    try:
        script = load_js_file(session, DUMP_JS, ssh_connection)
        logger.info('Dump script loaded. Starting dump process...')
        
        # Post dump command to script
        script.post('dump')
        
        # Wait for dump to complete with timeout
        # Some apps may crash, so we don't want to wait forever
        logger.info('Waiting for dump to complete (this may take a while)...')
        if not finished.wait(timeout=300):  # 5 minute timeout
            logger.error('Dump operation timed out after 5 minutes')
            logger.error('The app may have crashed or the dump script may be stuck')
            return False
        
        logger.info('Dump completed successfully')
        generate_ipa(PAYLOAD_PATH, ipa_name, output_dir)
        return True
        
    except frida.ProcessNotFoundError as e:
        logger.error('Process not found during dump: {}. App may have crashed.'.format(e))
        logger.error('This often happens when apps detect Frida or have anti-debugging protection.')
        return False
    except frida.TransportError as e:
        logger.error('Transport error during dump: {}. Connection lost - app may have crashed.'.format(e))
        logger.error('The app likely crashed when the dump script was injected.')
        return False
    except Exception as e:
        logger.error('Error during dump: {}'.format(e))
        logger.error('The app may have crashed. Check device logs for more details.')
        return False
    finally:
        if session:
            try:
                session.detach()
            except:
                pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (by AloneMonkey v2.0)')
    parser.add_argument('-u', '--user', dest='ssh_user', help='SSH username')
    parser.add_argument('-p', '--password', dest='ssh_password', help='SSH password')
    parser.add_argument('-H', '--host', dest='ssh_host', help='SSH host')
    parser.add_argument('-P', '--port', dest='ssh_port', type=int, help='SSH port')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-d', '--output-dir', dest='output_dir', help='Output directory for dumped IPAs (default: ./dumps)')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')
    args = parser.parse_args()

    exit_code = 0
    ssh = None

    if not len(sys.argv[1:]):
        parser.print_help()
        sys.exit(exit_code)

    device = get_usb_iphone()

    ssh_user = args.ssh_user
    ssh_password = args.ssh_password
    ssh_host = args.ssh_host
    ssh_port = args.ssh_port
    name_or_bundleid = args.target
    output_ipa = args.output_ipa
    output_dir = args.output_dir if args.output_dir else DUMP_OUTPUT_DIR
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_password, timeout=5)

        if not name_or_bundleid:
            logger.error('Target app name or bundle identifier is required')
            parser.print_help()
            sys.exit(1)
        
        create_dir(PAYLOAD_PATH)
        
        # Try to open/attach to the target app
        # Note: If you get "(os/kern) failure" errors, try:
        # 1. Kill the app manually on the device first
        # 2. Ensure the device is fully jailbroken
        # 3. Check that Frida server version matches client version
        # 4. Some apps with anti-debugging may block Frida
        (session, display_name, bundle_identifier, pid) = open_target_app(device, name_or_bundleid)
        
        if not session:
            logger.error('Failed to open target app. Exiting.')
            logger.error('Troubleshooting tips:')
            logger.error('  - Ensure the app is installed on the device')
            logger.error('  - Try killing the app first: ssh into device and run "killall <app_name>"')
            logger.error('  - Verify Frida server is running: frida-ps -U')
            logger.error('  - Check device is fully jailbroken with proper permissions')
            sys.exit(1)
        
        if output_ipa == "None" or not output_ipa:
            output_ipa = display_name if display_name else bundle_identifier
        output_ipa = re.sub(r'\.ipa$', '', output_ipa)
        if session:
            success = start_dump(session, output_ipa, display_name, ssh, device, pid, output_dir)
            if not success:
                logger.error('')
                logger.error('=' * 70)
                logger.error('Dump failed. The app crashed during spawn/attach.')
                logger.error('')
                logger.error('This app has strong anti-debugging that detects Frida immediately.')
                logger.error('The bypass script was injected but the app still crashed.')
                logger.error('')
                logger.error('✅ RECOMMENDED SOLUTION: Launch app manually first')
                logger.error('')
                logger.error('   Step 1: Open the app on your device manually')
                logger.error('   Step 2: Wait for it to fully load and be ready')
                logger.error('   Step 3: Run the dump command again:')
                logger.error('')
                logger.error('      ./ioshook -n "{}" -d -o {}'.format(display_name, output_ipa))
                logger.error('')
                logger.error('   When the app is already running, it will ATTACH instead of SPAWN,')
                logger.error('   which bypasses the initial anti-debugging checks.')
                logger.error('')
                logger.error('Alternative solutions (if manual launch doesn\'t work):')
                logger.error('')
                logger.error('  Option 2: Use bypass in separate terminal first')
                logger.error('    Terminal 1: ./ioshook -p {} -m bypass-jb'.format(bundle_identifier))
                logger.error('    Terminal 2: ./ioshook -n "{}" -d -o {}'.format(display_name, output_ipa))
                logger.error('')
                logger.error('  Option 3: Advanced Frida hiding techniques')
                logger.error('    - Use Frida with stealth mode')
                logger.error('    - Patch Frida detection functions')
                logger.error('    - Use custom Frida server builds')
                logger.error('=' * 70)
                sys.exit(1)
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        exit_code = 1
    except paramiko.AuthenticationException as e:
        print(e)
        exit_code = 1
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        exit_code = 1

    if ssh:
        ssh.close()

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH)

    sys.exit(exit_code)

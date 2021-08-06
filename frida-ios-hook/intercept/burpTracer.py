import frida
import requests
import time

BURP_HOST = "localhost"
BURP_PORT = 26080

def frida_process_message(self, message):
    handled = False
    print (message)
    #print (payload)
    if message['type'] == 'input':
        # handled = True
        print (message["payload"])
    elif message['type'] == 'send':
        stanza = message['payload']

        if stanza['from'] == '/http':
            req = requests.request('FRIDA', 'http://%s:%d/' % (BURP_HOST, BURP_PORT), headers={'content-type':'text/plain'}, data=stanza['payload'])
            self._script.post({ 'type': 'input', 'payload': req.content })
            handled = True

    if not handled:
        self.__process_message(message)

device = frida.get_usb_device()
pid = device.spawn(["application.abc.xyz"])
device.resume(pid)
time.sleep(1)  # Without it Java.perform silently fails
session = device.attach(pid)
with open("handlers.js") as f:
    script = session.create_script(f.read())
script.on("message", frida_process_message)
script.load()
input()

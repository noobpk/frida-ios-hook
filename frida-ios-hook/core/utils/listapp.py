from base64 import b64encode
import frida
import os
import sys
import threading

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

def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""

    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K


def _detect_iterm2_icon_size():
    """
    frida-ps (-Ua) renders icons using iTerm2 inline image protocol.
    We'll enable it only on iTerm2 to avoid printing escape codes elsewhere.
    """
    term_program = os.environ.get("TERM_PROGRAM")
    if term_program != "iTerm.app":
        return 0
    if not (sys.stdout.isatty() and sys.stdin.isatty()):
        return 0
    # A reasonable fixed size; frida-tools computes it dynamically, but this is enough to match frida-ps UX.
    return 18


def _compute_icon_width(item) -> int:
    for icon in getattr(item, "parameters", {}).get("icons", []):
        if icon.get("format") == "png":
            return 4
    return 0


def _pick_png_icon(item):
    for icon in getattr(item, "parameters", {}).get("icons", []):
        if icon.get("format") == "png" and icon.get("image") is not None:
            return icon
    return None


def _render_iterm2_icon(icon, icon_size: int) -> str:
    # iTerm2 inline image escape sequence (same as frida-tools).
    return "\033]1337;File=inline=1;width={}px;height={}px;:{}\007".format(
        icon_size, icon_size, b64encode(icon["image"]).decode("ascii")
    )

def get_applications(device, scope=None):
    try:
        if scope is None:
            applications = device.enumerate_applications()
        else:
            try:
                applications = device.enumerate_applications(scope=scope)
            except TypeError:
                applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)

    return applications

def list_applications(device):
    icon_size = _detect_iterm2_icon_size()
    scope = "full" if icon_size != 0 else "minimal"

    applications = list(get_applications(device, scope=scope))

    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len('{}'.format(app.pid)), applications))
        icon_width = max(map(_compute_icon_width, applications)) if icon_size != 0 else 0
        name_column_width = icon_width + max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        icon_width = 0
        name_column_width = 0
        identifier_column_width = 0

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))

    line_format = '%' + str(pid_column_width) + 's  %s  %-' + str(identifier_column_width) + 's'
    name_format = '%-' + str(max(name_column_width - icon_width, 0)) + 's'

    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if icon_width != 0:
            icon = _pick_png_icon(application)
            if icon is not None:
                icon_str = _render_iterm2_icon(icon, icon_size)
            else:
                icon_str = "   "
            name = icon_str + " " + (name_format % application.name)
        else:
            name = name_format % application.name

        if application.pid == 0:
            print(line_format % ('-', name, application.identifier))
        else:
            print(line_format % (application.pid, name, application.identifier))

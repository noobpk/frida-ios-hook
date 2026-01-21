## frida-ios-hook wiki

### Install
```
# Latest release
https://github.com/noobpk/frida-ios-hook/releases

# Development version
git clone -b dev https://github.com/noobpk/frida-ios-hook
```

### Build
```
cd frida-ios-hook/
pip3 install -r requirements.txt
python3 setup.py
cd frida-ios-hook
```

### Spawn/Attach App with Script
```
./ioshook -p com.apple.AppStore -s trace_class.js
./ioshook -n 'App Store' -s trace_class.js
```

### Quick Methods
Attach to App Store and run static analysis
```
./ioshook -n 'App Store' -m app-static
```

Spawn App Store and bypass jailbreak detection
```
./ioshook -p com.apple.AppStore -m bypass-jb
```

Spawn App Store and bypass SSL pinning
```
./ioshook -p com.apple.AppStore -m bypass-ssl
```

Attach to App Store and intercept URL request
```
./ioshook -n 'App Store' -m i-url-req
```

Spawn App Store and intercept crypto operations
```
./ioshook -p com.apple.AppStore -m i-crypto
```

### Dump Decrypt IPA
```
./ioshook -p com.apple.AppStore -d -o App_dump_name
./ioshook -n 'App Store' -d -o App_dump_name
./ioshook -p com.apple.AppStore -d --network 192.168.1.100:22
./ioshook -n 'App Store' -d --local
```

### Dump Memory
Dump memory of running application (e.g. --string)

```
./ioshook -n 'App Store' --dump-memory --string
```

### HexByte Scan IPA
Scan/patch IPA file for hex pattern (e.g. E103??AA????E0)

```
./ioshook --hexbyte-scan scan --file AppStore.ipa --pattern E103??AA????E0
./ioshook --hexbyte-scan json --file AppStore.ipa --task /hexbytescan-tasks/openssl_hook.json
```

### SSH Shell (Network)
Connect via network SSH (default port 22)

```
./ioshook --shell --network 192.168.1.100:22
./ioshook --ssh --network 192.168.1.100
```

### SSH Shell (USB - Default)
Connect via USB using iproxy (default if not specified)

```
./ioshook --shell
./ioshook --shell --local
```

### SSH Port Forward (Network)
Forward port from local to device (ssh -R)

```
./ioshook --ssh-port-forward 8080:8080 --network 192.168.1.100
```

### SSH Port Forward (USB)
Forward port from local to device (ssh -R)

```
./ioshook --ssh-port-forward 8080:8080 --local
./ioshook --ssh-port-forward 8080:8080
```

### Information
List all connected Frida devices
```
./ioshook --list-devices
```

List all installed applications on device
```
./ioshook --list-apps
```

List all available Frida scripts
```
./ioshook --list-scripts
```

Show system log of device (idevicesyslog)
```
./ioshook --logcat
```

### More Help
```
./ioshook -h
```

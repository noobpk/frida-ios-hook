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
```
./ioshook -n 'App Store' -m app-static
./ioshook -p com.apple.AppStore -m bypass-jb
./ioshook -p com.apple.AppStore -m bypass-ssl
./ioshook -n 'App Store' -m i-url-req
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
```
./ioshook -n 'App Store' --dump-memory --string
```

### HexByte Scan IPA
```
./ioshook --hexbyte-scan scan --file AppStore.ipa --pattern E103??AA????E0
./ioshook --hexbyte-scan json --file AppStore.ipa --task /hexbytescan-tasks/openssl_hook.json
```

### SSH Shell (Network)
```
./ioshook --shell --network 192.168.1.100:22
./ioshook --ssh --network 192.168.1.100
```

### SSH Shell (USB - Default)
```
./ioshook --shell
./ioshook --shell --local
```

### SSH Port Forward (Network)
```
./ioshook --ssh-port-forward 8080:8080 --network 192.168.1.100
```

### SSH Port Forward (USB)
```
./ioshook --ssh-port-forward 8080:8080 --local
./ioshook --ssh-port-forward 8080:8080
```

### Information
```
./ioshook --list-devices
./ioshook --list-apps
./ioshook --list-scripts
./ioshook --logcat
```

### More Help
```
./ioshook -h
```

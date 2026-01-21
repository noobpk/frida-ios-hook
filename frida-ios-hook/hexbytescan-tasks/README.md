# Hexbytescan-Task

|N|Task Name| Task Description|
|:---|:---|:---|
|1|openssl_hook.json|OpenSSL 1.0.2 certificate pinning hook on arm64|
|2|openssl_1_1_0_hook.json|OpenSSL 1.1.0 certificate pinning hook for arm64, it modifies cmp instruction in tls_process_server_certificate method|
|3|openssl_hook_v2.json|OpenSSL 1.0.2 certificate pinning hook on arm64, improved pattern, possibly for different compiler version or slightly updated OpenSSL, use if first version does not find patch location. These hooks patch call to ssl_verify_cert_chain in ssl3_get_server_certificate.|
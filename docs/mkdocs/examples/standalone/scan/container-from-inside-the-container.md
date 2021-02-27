```
$ docker run --rm -it alpine:3.10.2
/ # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
/ # trivy fs /
```

<details>
<summary>Result</summary>

```
adb3b9abab80 (alpine 3.10.2)
============================
Total: 5 (UNKNOWN: 0, LOW: 1, MEDIUM: 4, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1549    | MEDIUM   | 1.1.1c-r0         | 1.1.1d-r0     | openssl: information           |
|         |                  |          |                   |               | disclosure in fork()           |
+         +------------------+          +                   +---------------+--------------------------------+
|         | CVE-2019-1551    |          |                   | 1.1.1d-r2     | openssl: Integer overflow in   |
|         |                  |          |                   |               | RSAZ modular exponentiation on |
|         |                  |          |                   |               | x86_64                         |
+         +------------------+          +                   +---------------+--------------------------------+
|         | CVE-2019-1563    |          |                   | 1.1.1d-r0     | openssl: information           |
|         |                  |          |                   |               | disclosure in PKCS7_dataDecode |
|         |                  |          |                   |               | and CMS_decrypt_set1_pkey      |
+         +------------------+          +                   +---------------+--------------------------------+
|         | CVE-2020-1967    |          |                   | 1.1.1g-r0     | openssl: Segmentation fault in |
|         |                  |          |                   |               | SSL_check_chain causes denial  |
|         |                  |          |                   |               | of service                     |
+         +------------------+----------+                   +---------------+--------------------------------+
|         | CVE-2019-1547    | LOW      |                   | 1.1.1d-r0     | openssl: side-channel weak     |
|         |                  |          |                   |               | encryption vulnerability       |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

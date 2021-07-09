# Unpacked Filesystem

Scan aan unpacked container image filesystem.

In this case, Trivy works the same way when scanning containers

```bash
$ docker export $(docker create alpine:3.10.2) | tar -C /tmp/rootfs -xvf -
$ trivy fs /tmp/rootfs
```

<details>
<summary>Result</summary>

```bash
2021-03-08T05:22:26.378Z        INFO    Need to update DB
2021-03-08T05:22:26.380Z        INFO    Downloading DB...
20.37 MiB / 20.37 MiB [-------------------------------------------------------------------------------------------------------------------------------------] 100.00% 8.24 MiB p/s 2s
2021-03-08T05:22:30.134Z        INFO    Detecting Alpine vulnerabilities...

/tmp/rootfs (alpine 3.10.2)
===========================
Total: 20 (UNKNOWN: 0, LOW: 2, MEDIUM: 10, HIGH: 8, CRITICAL: 0)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| libcrypto1.1 | CVE-2020-1967    | HIGH     | 1.1.1c-r0         | 1.1.1g-r0     | openssl: Segmentation                 |
|              |                  |          |                   |               | fault in SSL_check_chain              |
|              |                  |          |                   |               | causes denial of service              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1967  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23839   |          |                   | 1.1.1j-r0     | openssl: incorrect SSLv2              |
|              |                  |          |                   |               | rollback protection                   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23839 |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2021-23840   |          |                   |               | openssl: integer                      |
|              |                  |          |                   |               | overflow in CipherUpdate              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23840 |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2021-23841   |          |                   |               | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in X509_issuer_and_serial_hash()      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23841 |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1547    | MEDIUM   |                   | 1.1.1d-r0     | openssl: side-channel weak            |
|              |                  |          |                   |               | encryption vulnerability              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1547  |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2019-1549    |          |                   |               | openssl: information                  |
|              |                  |          |                   |               | disclosure in fork()                  |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1549  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2019-1551    |          |                   | 1.1.1d-r2     | openssl: Integer overflow in RSAZ     |
|              |                  |          |                   |               | modular exponentiation on x86_64      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1551  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2020-1971    |          |                   | 1.1.1i-r0     | openssl: EDIPARTYNAME                 |
|              |                  |          |                   |               | NULL pointer de-reference             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1971  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1563    | LOW      |                   | 1.1.1d-r0     | openssl: information                  |
|              |                  |          |                   |               | disclosure in PKCS7_dataDecode        |
|              |                  |          |                   |               | and CMS_decrypt_set1_pkey             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1563  |
+--------------+------------------+----------+                   +---------------+---------------------------------------+
| libssl1.1    | CVE-2020-1967    | HIGH     |                   | 1.1.1g-r0     | openssl: Segmentation                 |
|              |                  |          |                   |               | fault in SSL_check_chain              |
|              |                  |          |                   |               | causes denial of service              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1967  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23839   |          |                   | 1.1.1j-r0     | openssl: incorrect SSLv2              |
|              |                  |          |                   |               | rollback protection                   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23839 |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2021-23840   |          |                   |               | openssl: integer                      |
|              |                  |          |                   |               | overflow in CipherUpdate              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23840 |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2021-23841   |          |                   |               | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in X509_issuer_and_serial_hash()      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23841 |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1547    | MEDIUM   |                   | 1.1.1d-r0     | openssl: side-channel weak            |
|              |                  |          |                   |               | encryption vulnerability              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1547  |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2019-1549    |          |                   |               | openssl: information                  |
|              |                  |          |                   |               | disclosure in fork()                  |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1549  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2019-1551    |          |                   | 1.1.1d-r2     | openssl: Integer overflow in RSAZ     |
|              |                  |          |                   |               | modular exponentiation on x86_64      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1551  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2020-1971    |          |                   | 1.1.1i-r0     | openssl: EDIPARTYNAME                 |
|              |                  |          |                   |               | NULL pointer de-reference             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1971  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1563    | LOW      |                   | 1.1.1d-r0     | openssl: information                  |
|              |                  |          |                   |               | disclosure in PKCS7_dataDecode        |
|              |                  |          |                   |               | and CMS_decrypt_set1_pkey             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1563  |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| musl         | CVE-2020-28928   | MEDIUM   | 1.1.22-r3         | 1.1.22-r4     | In musl libc through 1.2.1,           |
|              |                  |          |                   |               | wcsnrtombs mishandles particular      |
|              |                  |          |                   |               | combinations of destination buffer... |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-28928 |
+--------------+                  +          +                   +               +                                       +
| musl-utils   |                  |          |                   |               |                                       |
|              |                  |          |                   |               |                                       |
|              |                  |          |                   |               |                                       |
|              |                  |          |                   |               |                                       |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
```

</details>

# Filesystem

Scan a filesystem (such as a host machine, a virtual machine image, or an unpacked container image filesystem).

```bash
$ trivy fs /path/to/project
```

## Local Project
Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json.

```
$ trivy fs ~/src/github.com/aquasecurity/trivy-ci-test
```

<details>
<summary>Result</summary>

```
2020-06-01T17:06:58.652+0300    WARN    OS is not detected and vulnerabilities in OS packages are not detected.
2020-06-01T17:06:58.652+0300    INFO    Detecting pipenv vulnerabilities...
2020-06-01T17:06:58.691+0300    INFO    Detecting cargo vulnerabilities...

Pipfile.lock
============
Total: 10 (UNKNOWN: 2, LOW: 0, MEDIUM: 6, HIGH: 2, CRITICAL: 0)

+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
|       LIBRARY       | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |     FIXED VERSION      |               TITLE                |
+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
| django              | CVE-2020-7471    | HIGH     | 2.0.9             | 3.0.3, 2.2.10, 1.11.28 | django: potential                  |
|                     |                  |          |                   |                        | SQL injection via                  |
|                     |                  |          |                   |                        | StringAgg(delimiter)               |
+                     +------------------+----------+                   +------------------------+------------------------------------+
|                     | CVE-2019-19844   | MEDIUM   |                   | 3.0.1, 2.2.9, 1.11.27  | Django: crafted email address      |
|                     |                  |          |                   |                        | allows account takeover            |
+                     +------------------+          +                   +------------------------+------------------------------------+
|                     | CVE-2019-3498    |          |                   | 2.1.5, 2.0.10, 1.11.18 | python-django: Content             |
|                     |                  |          |                   |                        | spoofing via URL path in           |
|                     |                  |          |                   |                        | default 404 page                   |
+                     +------------------+          +                   +------------------------+------------------------------------+
|                     | CVE-2019-6975    |          |                   | 2.1.6, 2.0.11, 1.11.19 | python-django:                     |
|                     |                  |          |                   |                        | memory exhaustion in               |
|                     |                  |          |                   |                        | django.utils.numberformat.format() |
+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
...
```

</details>

## From Inside Containers
Scan your container from inside the container.

```bash
$ docker run --rm -it alpine:3.11
/ # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
/ # trivy fs /
```

<details>
<summary>Result</summary>

```
2021-03-08T05:22:26.378Z        INFO    Need to update DB
2021-03-08T05:22:26.380Z        INFO    Downloading DB...
20.37 MiB / 20.37 MiB [-------------------------------------------------------------------------------------------------------------------------------------] 100.00% 8.24 MiB p/s 2s
2021-03-08T05:22:30.134Z        INFO    Detecting Alpine vulnerabilities...
2021-03-08T05:22:30.138Z        INFO    Trivy skips scanning programming language libraries because no supported file was detected

313430f09696 (alpine 3.11.7)
============================
Total: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 6, CRITICAL: 0)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| libcrypto1.1 | CVE-2021-23839   | HIGH     | 1.1.1i-r0         | 1.1.1j-r0     | openssl: incorrect SSLv2              |
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
+--------------+------------------+          +                   +               +---------------------------------------+
| libssl1.1    | CVE-2021-23839   |          |                   |               | openssl: incorrect SSLv2              |
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
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
```

</details>

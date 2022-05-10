# Quick Start

## Scan image for vulnerabilities and secrets

Simply specify an image name (and a tag).

```
$ trivy image [YOUR_IMAGE_NAME]
```

For example:

``` shell
$ trivy image myimage:1.0.0
2022-04-21T18:56:44.099+0300    INFO    Detected OS: alpine
2022-04-21T18:56:44.099+0300    INFO    Detecting Alpine vulnerabilities...
2022-04-21T18:56:44.101+0300    INFO    Number of language-specific files: 0

myimage:1.0.0 (alpine 3.15.0)
=============================
Total: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| busybox      | CVE-2022-28391   | CRITICAL | 1.34.1-r3         | 1.34.1-r5     | CVE-2022-28391 affecting              |
|              |                  |          |                   |               | package busybox 1.35.0                |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2022-28391 |
+--------------+------------------|          |-------------------+---------------+---------------------------------------+
| ssl_client   | CVE-2022-28391   |          | 1.34.1-r3         | 1.34.1-r5     | CVE-2022-28391 affecting              |
|              |                  |          |                   |               | package busybox 1.35.0                |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2022-28391 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+

app/deploy.sh (secrets)
=======================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

+----------+-------------------+----------+---------+--------------------------------+
| CATEGORY |    DESCRIPTION    | SEVERITY | LINE NO |             MATCH              |
+----------+-------------------+----------+---------+--------------------------------+
|   AWS    | AWS Access Key ID | CRITICAL |   10    | export AWS_ACCESS_KEY_ID=***** |
+----------+-------------------+----------+---------+--------------------------------+
```

For more details, see [vulnerability][vulnerability] and [secret][secret] pages.

## Scan directory for misconfigurations

Simply specify a directory containing IaC files such as Terraform and Dockerfile.

```
$ trivy config [YOUR_IAC_DIR]
```

For example:

``` shell
$ ls build/
Dockerfile
$ trivy config ./build
2021-07-09T10:06:29.188+0300    INFO    Need to update the built-in policies
2021-07-09T10:06:29.188+0300    INFO    Downloading the built-in policies...
2021-07-09T10:06:30.520+0300    INFO    Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+
```

For more details, see [here][misconf].

[vulnerability]: ../docs/vulnerability/scanning/index.md
[misconf]: ../docs/misconfiguration/scanning.md
[secret]: ../docs/secret/scanning.md

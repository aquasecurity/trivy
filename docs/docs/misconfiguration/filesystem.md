# Filesystem

## Quick start

Trivy scans a filesystem such as a virtual machine to detect misconfigurations.

You have to specify `--security-checks config` to enable misconfiguration detection.

```bash
$ trivy fs --security-checks config /path/to/dir
```

Internally, it is the same as [config subcommand](iac.md).

## Vulnerability and Misconfiguration scanning
The difference between `fs` and `config` subcommand is that `fs` can detect both vulnerabilities and misconfiguration at the same time.

You have to specify `--security-checks vuln,config` to enable vulnerability and misconfiguration detection.

``` bash
$ ls myapp/
Dockerfile Pipfile.lock
$ trivy fs --security-checks vuln,config --severity HIGH,CRITICAL myapp/
2021-07-09T12:03:27.564+0300    INFO    Detected OS: unknown
2021-07-09T12:03:27.564+0300    INFO    Number of language-specific files: 1
2021-07-09T12:03:27.564+0300    INFO    Detecting pipenv vulnerabilities...
2021-07-09T12:03:27.566+0300    INFO    Detected config files: 1

Pipfile.lock (pipenv)
=====================
Total: 1 (HIGH: 1, CRITICAL: 0)

+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| LIBRARY  | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| httplib2 | CVE-2021-21240   | HIGH     | 0.12.1            | 0.19.0        | python-httplib2: Regular              |
|          |                  |          |                   |               | expression denial of                  |
|          |                  |          |                   |               | service via malicious header          |
|          |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-21240 |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+
```

In the above example, Trivy detected vulnerabilities of Python dependencies and misconfigurations in Dockerfile.
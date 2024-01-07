# Others

## Enable/Disable Scanners
You can enable/disable scanners with the `--scanners` flag.

Supported values:

- vuln
- misconfig
- secret
- license
 
For example, container image scanning enables vulnerability and secret scanners by default.
If you don't need secret scanning, it can be disabled.

``` shell
$ trivy image --scanners vuln alpine:3.15
```

## Exit Code
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

By default, `Trivy` exits with code 0 even when security issues are detected.
Use the `--exit-code` option if you want to exit with a non-zero exit code.

```
$ trivy image --exit-code 1 python:3.4-alpine3.9
```

<details>
<summary>Result</summary>

```
2019-05-16T12:51:43.500+0900    INFO    Updating vulnerability database...
2019-05-16T12:52:00.387+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

This option is useful for CI/CD. In the following example, the test will fail only when a critical vulnerability is found.

```
$ trivy image --exit-code 0 --severity MEDIUM,HIGH ruby:2.4.0
$ trivy image --exit-code 1 --severity CRITICAL ruby:2.4.0
```

## Exit on EOL
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |           |
|      Secret      |           |
|     License      |           |

Sometimes you may surprisingly get 0 vulnerabilities in an old image:

- Enabling `--ignore-unfixed` option while all packages have no fixed versions.
- Scanning a rather outdated OS (e.g. Ubuntu 10.04).

An OS at the end of service/life (EOL) usually gets into this situation, which is definitely full of vulnerabilities.
`--exit-on-eol` can fail scanning on EOL OS with a non-zero code.
This flag is available with the following targets.

- Container images (`trivy image`)
- Virtual machine images (`trivy vm`)
- SBOM (`trivy sbom`)
- Root filesystem (`trivy rootfs`)

```
$ trivy image --exit-on-eol 1 alpine:3.10
```

<details>
<summary>Result</summary>

```
2023-03-01T11:07:15.455+0200    INFO    Vulnerability scanning is enabled
...
2023-03-01T11:07:17.938+0200    WARN    This OS version is no longer supported by the distribution: alpine 3.10.9
2023-03-01T11:07:17.938+0200    WARN    The vulnerability detection may be insufficient because security updates are not provided

alpine:3.10 (alpine 3.10.9)
===========================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

┌───────────┬────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────────────────────────────┐
│  Library  │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                            Title                            │
├───────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│ apk-tools │ CVE-2021-36159 │ CRITICAL │ 2.10.6-r0         │ 2.10.7-r0     │ libfetch before 2021-07-26, as used in apk-tools, xbps, and │
│           │                │          │                   │               │ other products, mishandles...                               │
│           │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2021-36159                  │
└───────────┴────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────────────────────────────┘
2023-03-01T11:07:17.941+0200    ERROR   Detected EOL OS: alpine 3.10.9
```

</details>

This option is useful for CI/CD.
The following example will fail when a critical vulnerability is found or the OS is EOSL:

```
$ trivy image --exit-code 1 --exit-on-eol 1 --severity CRITICAL alpine:3.16.3
```

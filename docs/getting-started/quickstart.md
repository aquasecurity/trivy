# Quick Start

## Scan image for vulnerabilities and secrets

Simply specify an image name (and a tag).

```
$ trivy image [YOUR_IMAGE_NAME]
```

For example:

``` shell
$ trivy image myimage:1.0.0
2022-05-16T13:25:17.826+0100	INFO	Detected OS: alpine
2022-05-16T13:25:17.826+0100	INFO	Detecting Alpine vulnerabilities...
2022-05-16T13:25:17.826+0100	INFO	Number of language-specific files: 0

myimage:1.0.0 (alpine 3.15.3)

Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

┌────────────┬────────────────┬──────────┬───────────────────┬───────────────┬─────────────────────────────────────────────────────────┐
│  Library   │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                          Title                          │
├────────────┼────────────────┼──────────┼───────────────────┼───────────────┼─────────────────────────────────────────────────────────┤
│ busybox    │ CVE-2022-28391 │ CRITICAL │ 1.34.1-r4         │ 1.34.1-r5     │ busybox: remote attackers may execute arbitrary code if │
│            │                │          │                   │               │ netstat is used                                         │
│            │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-28391              │
├────────────┤                │          │                   │               │                                                         │
│ ssl_client │                │          │                   │               │                                                         │
│            │                │          │                   │               │                                                         │
│            │                │          │                   │               │                                                         │
└────────────┴────────────────┴──────────┴───────────────────┴───────────────┴─────────────────────────────────────────────────────────┘

app/deploy.sh (secrets)

Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

┌──────────┬───────────────────┬──────────┬─────────┬────────────────────────────────┐
│ Category │    Description    │ Severity │ Line No │             Match              │
├──────────┼───────────────────┼──────────┼─────────┼────────────────────────────────┤
│   AWS    │ AWS Access Key ID │ CRITICAL │    3    │ export AWS_ACCESS_KEY_ID=***** │
└──────────┴───────────────────┴──────────┴─────────┴────────────────────────────────┘
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
2022-05-16T13:29:29.952+0100	INFO	Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

MEDIUM: Specify a tag in the 'FROM' statement for image 'alpine'
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.

See https://avd.aquasec.com/misconfig/ds001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:1
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 [ FROM alpine:latest
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

For more details, see [here][misconf].

[vulnerability]: ../docs/vulnerability/scanning/index.md
[misconf]: ../docs/misconfiguration/scanning.md
[secret]: ../docs/secret/scanning.md

# Kubernetes
Trivy supports the scanners listed in the table below.

|      Scanner       | Supported |
|:------------------:|:---------:|
|  [Vulnerability]   |     ✓     |
| [Misconfiguration] |     ✓     |
|      [Secret]      |     ✓     |

In addition to raw YAML and JSON, it supports the following templates:

|    Template     | Supported |
| :-------------: | :-------: |
| [Helm](helm.md) |     ✓     |
|    Kustomize    |   ✓[^1]   |

!!! note
    Trivy does not support Kustomize overlays, so it scans files defined in the base.
    Or, you can scan the output of `kustomize build`.

## Vulnerability
Trivy supports searching for vulnerabilities in Kubernetes components (such as `kubelet`, `apiserver`, etc.).
Currently only discovery from KBOM files is supported.

This means you need to get a report of your cluster in [KBOM format][KBOM-format]. 
After that, scan this file:
```shell
$ trivy k8s --format cyclonedx cluster -o kbom.json
$ trivy sbom kbom.json
2023-09-28T22:52:25.707+0300    INFO    Vulnerability scanning is enabled
2023-09-28T22:52:25.707+0300    INFO    Detected SBOM format: cyclonedx-json
2023-09-28T22:52:25.717+0300    WARN    No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.
2023-09-28T22:52:25.717+0300    WARN    e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"
2023-09-28T22:52:25.717+0300    INFO    Detected OS: debian gnu/linux
2023-09-28T22:52:25.717+0300    WARN    unsupported os : debian gnu/linux
2023-09-28T22:52:25.717+0300    INFO    Number of language-specific files: 3
2023-09-28T22:52:25.717+0300    INFO    Detecting kubernetes vulnerabilities...
2023-09-28T22:52:25.718+0300    INFO    Detecting gobinary vulnerabilities...

Kubernetes (kubernetes)

Total: 2 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

┌────────────────┬────────────────┬──────────┬────────┬───────────────────┬─────────────────────────────────┬──────────────────────────────────────────────────┐
│    Library     │ Vulnerability  │ Severity │ Status │ Installed Version │          Fixed Version          │                      Title                       │
├────────────────┼────────────────┼──────────┼────────┼───────────────────┼─────────────────────────────────┼──────────────────────────────────────────────────┤
│ k8s.io/kubelet │ CVE-2021-25749 │ HIGH     │ fixed  │ 1.24.0            │ 1.22.14, 1.23.11, 1.24.5        │ runAsNonRoot logic bypass for Windows containers │
│                │                │          │        │                   │                                 │ https://avd.aquasec.com/nvd/cve-2021-25749       │
│                ├────────────────┼──────────┤        │                   ├─────────────────────────────────┼──────────────────────────────────────────────────┤
│                │ CVE-2023-2431  │ LOW      │        │                   │ 1.24.14, 1.25.9, 1.26.4, 1.27.1 │ Bypass of seccomp profile enforcement            │
│                │                │          │        │                   │                                 │ https://avd.aquasec.com/nvd/cve-2023-2431        │
└────────────────┴────────────────┴──────────┴────────┴───────────────────┴─────────────────────────────────┴──────────────────────────────────────────────────┘
```

## Misconfiguration
Trivy recursively searches directories and scans all found Kubernetes files.

## Secret
The secret scan is performed on plain text files, with no special treatment for Kubernetes.
This means that Base64 encoded secrets are not scanned, and only secrets written in plain text are detected.


[Vulnerability]: ../../scanner/vulnerability.md
[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md

[KBOM-format]: ../../target/kubernetes.md#kbom

[^1]: Kustomize is not natively supported.
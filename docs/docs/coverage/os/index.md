# OS

## Scanner
Trivy supports operating systems for 

- [SBOM][sbom]
- [Vulnerabilities][vuln]
- [Licenses][license]

## Supported OS

| OS                                    | Supported Versions                  | Package Managers |
|---------------------------------------|-------------------------------------|------------------|
| [Alpine Linux](alpine.md)             | 2.2 - 2.7, 3.0 - 3.21, edge         | apk              |
| [Wolfi Linux](wolfi.md)               | (n/a)                               | apk              |
| [Chainguard](chainguard.md)           | (n/a)                               | apk              |
| [Red Hat Enterprise Linux](rhel.md)   | 6, 7, 8                             | dnf/yum/rpm      |
| [CentOS](centos.md)[^1]               | 6, 7, 8                             | dnf/yum/rpm      |
| [AlmaLinux](alma.md)                  | 8, 9                                | dnf/yum/rpm      |
| [Rocky Linux](rocky.md)               | 8, 9                                | dnf/yum/rpm      |
| [Oracle Linux](oracle.md)             | 5, 6, 7, 8                          | dnf/yum/rpm      |
| [Azure Linux (CBL-Mariner)](azure.md) | 1.0, 2.0, 3.0                       | tdnf/dnf/yum/rpm |
| [Amazon Linux](amazon.md)             | 1, 2, 2023                          | dnf/yum/rpm      |
| [openSUSE Leap](suse.md)              | 42, 15                              | zypper/rpm       |
| [openSUSE Tumbleweed](suse.md)        | (n/a)                               | zypper/rpm       |
| [SUSE Linux Enterprise](suse.md)      | 11, 12, 15                          | zypper/rpm       |
| [SUSE Linux Enterprise Micro](suse.md)| 5, 6                                | zypper/rpm       |
| [Photon OS](photon.md)                | 1.0, 2.0, 3.0, 4.0                  | tndf/yum/rpm     |
| [Debian GNU/Linux](debian.md)         | 7, 8, 9, 10, 11, 12                 | apt/dpkg         |
| [Ubuntu](ubuntu.md)                   | All versions supported by Canonical | apt/dpkg         |
| [OSs with installed Conda](../others/conda.md)  | -                                   | conda            |

## Supported container images

| Container image                               | Supported Versions                  | Package Managers |
|-----------------------------------------------|-------------------------------------|------------------|
| [Google Distroless](google-distroless.md)[^2] | Any                                 | apt/dpkg         |
| [Bitnami](../others/bitnami.md)                         | Any                                 | -                |

Each page gives more details.

[^1]: CentOS Stream is not supported 
[^2]: https://github.com/GoogleContainerTools/distroless


[sbom]: ../../supply-chain/sbom.md
[vuln]: ../../scanner/vulnerability.md
[license]: ../../scanner/license.md

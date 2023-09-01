# Bitnami Images

!!! warning "EXPERIMENTAL"
    Scanning results may be inaccurate.

While it is not an OS, this page describes the details of the [container images provided by Bitnami](https://github.com/bitnami/containers).
Bitnami images are based on [Debian](debian.md).
Please see [the Debian page](debian.md) for OS packages.

Trivy supports the following scanners for Bitnami packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
| :----------------------------------: | :-------: |
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     -     |

## SBOM
Trivy analyzes the SBOM information contained within the container images provided by Bitnami.
The SBOM files are located at `/opt/bitnami/<component>/.spdx-<component>.spdx`.

## Vulnerability
Since Bitnami has its [own vulnerability database][vulndb], it uses these for vulnerability detection of applications and packages distributed by Bitnami.

!!! note
    Trivy does not support vulnerability detection of independently compiled binaries, so even if you scan container images like `nginx:1.15.2`, vulnerabilities in Nginx cannot be detected.
    This is because main applications like Nginx are [not installed by the package manager](https://github.com/nginxinc/docker-nginx/blob/321a13a966eeff945196ddd31a629dad2aa85eda/mainline/debian/Dockerfile).
    However, in the case of Bitnami images, since these SBOMs are stored within the image, scanning `bitnami/nginx:1.15.2` allows for the detection of vulnerabilities in Nginx.

### Fixed Version
Trivy refers to the [Bitnami database][vulndb]. Please note that these may differ from the upstream fixed versions.

### Severity
Similar to Fixed versions, it follows Bitnami's vulnerability database.

### Status
Trivy supports the following [vulnerability statuses] for Bitnami packages.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |           |
|    Will Not Fix     |           |
|    Fix Deferred     |           |
|     End of Life     |           |



## License
If licenses are included in the SBOM distributed by Bitnami, they will be used for scanning.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[vulndb]: https://github.com/bitnami/vulndb
[vulnerability statuses]: ../../configuration/filtering.md#by-status

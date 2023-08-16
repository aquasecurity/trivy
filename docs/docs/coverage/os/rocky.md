# Rocky Linux
Trivy supports the following scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

Please see [here](index.md#supported-os) for supported versions.

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
Rocky Linux offers its own security advisories, and these are utilized when scanning Rocky Linux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
Trivy takes fixed versions from [Rocky Linux Errata][errata], not NVD or somewhere else.
See [here](../../scanner/vulnerability.md#data-source-selection) for more details.

!!! architectures
    There are cases when the vulnerability affects packages of not all architectures.
    For example, vulnerable packages for [CVE-2023-0361](https://errata.rockylinux.org/RLSA-2023:1141) are only `aarch64` packages.
    
    Trivy only detects vulnerabilities for packages of your architecture.

### Severity
Trivy calculates the severity of an issue based on the severity provided in [Rocky Linux Errata][errata].

The table below is the mapping of Rocky Linux's severity to Trivy's severity levels.

| Rocky Linux |  Trivy   |
| :---------: | :------: |
|     Low     |   Low    |
|  Moderate   |  Medium  |
|  Important  |   High   |
|  Critical   | Critical |

### Status
Trivy supports the following [vulnerability statuses] for Rocky Linux.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |           |
|    Will Not Fix     |           |
|    Fix Deferred     |           |
|     End of Life     |           |


## License
Trivy identifies licenses by examining the metadata of RPM packages.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[updateinfo]: https://download.rockylinux.org/pub/rocky/
[errata]: https://errata.rockylinux.org/

[vulnerability statuses]: ../../configuration/filtering.md#by-status
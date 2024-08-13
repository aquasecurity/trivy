# Azure Linux (CBL-Mariner)

*CBL-Mariner was rebranded to Azure Linux for version 3.0 onwards.*

Trivy supports the following scanners for OS packages.

| Version          | SBOM  | Vulnerability | License |
| ---------------- | :---: | :-----------: | :-----: |
| 1.0              |   ✔   |       ✔       |    ✔    |
| 1.0 (Distroless) |   ✔   |       ✔       |         |
| 2.0              |   ✔   |       ✔       |    ✔    |
| 2.0 (Distroless) |   ✔   |       ✔       |         |
| 3.0              |   ✔   |       ✔       |    ✔    |
| 3.0 (Distroless) |   ✔   |       ✔       |         |


The following table provides an outline of the targets Trivy supports.

| Version | Container image | Virtual machine |     Arch     |
| ------- | :-------------: | :-------------: | :----------: |
| 1.0     |        ✔        |        ✔        | amd64, arm64 |
| 2.0     |        ✔        |        ✔        | amd64, arm64 |
| 3.0     |        ✔        |        ✔        | amd64, arm64 |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|    Detect unfixed vulnerabilities    |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `tdnf`, `dnf` and `yum`.

## Vulnerability
Azure Linux offers its own security advisories, and these are utilized when scanning Azure Linux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
Trivy takes fixed versions from [Azure Linux OVAL][oval].

### Severity
Trivy calculates the severity of an issue based on the severity provided in [Azure Linux OVAL][oval].

### Status
Trivy supports the following [vulnerability statuses] for Azure Linux.

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

!!! note
    License detection is not supported for Azure Linux Distroless images.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[oval]: https://github.com/microsoft/AzureLinuxVulnerabilityData/

[vulnerability statuses]: ../../configuration/filtering.md#by-status

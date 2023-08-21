# Oracle Linux
Trivy supports the following scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

Please see [here](index.md#supported-os) for supported versions.

The table below outlines the features offered by Trivy.

|                Feature                | Supported |
| :-----------------------------------: | :-------: |
|        Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
Oracle Linux offers its own security advisories, and these are utilized when scanning Oracle Linux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
Trivy takes fixed versions from [Oracle security advisories][alerts].

### Severity
Trivy determines vulnerability severity based on the severity metric provided in [Oracle security advisories][alerts].
For example, the security patch for [CVE-2023-0464][CVE-2023-0464] is provided as [ELSA-2023-2645][ELSA-2023-2645].
Its severity is rated as "MODERATE".
Thus, even though it's evaluated as "HIGH" in the NVD, Trivy displays it with a severity of "MEDIUM".

The table below is the mapping of Oracle's threat to Trivy's severity levels.

|  Oracle   |  Trivy   |
| :-------: | :------: |
|    Low    |   Low    |
| Moderate  |  Medium  |
| Important |   High   |
| Critical  | Critical |

### Status
Trivy supports the following [vulnerability statuses] for Oracle Linux.

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

[oval]: https://linux.oracle.com/security/oval/
[alerts]: https://www.oracle.com/security-alerts/

[CVE-2023-0464]: https://linux.oracle.com/cve/CVE-2023-0464.html
[ELSA-2023-2645]: https://linux.oracle.com/errata/ELSA-2023-2645.html
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-0464

[vulnerability statuses]: ../../configuration/filtering.md#by-status
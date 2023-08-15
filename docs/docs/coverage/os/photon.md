# Photon OS
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
Trivy detects packages that have been installed through package managers such as `tdnf` and `yum`.

## Vulnerability
Photon OS offers its own security advisories, and these are utilized when scanning Photon OS for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
Trivy takes fixed versions from [Photon CVE metadata][metadata].

### Severity
Trivy determines the severity of vulnerabilities based on the CVSSv3 score provided by Photon OS.
See [here](../../scanner/vulnerability.md#severity-selection) for the conversion table from CVSS score to severity.

### Status
Trivy supports the following [vulnerability statuses] for Photon OS.

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

[metadata]: https://packages.vmware.com/photon/photon_cve_metadata/

[vulnerability statuses]: ../../configuration/filtering.md#by-status
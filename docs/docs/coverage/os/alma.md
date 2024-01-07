# AlmaLinux
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
AlmaLinux offers its own security advisories, and these are utilized when scanning AlmaLinux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by AlmaLinux.
For example, for CVE-2023-0464, the fixed version for AlmaLinux 9 is listed as `3.0.7-16.el9_2` in [their advisory][ALSA-2023:3722].
Note that this is different from the upstream fixed version, which is `3.0.9`, `3.1.1`, and son on.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
Trivy calculates the severity of an issue based on the severity provided by AlmaLinux.
If the severity is not provided or defined yet by AlmaLinux, the severity from the NVD is taken into account.

Using CVE-2023-0464 as an example, while it is rated as "High" in NVD, AlmaLinux has marked as ["moderate"][ALSA-2023:3722].
As a result, Trivy will display it as "Medium".

The table below is the mapping of AlmaLinux's severity to Trivy's severity levels.

| AlmaLinux |  Trivy   |
| :-------: | :------: |
|    Low    |   Low    |
| Moderate  |  Medium  |
| Important |   High   |
| Critical  | Critical |

### Status
Trivy supports the following [vulnerability statuses] for AlmaLinux.

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

[errata]: https://errata.almalinux.org/

[ALSA-2023:3722]: https://errata.almalinux.org/9/ALSA-2023-3722.html
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-0464

[vulnerability statuses]: ../../configuration/filtering.md#by-status
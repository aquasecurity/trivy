# Alibaba Cloud Linux
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
|        End of life awareness         |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
Alibaba Cloud Linux offers its own security advisories, and these are utilized when scanning Alibaba Cloud Linux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Alibaba Cloud.
For example, for CVE-2020-25694, the fixed version for Alibaba Cloud Linux 3 is listed as `12.5-1.1.al8` in [ALINUX3-SA-2021:0002].
Note that this is different from the upstream fixed version.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
Trivy calculates the severity of an issue based on the severity provided by Alibaba Cloud Linux.
If the severity is not provided or defined yet by Alibaba Cloud Linux, the severity from the NVD is taken into account.

Using CVE-2020-10543 as an example, while it is rated as "High" in NVD, Alibaba Cloud Linux has marked it as ["Moderate"][ALINUX3-SA-2021:0012].
As a result, Trivy will display it as "Medium".

The table below is the mapping of Alibaba Cloud Linux's severity to Trivy's severity levels.

| Alibaba Cloud Linux |  Trivy   |
| :-----------------: | :------: |
|         Low         |   Low    |
|      Moderate       |  Medium  |
|      Important      |   High   |
|      Critical       | Critical |

### Status
Trivy supports the following [vulnerability statuses] for Alibaba Cloud Linux.

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

[ALINUX3-SA-2021:0002]: https://alas.aliyuncs.com/alinux3/ALINUX3-SA-2021-0002
[ALINUX3-SA-2021:0012]: https://alas.aliyuncs.com/alinux3/ALINUX3-SA-2021-0012
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2020-25694

[vulnerability statuses]: ../../configuration/filtering.md#by-status

# Amazon Linux
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
Amazon Linux offers its own security advisories, and these are utilized when scanning Amazon Linux for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Amazon.
For example, for CVE-2023-0464, the fixed version for Amazon Linux 2023 is listed as `3.0.8-1.amzn2023.0.2` in [ALAS2023-2023-181].
Note that this is different from the upstream fixed version, which is `3.0.9`, `3.1.1`, and so on.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
Trivy determines vulnerability severity based on the severity metric provided by Amazon.
For example, the security patch for [CVE-2023-0464] in Amazon Linux 2023 is provided as [ALAS2023-2023-181].
Its severity is rated as "Medium".
Thus, even though it's evaluated as "HIGH" in the NVD, Trivy displays it with a severity of "MEDIUM".

The table below is the mapping of Amazon's severity to Trivy's severity levels.

|  Amazon   |  Trivy   |
| :-------: | :------: |
|    Low    |   Low    |
|  Medium   |  Medium  |
| Important |   High   |
| Critical  | Critical |

### Status
Trivy supports the following [vulnerability statuses] for Amazon Linux.

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
[center]: https://alas.aws.amazon.com/

[CVE-2023-0464]: https://alas.aws.amazon.com/cve/html/CVE-2023-0464.html
[ALAS2023-2023-181]: https://alas.aws.amazon.com/AL2023/ALAS-2023-181.html
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-0464

[vulnerability statuses]: ../../configuration/filtering.md#by-status
# Ubuntu
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

Please see [here](index.md#supported-os) for supported versions.

The following table provides an outline of the features Trivy offers.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|    Detect unfixed vulnerabilities    |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Same as [Debian](debian.md#sbom).

## Vulnerability
Ubuntu offers its own security advisories, and these are utilized when scanning Ubuntu for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Ubuntu.
As an illustration, for CVE-2023-3269, the fixed version for Ubuntu 23.04 (lunar) is listed as `6.2.0-26.26` in [the Security Tracker][CVE-2023-3269].
It's essential to recognize that this differs from the upstream fixed version, which stands at `6.5`.
Typically, only the upstream information gets listed on [NVD][CVE-2023-3269 NVD], so it's important not to get confused.

### Severity
Trivy calculates the severity of an issue based on the 'Priority' metric found in the Security Tracker.
If 'Priority' isn't provided by Ubuntu, the severity from the NVD is taken into account.

Using CVE-2019-15052 as an example, while it is rated as ["Critical" in NVD][CVE-2019-15052 NVD], Ubuntu has marked its "Priority" as ["Medium"][CVE-2019-15052].
As a result, Trivy will display it as "Medium".

### Status
Trivy supports the following [vulnerability statuses] for Ubuntu.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |           |
|    Will Not Fix     |           |
|    Fix Deferred     |           |
|     End of Life     |           |

## License
Same as [Debian](debian.md#license).


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[Ubuntu CVE Tracker]: https://ubuntu.com/security/cve

[CVE-2023-3269]: https://ubuntu.com/security/CVE-2023-3269
[CVE-2019-15052]: https://ubuntu.com/security/CVE-2019-15052
[CVE-2023-3269 NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-3269
[CVE-2019-15052 NVD]: https://nvd.nist.gov/vuln/detail/CVE-2019-15052

[vulnerability statuses]: ../../configuration/filtering.md#by-status
# Red Hat Enterprise Linux
Trivy supports the following scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

Please see [here](index.md#supported-os) for supported versions.

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
| :----------------------------------: | :-------: |
|       Unfixed vulnerabilities        |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
Red Hat offers its own security advisories, and these are utilized when scanning Red Hat Enterprise Linux (RHEL) for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Red Hat.
For example, for CVE-2023-0464, the fixed version for RHEL 9 is listed as `3.0.7-16.el9_2` in [their advisory][CVE-2023-0464].
This patch is provided in [RHSA-2023:3722].
Note that this is different from the upstream fixed version, which is `3.0.9`, `3.1.1`, and so on.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
Trivy calculates the severity of a vulnerability based on the 'Impact' metric provided by Red Hat.
If the impact is not provided or defined yet by Red Hat, the severity from the NVD is taken into account.

Using CVE-2023-0464 as an example, while it is rated as "HIGH" in NVD, Red Hat has marked its 'Impact' as ["Low"][CVE-2023-0464].
As a result, Trivy will display it as "Low".

The table below is the mapping of Red Hat's impact to Trivy's severity levels.

|  Red Hat  |  Trivy   |
| :-------: | :------: |
|    Low    |   Low    |
| Moderate  |  Medium  |
| Important |   High   |
| Critical  | Critical |

### Status
Trivy supports the following [vulnerability statuses] for RHEL.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |     ✓     |
|    Will Not Fix     |     ✓     |
|    Fix Deferred     |     ✓     |
|     End of Life     |     ✓     |

When a vulnerability status is listed as "End of Life", it means a vulnerability with the impact level assigned to this CVE is no longer covered by its current support lifecycle phase.
The product has been identified to contain the impacted component, but analysis to determine whether it is affected or not by this vulnerability was not performed.
Red Hat advises that the product should be assumed to be affected.
Therefore, Trivy detects vulnerabilities with this status as "End of Life".

On the other hand, for those marked "Under Investigation," the impact is unclear as they are still being examined, so Trivy does not detect them. Once the investigation is completed, the status should be updated.

!!! abstract
    Vulnerabilities with a status of "End of Life", where the presence or absence of impact is unclear, are detected by Trivy. However, those with a status of "Under Investigation" are not detected.

## License
Trivy identifies licenses by examining the metadata of RPM packages.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[oval]: https://www.redhat.com/security/data/oval/v2/
[api]: https://www.redhat.com/security/data/metrics/

[CVE-2023-0464]: https://access.redhat.com/security/cve/cve-2023-0464
[RHSA-2023:3722]: https://access.redhat.com/errata/RHSA-2023:3722
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-0464

[vulnerability statuses]: ../../configuration/filtering.md#by-status

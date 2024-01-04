# Alpine Linux
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
Trivy detects packages that have been installed through `apk`.

## Vulnerability
Alpine Linux offers its own security advisories, and these are utilized when scanning Alpine for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Alpine.
For example, for CVE-2023-0464, the fixed version for Alpine Linux is listed as `3.1.0-r1` in [the secfixes][CVE-2023-0464].
Note that this is different from the upstream fixed version, which is `3.1.1`.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
For Alpine vulnerabilities, the severity is determined using the values set by NVD.

### Status
Trivy supports the following [vulnerability statuses] for Alpine.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |           |
|    Will Not Fix     |           |
|    Fix Deferred     |           |
|     End of Life     |           |

## License
Trivy identifies licenses by examining the metadata of APK packages.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[secdb]: https://secdb.alpinelinux.org/

[CVE-2023-0464]: https://gitlab.alpinelinux.org/alpine/aports/-/blob/dad5b7380ab3be705951ce6fd2d7bba513d6a744/main/openssl/APKBUILD#L36-37
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-0464

[vulnerability statuses]: ../../configuration/filtering.md#by-status
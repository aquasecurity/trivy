# Debian
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
|        Unfixed vulnerabilities        |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `apt` and `dpkg`.
While there are some exceptions, like Go binaries and JAR files, it's important to note that binaries that have been custom-built using `make` or tools installed via `curl` are generally not detected.

## Vulnerability
Debian offers its own security advisories, and these are utilized when scanning Debian for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
When looking at fixed versions, it's crucial to consider the patches supplied by Debian.
For example, for CVE-2023-3269, the fixed version for Debian 12 (bookworm) is listed as `6.1.37-1` in [the Security Tracker][CVE-2023-3269].
This patch is provided in [DSA-5448-1].
Note that this is different from the upstream fixed version, which is `6.5`.
Typically, only the upstream information gets listed on [NVD], so it's important not to get confused.

### Severity
Trivy calculates the severity of an issue based on the 'Urgency' metric found in the Security Tracker.
If 'Urgency' isn't provided by Debian, the severity from the NVD is taken into account.

Using CVE-2019-15052 as an example, while it is rated as "Critical" in NVD, Debian has marked its "Urgency" as ["Low"][CVE-2019-15052].
As a result, Trivy will display it as "Low".

### Status
Trivy supports the following [vulnerability statuses] for Debian.

|       Status        | Supported |
| :-----------------: | :-------: |
|        Fixed        |     ✓     |
|      Affected       |     ✓     |
| Under Investigation |           |
|    Will Not Fix     |           |
|    Fix Deferred     |     ✓     |
|     End of Life     |     ✓     |

## License
To identify the license of a package, Trivy checks the copyright file located at `/usr/share/doc/*/copyright`.

However, this method has its limitations as the file isn't machine-readable, leading to situations where the license isn't detected.
In such scenarios, the `--license-full` flag can be passed.
It compares the contents of known licenses with the copyright file to discern the license in question.
Please be aware that using this flag can increase memory usage, so it's disabled by default for efficiency.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[debian-tracker]: https://security-tracker.debian.org/tracker/
[debian-oval]: https://www.debian.org/security/oval/

[CVE-2023-3269]: https://security-tracker.debian.org/tracker/CVE-2023-3269
[CVE-2019-15052]: https://security-tracker.debian.org/tracker/CVE-2019-15052
[DSA-5448-1]: https://security-tracker.debian.org/tracker/DSA-5448-1
[NVD]: https://nvd.nist.gov/vuln/detail/CVE-2023-3269

[vulnerability statuses]: ../../configuration/filtering.md#by-status
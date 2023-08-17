# SUSE
Trivy supports the following distributions:

- openSUSE Leap
- SUSE Enterprise Linux (SLE)

Please see [here](index.md#supported-os) for supported versions.

Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
SUSE offers its [own security advisories][cvrf], and these are utilized when scanning openSUSE/SLE for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Trivy identifies licenses by examining the metadata of RPM packages.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[cvrf]: http://ftp.suse.com/pub/projects/security/cvrf/

[vulnerability statuses]: ../../configuration/filtering.md#by-status
# Mageia

Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     -     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `urpmi`.

## Vulnerability
Mageia offers its [own security advisories][mgasa], and these are utilized when scanning Mageia for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Trivy identifies licenses by examining the metadata of RPM packages.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[mgasa]: https://advisories.mageia.org/

[vulnerability statuses]: ../../configuration/filtering.md#by-status

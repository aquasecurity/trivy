# ALT
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
Trivy detects packages that have been installed through package managers such as `apt-rpm`.

## Vulnerability
ALT offers its own security advisories, and these are utilized when scanning ALT for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Fixed Version
Trivy takes fixed versions from [errata.altlinux.org][errata] and from [bdu.fstec.ru][fstec].

## License
Trivy identifies licenses by examining the metadata of RPM packages.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[vulnerability statuses]: ../../configuration/filtering.md#by-status
[errata]: https://errata.altlinux.org/
[fstec]: https://bdu.fstec.ru/vul/

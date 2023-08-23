# Google Distroless
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
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages pre-installed in distroless images.

## Vulnerability
Google Distroless is based on [Debian]; see there for details.

## License
Google Distroless is based on [Debian]; see there for details.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[metadata]: https://packages.vmware.com/photon/photon_cve_metadata/

[vulnerability statuses]: ../../configuration/filtering.md#by-status

[Debian]: debian.md
# CoreOS
This page describes the deprecated `CoreOS Container Linux` (EOL) and its successor, [Fedora CoreOS][fedora-coreos].

Trivy supports the following scanners for OS packages on these systems.

|    Scanner    | Supported |
|:-------------:|:---------:|
|     SBOM      |     ✓     |
| Vulnerability |     -     |
|    License    |     -     |

Please see [here](index.md#supported-os) for supported versions.

## SBOM
Trivy detects packages that are listed in the RPM database.

[fedora-coreos]: https://fedoraproject.org/coreos/
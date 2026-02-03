# ActiveState Images

While it is not an OS with a package manager, this page describes the details of ActiveState container images.
ActiveState images don't contain OS packages.

Trivy supports the following scanners for ActiveState images.

|    Scanner    | Supported |
|:-------------:|:---------:|
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

## SBOM
Trivy collects packages from two sources:

- Pre-built SBOM file at `/opt/activestate/<name>.spdx.json` (if present)
- Language-specific packages (e.g., npm, pip, go.mod)

!!! note
    This may result in [duplicates](#duplicates) if both sources contain the same packages.

## Vulnerability
Trivy detects vulnerabilities in language-specific packages found in the image.

ActiveState images don't contain OS packages, so vulnerability detection for OS packages is not performed.

## License
Trivy detects licenses from language-specific packages found in the image.

## Duplicates
Scan results may contain duplicates when the same packages are detected both from the SBOM file
and by Trivy's analyzers. This is expected behavior.

To avoid duplicates, you can either:

- [Skip the SBOM file][skipping] from scanning
- [Filter the results][filtering] to remove duplicates

[skipping]: ../../configuration/skipping.md
[filtering]: ../../configuration/filtering.md

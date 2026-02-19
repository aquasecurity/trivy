# Bottlerocket
Trivy supports the following scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     -     |

Please see [here](index.md#supported-os) for supported versions.

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|        End of life awareness         |     -     |

## SBOM
Trivy detects packages that are listed in the [software inventory].

## Vulnerability
Trivy checks for vulnerabilities using the [Bottlerocket security advisories][advisories],
comparing installed package versions from the software inventory against known fixed versions.

Data source: [Bottlerocket Security Advisories][advisories]

[software inventory]: https://bottlerocket.dev/en/os/1.37.x/concepts/variants/#software-inventory
[advisories]: https://advisories.bottlerocket.aws/

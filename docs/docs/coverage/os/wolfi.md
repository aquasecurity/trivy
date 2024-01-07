# Wolfi Linux
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|    Detect unfixed vulnerabilities    |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Same as [Alpine Linux](alpine.md#sbom).

## Vulnerability
Wolfi Linux offers its own security advisories, and these are utilized when scanning Wolfi for vulnerabilities.
Everything else is the same as [Alpine Linux](alpine.md#vulnerability).

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Alpine Linux](alpine.md#license).

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[secdb]: https://packages.wolfi.dev/os/security.json
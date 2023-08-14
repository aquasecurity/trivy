# Wolfi Linux
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|                Feature                | Supported |
| :-----------------------------------: | :-------: |
|    Detect unfixed vulnerabilities     |     -     |
| [Dependency graph][dependench-graph]) |     ✓     |

## SBOM
Same as [Alpine Linux](alpine.md).

## Vulnerability
Wolfi Linux offers its own security advisories, and these are utilized when scanning Wolfi for vulnerabilities.
Everything else is the same as [Alpine Linux](alpine.md).

### Data Source
See [here](../../scanner/vulnerability/os#data-sources).

## License
Same as [Alpine Linux](alpine.md).

[dependench-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[secdb]: https://packages.wolfi.dev/os/security.json
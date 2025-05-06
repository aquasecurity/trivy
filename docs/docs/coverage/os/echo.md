# Echo OS
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|    Detect unfixed vulnerabilities    |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Same as [Debian](debian.md#sbom).

## Vulnerability
Echo OS offers its own security advisories, and these are utilized when scanning Echo OS for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Debian](debian.md#license).

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[secdb]: https://advisory.echohq.com/data.json
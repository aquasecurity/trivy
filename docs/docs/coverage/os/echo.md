# Echo
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|    Unfixed vulnerabilities           |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |
|        End of life awareness         |     -     |

## SBOM
Same as [Debian](debian.md#sbom).

## Vulnerability
Echo offers its own security advisories, and these are utilized when scanning Echo for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Debian](debian.md#license).

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[advisory]: https://advisory.echohq.com/data.json
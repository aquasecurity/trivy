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

## Language Packages
Echo also provides patched versions of Python packages.
Trivy identifies them by an Echo local version segment `+echo.N` at the end of the version (for example, `requests` `2.14.2+echo.1`).

For these packages, Trivy uses Echo's own security advisories from the [Echo OSV feed][osv-feed] instead of the upstream ones.
Other packages in the same project are scanned as usual.

Only pip packages are supported.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[advisory]: https://advisory.echohq.com/data.json
[osv-feed]: https://advisory.echohq.com/osv/all.zip
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
|    Detect unfixed vulnerabilities    |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |
|        End of life awareness         |     -     |

## SBOM
Same as [Alpine Linux](alpine.md#sbom).

## Vulnerability
Wolfi Linux offers its own security advisories, and these are utilized when scanning Wolfi for vulnerabilities.
Everything else is the same as [Alpine Linux](alpine.md#vulnerability).

Wolfi advisories are published by Chainguard in the same [OSV v3 feed][osv-v3] as the Chainguard ones, under the Wolfi ecosystem and with the same version ranges.
Matching, aggregation and unfixed vulnerabilities work exactly as described for [Chainguard](chainguard.md#vulnerability).

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Alpine Linux](alpine.md#license).

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[osv-v3]: https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md

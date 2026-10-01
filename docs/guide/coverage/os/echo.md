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
Echo provides patched versions of language packages.
Trivy identifies them by the version suffix and uses Echo's own security advisories from the [Echo OSV feed][osv-feed] for them instead of the upstream ones.

| Ecosystem                       | Version Suffix | Example                    |
|---------------------------------|----------------|----------------------------|
| [Python](../language/python.md) | `+echo.N`      | `requests` `2.14.2+echo.1` |

Other packages, including those from other ecosystems, are scanned against the upstream advisories as usual.

!!! note
    These packages are detected regardless of the OS, including filesystem and repository scans.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[advisory]: https://advisory.echohq.com/data.json
[osv-feed]: https://advisory.echohq.com/osv/all.zip
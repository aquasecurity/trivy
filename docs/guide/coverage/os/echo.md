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
Trivy identifies them by the version suffix and checks both upstream advisories and Echo's own advisories from the [Echo OSV feed][osv-feed].
Upstream advisories are evaluated against the base version before `+echo.N`, while Echo advisories are evaluated against the full Echo version.
When Echo has an advisory with the same primary vulnerability ID, the Echo advisory replaces the upstream one so that Echo fixes are taken into account.
Unrelated upstream advisories remain in the scan, and an upstream advisory is used when there is no active Echo advisory for that vulnerability.

If a version-specific `not_applicable` decision is published only as a withdrawn Echo OSV record, Trivy has no active Echo advisory to apply and reports a matching upstream advisory.
Known non-applicable findings can be filtered with [VEX](../../supply-chain/vex/index.md).

| Ecosystem                        | Version Suffix | Example                                                   |
|----------------------------------|----------------|-----------------------------------------------------------|
| [Python](../language/python.md)  | `+echo.N`      | `requests` `2.14.2+echo.1`                                |
| [Java](../language/java.md)      | `+echo.N`      | `org.springframework:spring-core` `6.1.21+echo.1`          |
| [Node.js](../language/nodejs.md) | `+echo.N`      | `nanoid` `3.3.6+echo.2`                                   |
| [.NET](../language/dotnet.md)    | `+echo.N`      | `System.Security.Cryptography.Xml` `8.0.0+echo.1`         |
| [Go](../language/golang.md)      | `+echo.N`      | `golang.org/x/net` `v0.22.0+echo.1`                       |

Packages without the Echo version suffix, and packages from unsupported ecosystems, are scanned against the upstream advisories as usual.

!!! note
    These packages are detected regardless of the OS, including filesystem and repository scans.

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[advisory]: https://advisory.echohq.com/data.json
[osv-feed]: https://advisory.echohq.com/osv/all.zip
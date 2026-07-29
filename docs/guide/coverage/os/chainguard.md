# Chainguard
Trivy supports the following scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|                Feature                | Supported |
| :-----------------------------------: | :-------: |
|    Detect unfixed vulnerabilities     |     ✓     |
| [Dependency graph][dependency-graph] |     ✓     |
|        End of life awareness         |     -     |

## SBOM
Same as [Alpine Linux](alpine.md#sbom).

## Vulnerability
Chainguard offers its own security advisories, and these are utilized when scanning Chainguard for vulnerabilities.
Everything else is the same as [Alpine Linux](alpine.md#vulnerability).

Advisories come from the [Chainguard OSV v3 feed][osv-v3], which replaced the deprecated secdb feed.
The feed publishes one record per vulnerable component found inside a package, so Trivy combines every record covering the same package, architecture and CVE:

- If any record is still unresolved, the package is reported as vulnerable with no fixed version.
- Otherwise the highest fixed version any record names is reported, because that is the first version in which every component is fixed.
- A vulnerability Chainguard has determined does not apply to the package is not reported.

Advisories are matched per architecture. A vulnerability that only affects the `x86_64` build of a package is not reported for the `aarch64` build.

### Unfixed vulnerabilities
Unlike secdb, the OSV v3 feed also publishes advisories Chainguard has not resolved yet.
Trivy reports them with no fixed version, and records the reason as the vulnerability status:

| Chainguard status            | Trivy status          |
|------------------------------|-----------------------|
| `true_positive_determination` | `affected`            |
| `pending_upstream_fix`        | `fix_deferred`        |
| `fix_not_planned`             | `will_not_fix`        |
| `analysis_not_planned`        | `will_not_fix`        |
| `detection`                   | `under_investigation` |

Use `--ignore-unfixed` to leave all of them out, or `--ignore-status` to leave out particular statuses.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Alpine Linux](alpine.md#license).


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[osv-v3]: https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md

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

A package is matched on its own name. The feed files an advisory against whichever APK package ships the vulnerable component, so a subpackage such as `libcrypto3` carries its own advisories rather than inheriting every advisory filed against its origin package `openssl`.

### Architectures
The feed records each advisory against a CPU architecture, and Trivy prefers the advisory matching the architecture of the installed package, because the two builds of a package are not always fixed in the same revision.

Where the feed has no advisory for a package's architecture at all, the advisory recorded for the other architecture is used rather than being discarded. Around one package/vulnerability pair in eleven appears for a single architecture only, and Chainguard builds every architecture of a package from the same source, so an advisory recorded for one is evidence about the other.

### Unfixed vulnerabilities
Unlike secdb, the OSV v3 feed also publishes advisories Chainguard has not resolved yet.
Trivy reports them with no fixed version, and records the reason as the vulnerability status:

| Chainguard status             | Trivy status          |
|-------------------------------|-----------------------|
| `true_positive_determination`  | `affected`            |
| `pending_upstream_fix`         | `fix_deferred`        |
| `fix_not_planned`              | `will_not_fix`        |
| `analysis_not_planned`         | `will_not_fix`        |
| `detection`                    | `under_investigation` |
| anything else unresolved       | `affected`            |

A `false_positive_determination` is resolved rather than unresolved, and is not reported at all.

Use `--ignore-unfixed` to leave all unresolved advisories out, or `--ignore-status` to leave out particular statuses.

Note that Chainguard records these against the component inside the package, and Trivy's language scanners may report the same vulnerability against that component directly. The two findings then appear under different package names.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Same as [Alpine Linux](alpine.md#license).


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[osv-v3]: https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md

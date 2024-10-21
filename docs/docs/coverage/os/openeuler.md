# openEuler
Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

Please see [here](index.md#supported-os) for supported versions.

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
openEuler offers its [own security advisories][cvrf], and these are utilized when scanning openEuler for vulnerabilities.

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

### Severity
Trivy calculates the severity of a vulnerability based on the severity provided in [openEuler Security Data][cvrf].

The table below is the mapping of openEuler's severity to Trivy's severity levels.

| openEuler |  Trivy   |
| :---------: | :------: |
|     Low     |   Low    |
|  Medium     |  Medium  |
|  High       |   High   |
|  Critical   | Critical |

## License
Trivy identifies licenses by examining the metadata of RPM packages.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[cvrf]: https://repo.openeuler.org/security/data/cvrf/

[vulnerability statuses]: ../../configuration/filtering.md#by-status

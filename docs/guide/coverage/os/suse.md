# SUSE
Trivy supports the following distributions:

- openSUSE Leap
- openSUSE Leap Micro
- openSUSE Tumbleweed
- openSUSE MicroOS
- SUSE Linux Enterprise (SLE)
- SUSE Linux Enterprise Micro

Please see [here](index.md#supported-os) for supported versions.

Trivy supports these scanners for OS packages.

|    Scanner    | Supported |
| :-----------: | :-------: |
|     SBOM      |     ✓     |
| Vulnerability |     ✓     |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

|               Feature                | Supported |
|:------------------------------------:|:---------:|
|       Unfixed vulnerabilities        |     -     |
| [Dependency graph][dependency-graph] |     ✓     |
|        End of life awareness         |     ✓     |

## SBOM
Trivy detects packages that have been installed through package managers such as `dnf` and `yum`.

## Vulnerability
SUSE offers its [own security advisories][cvrf], and these are utilized when scanning openSUSE/SLE for vulnerabilities.

openSUSE MicroOS and openSUSE Leap Micro are detected for SBOM/package purposes, but vulnerability matching isn't available out of the box: MicroOS is a rolling release versioned by build timestamp rather than a release number, and no advisory source currently covers either OS by that versioning scheme. Use `--distro <family>/<version>` to force matching against a supported family/version (e.g. `opensuse-leap/15.6`).

### Data Source
See [here](../../scanner/vulnerability.md#data-sources).

## License
Trivy identifies licenses by examining the metadata of RPM packages.


[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[cvrf]: https://ftp.suse.com/pub/projects/security/cvrf/

[vulnerability statuses]: ../../configuration/filtering.md#by-status

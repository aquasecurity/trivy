# RPM Archives

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports the following scanners for RPM archives.

|    Scanner    | Supported |
|:-------------:|:---------:|
|     SBOM      |     ✓     |
| Vulnerability |   ✓[^1]   |
|    License    |     ✓     |

The table below outlines the features offered by Trivy.

## SBOM
Trivy analyzes RPM archives matching `*.rpm`.
This feature is currently disabled by default but can be enabled with an environment variable, `TRIVY_EXPERIMENTAL_RPM_ARCHIVE`.

```shell
TRIVY_EXPERIMENTAL_RPM_ARCHIVE=true trivy fs ./rpms --format cyclonedx --output rpms.cdx.json
```

!!! note
    Currently, it works with `--format cyclonedx`, `--format spdx` or `--format spdx-json`.


## Vulnerability
Since RPM files don't have OS information, you need to generate SBOM, fill in the OS information manually and then scan the SBOM for vulnerabilities.

For example:

```shell
$ TRIVY_EXPERIMENTAL_RPM_ARCHIVE=true trivy fs ./rpms -f cyclonedx -o rpms.cdx.json
$ jq '(.components[] | select(.type == "operating-system")) |= (.name = "redhat" | .version = "7.9")' rpms.cdx.json > rpms-res.cdx.json
$ trivy sbom ./rpms-res.cdx.json
```

## License
If licenses are included in the RPM archive, Trivy extracts it.

[^1]: Need to generate SBOM first and add OS information to that SBOM

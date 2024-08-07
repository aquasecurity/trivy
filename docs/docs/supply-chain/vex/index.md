# Vulnerability Exploitability Exchange (VEX)

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports filtering detected vulnerabilities using the [Vulnerability Exploitability eXchange (VEX)](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf), a standardized format for sharing and exchanging information about vulnerabilities.
By providing VEX during scanning, it is possible to filter vulnerabilities based on their status.

## VEX Usage Methods

Trivy currently supports two methods for utilizing VEX:

1. [VEX Repository](./repo.md)
2. [Local VEX Files](./file.md)
3. [VEX Attestation](./oci.md)

### Enabling VEX
To enable VEX, use the `--vex` option.
You can specify the method to use:

- To enable the VEX Repository: `--vex repo`
- To use a local VEX file: `--vex /path/to/vex-document.json`
- To enable VEX attestation discovery in OCI registry: `--vex oci`

```bash
$ trivy image ghcr.io/aquasecurity/trivy:0.52.0 --vex repo
```

You can enable these methods simultaneously.
The order of specification determines the priority:

- `--vex repo --vex /path/to/vex-document.json`: VEX Repository has priority
- `--vex /path/to/vex-document.json --vex repo`: Local file has priority

For detailed information on each method, please refer to each page.
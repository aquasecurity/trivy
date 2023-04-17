# Vulnerability Exploitability Exchange (VEX)
Trivy supports filtering detected vulnerabilities using [the Vulnerability Exploitability Exchange (VEX)](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf), a standardized format for sharing and exchanging information about vulnerabilities.
By providing VEX alongside the Software Bill of Materials (SBOM) during scanning, it is possible to filter vulnerabilities based on their status.
Currently, Trivy supports the following two formats:

- [CycloneDX](https://cyclonedx.org/capabilities/vex/)
- [OpenVEX](https://github.com/openvex/spec)

This is still an experimental implementation, with only minimal functionality added.

## CycloneDX
There are [two VEX formats](https://cyclonedx.org/capabilities/vex/) for CycloneDX:

- Independent BOM and VEX BOM
- BOM With Embedded VEX

Trivy only supports the Independent BOM and VEX BOM format, so you need to provide a separate VEX file alongside the SBOM.
The following steps are required:

1. Generate a CycloneDX SBOM.
2. Create a VEX based on the SBOM generated in step 1.
3. Provide the VEX when scanning the SBOM.

### Generating the SBOM
You can generate a CycloneDX SBOM with Trivy as follows:

```shell
$ trivy image --format cyclonedx --output debian11.sbom.cdx debian:11
```

### Create the VEX

```
$ cat <<EOF > trivy.vex.cdx
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2020-8911",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "response": ["will_not_fix", "update"],
        "detail": "The vulnerable function is not called"
      },
      "affects": [
        {
          "ref": "pkg:golang/github.com/aws/aws-sdk-go@1.44.234"
        }
      ]
    }
  ]
}
EOF
```

!!! note
    The `affects.ref` field must contain a CycloneDX [BOM-Link](https://cyclonedx.org/capabilities/bomlink/).

### Scan SBOM with VEX
Provide the VEX when scanning the SBOM.

```
$ trivy sbom trivy.sbom.cdx --vex trivy.vex.cdx
...
2023-04-13T12:55:44.838+0300    INFO    Filtered out CVE-2020-8911 according to VEX: status: not_affected, justification: code_not_reachable

go.mod (gomod)
==============
Total: 1 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

┌───────────────────────────┬───────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│          Library          │ Vulnerability │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├───────────────────────────┼───────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ github.com/aws/aws-sdk-go │ CVE-2020-8912 │ LOW      │ 1.44.234          │               │ aws-sdk-go: In-band key negotiation issue in AWS S3 Crypto │
│                           │               │          │                   │               │ SDK for golang...                                          │
│                           │               │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-8912                  │
└───────────────────────────┴───────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
```
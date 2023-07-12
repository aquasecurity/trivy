# Vulnerability Exploitability Exchange (VEX)

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

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
The input SBOM format must be in CycloneDX format.

The following steps are required:

1. Generate a CycloneDX SBOM
2. Create a VEX based on the SBOM generated in step 1
3. Provide the VEX when scanning the CycloneDX SBOM

### Generating the SBOM
You can generate a CycloneDX SBOM with Trivy as follows:

```shell
$ trivy image --format cyclonedx --output debian11.sbom.cdx debian:11
```

### Create the VEX
Next, create a VEX based on the generated SBOM.
Multiple vulnerability statuses can be defined under `vulnerabilities`.
Take a look at the example below.

```
$ cat <<EOF > trivy.vex.cdx
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
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
          "ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:golang/github.com/aws/aws-sdk-go@1.44.234"
        }
      ]
    }
  ]
}
EOF
```

This is a VEX document in the CycloneDX format.
The vulnerability ID, such as a CVE-ID or GHSA-ID, should be placed in `vulnerabilities.id`.
When the `analysis.state` is set to `not_affected`, Trivy will not detect the vulnerability.

BOM-Links must be placed in `affects.ref`.
The BOM-Link has the following syntax and consists of three elements:

```
urn:cdx:serialNumber/version#bom-ref
```

- serialNumber
- version
- bom-ref
 
These values must be obtained from the CycloneDX SBOM.
Please note that while the serialNumber starts with `urn:uuid:`, the BOM-Link starts with `urn:cdx:`.

The `bom-ref` must contain the BOM-Ref of the package affected by the vulnerability.
In the example above, since the Go package `github.com/aws/aws-sdk-go` is affected by CVE-2020-8911, it was necessary to specify the SBOM's BOM-Ref, `pkg:golang/github.com/aws/aws-sdk-go@1.44.234`.

For more details on CycloneDX VEX and BOM-Link, please refer to the following links:

- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
- [BOM-Link](https://cyclonedx.org/capabilities/bomlink/)
- [Examples](https://github.com/CycloneDX/bom-examples/tree/master)

### Scan SBOM with VEX
Provide the VEX when scanning the CycloneDX SBOM.

```
$ trivy sbom trivy.sbom.cdx --vex trivy.vex.cdx
...
2023-04-13T12:55:44.838+0300    INFO    Filtered out the detected vulnerability {"VEX format": "CycloneDX", "vulnerability-id": "CVE-2020-8911", "status": "not_affected", "justification": "code_not_reachable"}

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

CVE-2020-8911 is no longer shown as it is filtered out according to the given CycloneDX VEX document.

## OpenVEX
Trivy also supports [OpenVEX](https://github.com/openvex/spec) that is designed to be minimal, compliant, interoperable, and embeddable.
Since OpenVEX aims to be SBOM format agnostic, both CycloneDX and SPDX formats are available for use as input SBOMs in Trivy.

The following steps are required:

1. Generate a SBOM (CycloneDX or SPDX)
2. Create a VEX based on the SBOM generated in step 1
3. Provide the VEX when scanning the SBOM

### Generating the SBOM
You can generate a CycloneDX or SPDX SBOM with Trivy as follows:

```shell
$ trivy image --format spdx-json --output debian11.spdx.json debian:11
```

### Create the VEX
Please see also [the example](https://github.com/openvex/examples).
The product identifiers differ depending on the SBOM format the VEX references.

- SPDX: [Package URL (PURL)](https://github.com/package-url/purl-spec)
- CycloneDX: [BOM-Link](https://cyclonedx.org/capabilities/bomlink/)

```
$ cat <<EOF > trivy.openvex
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
  "author": "Aqua Security",
  "timestamp": "2023-01-16T19:07:16.853479631-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2019-8457",
      "products": [
        "pkg:deb/debian/libdb5.3@5.3.28+dfsg1-0.8?arch=arm64\u0026distro=debian-11.6"
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
EOF
```

In the above example, PURLs, located in `packages.externalRefs.referenceLocator` are used since the input SBOM format is SPDX.

As for CycloneDX BOM-Link, please reference [the CycloneDX section](#cyclonedx).

### Scan SBOM with VEX
Provide the VEX when scanning the SBOM.

```
$ trivy sbom debian11.spdx.json --vex trivy.openvex
...
2023-04-26T17:56:05.358+0300    INFO    Filtered out the detected vulnerability {"VEX format": "OpenVEX", "vulnerability-id": "CVE-2019-8457", "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}

debian11.spdx.json (debian 11.6)
================================
Total: 80 (UNKNOWN: 0, LOW: 58, MEDIUM: 6, HIGH: 16, CRITICAL: 0)
```

CVE-2019-8457 is no longer shown as it is filtered out according to the given OpenVEX document.

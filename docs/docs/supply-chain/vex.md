# Vulnerability Exploitability Exchange (VEX)

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports filtering detected vulnerabilities using [the Vulnerability Exploitability Exchange (VEX)](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf), a standardized format for sharing and exchanging information about vulnerabilities.
By providing VEX during scanning, it is possible to filter vulnerabilities based on their status.
Currently, Trivy supports the following three formats:

- [CycloneDX](https://cyclonedx.org/capabilities/vex/)
- [OpenVEX](https://github.com/openvex/spec)
- [CSAF](https://oasis-open.github.io/csaf-documentation/specification.html)

This is still an experimental implementation, with only minimal functionality added.

## CycloneDX
|     Target      | Supported |
|:---------------:|:---------:|
| Container Image |           |
|   Filesystem    |           |
| Code Repository |           |
|    VM Image     |           |
|   Kubernetes    |           |
|      SBOM       |     ✅     |

There are [two VEX formats](https://cyclonedx.org/capabilities/vex/) for CycloneDX:

- Independent BOM and VEX BOM
- BOM With Embedded VEX

Trivy only supports the Independent BOM and VEX BOM format, so you need to provide a separate VEX file alongside the SBOM.
The input SBOM format must be in CycloneDX format.

The following steps are required:

1. Generate a CycloneDX SBOM
2. Create a VEX based on the SBOM generated in step 1
3. Provide the VEX when scanning the CycloneDX SBOM

### Generate the SBOM
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
|     Target      | Supported |
|:---------------:|:---------:|
| Container Image |     ✅     |
|   Filesystem    |     ✅     |
| Code Repository |     ✅     |
|    VM Image     |     ✅     |
|   Kubernetes    |     ✅     |
|      SBOM       |     ✅     |

Trivy also supports [OpenVEX][openvex] that is designed to be minimal, compliant, interoperable, and embeddable.
OpenVEX can be used in all Trivy targets, unlike CycloneDX VEX.

The following steps are required:

1. Create a VEX document
2. Provide the VEX when scanning your target

### Create the VEX document
Please see also [the example](https://github.com/openvex/examples).
In Trivy, [the Package URL (PURL)][purl] is used as the product identifier.

```
$ cat <<EOF > debian11.openvex
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
  "author": "Aqua Security",
  "timestamp": "2023-08-29T19:07:16.853479631-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2019-8457"},
      "products": [
        {"@id": "pkg:deb/debian/libdb5.3@5.3.28+dfsg1-0.8"}
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
EOF
```

In the above example, PURLs, located in `packages.externalRefs.referenceLocator` in SPDX are used for the product identifier.

!!! note
    If a qualifier is specified in the PURL used as the product id in the VEX, the qualifier is compared.
    Other qualifiers are ignored in the comparison.
    `pkg:deb/debian/curl@7.50.3-1` in OpenVEX matches `pkg:deb/debian/curl@7.50.3-1?arch=i386`, 
    while `pkg:deb/debian/curl@7.50.3-1?arch=amd64` does not match `pkg:deb/debian/curl@7.50.3-1?arch=i386`.

### Scan with VEX
Provide the VEX when scanning your target.

```
$ trivy image debian:11 --vex debian11.openvex
...
2023-04-26T17:56:05.358+0300    INFO    Filtered out the detected vulnerability {"VEX format": "OpenVEX", "vulnerability-id": "CVE-2019-8457", "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}

debian11.spdx.json (debian 11.6)
================================
Total: 80 (UNKNOWN: 0, LOW: 58, MEDIUM: 6, HIGH: 16, CRITICAL: 0)
```

CVE-2019-8457 is no longer shown as it is filtered out according to the given OpenVEX document.


## CSAF
|     Target      | Supported |
|:---------------:|:---------:|
| Container Image |     ✅     |
|   Filesystem    |     ✅     |
| Code Repository |     ✅     |
|    VM Image     |     ✅     |
|   Kubernetes    |     ✅     |
|      SBOM       |     ✅     |

Trivy also supports [CSAF][csaf] format for VEX.
Since CSAF aims to be SBOM format agnostic, both CycloneDX and SPDX formats are available for use as input SBOMs in Trivy.

The following steps are required:

1. Create a CSAF document
2. Provide the CSAF when scanning your target


### Create the CSAF document
Create a CSAF document in JSON format as follows:

```
$ cat <<EOF > debian11.vex.csaf
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "notes": [
      {
        "category": "summary",
        "text": "Example Company VEX document. Unofficial content for demonstration purposes only.",
        "title": "Author comment"
      }
    ],
    "publisher": {
      "category": "vendor",
      "name": "Example Company ProductCERT",
      "namespace": "https://psirt.example.com"
    },
    "title": "AquaSecurity example VEX document",
    "tracking": {
      "current_release_date": "2024-01-01T11:00:00.000Z",
      "generator": {
        "date": "2024-01-01T11:00:00.000Z",
        "engine": {
          "name": "Secvisogram",
          "version": "1.11.0"
        }
      },
      "id": "2024-EVD-UC-01-A-001",
      "initial_release_date": "2024-01-01T11:00:00.000Z",
      "revision_history": [
        {
          "date": "2024-01-01T11:00:00.000Z",
          "number": "1",
          "summary": "Initial version."
        }
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "branches": [
          {
            "branches": [
              {
                "category": "product_version",
                "name": "5.3",
                "product": {
                  "name": "Database Libraries 5.3",
                  "product_id": "LIBDB-5328",
                  "product_identification_helper": {
                    "purl": "pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=amd64\u0026distro=debian-11.8"
                  }
                }
              }
            ],
            "category": "product_name",
            "name": "Database Libraries"
          }
        ],
        "category": "vendor",
        "name": "Debian"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2019-8457",
      "notes": [
        {
          "category": "description",
          "text": "SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable to heap out-of-bound read in the rtreenode() function when handling invalid rtree tables.",
          "title": "CVE description"
        }
      ],
      "product_status": {
        "known_not_affected": [
          "LIBDB-5328"
        ]
      },
      "threats": [
        {
          "category": "impact",
          "details": "Vulnerable code not in execute path.",
          "product_ids": [
            "LIBDB-5328"
          ]
        }
      ]
    }
  ]
}
EOF
```

### Scan with CSAF VEX
Provide the CSAF document when scanning your target.

```console
$ trivy image debian:11 --vex debian11.vex.csaf
...
2024-01-02T10:28:26.704+0100	INFO	Filtered out the detected vulnerability	{"VEX format": "CSAF", "vulnerability-id": "CVE-2019-8457", "status": "not_affected"}

debian11.spdx.json (debian 11.6)
================================
Total: 80 (UNKNOWN: 0, LOW: 58, MEDIUM: 6, HIGH: 16, CRITICAL: 0)
```

CVE-2019-8457 is no longer shown as it is filtered out according to the given CSAF document.

## Appendix
### PURL matching
In the context of VEX, Package URLs (PURLs) are utilized to identify specific software packages and their versions.
The PURL matching specification outlines how PURLs are interpreted for vulnerability exception processing, ensuring precise identification and broad coverage of software packages.

!!! note
    The following PURL matching rules are not formally defined within the current official PURL specification.
    Instead, they represent [a community consensus][purl-matching] on how to interpret PURLs.

Below are the key aspects of the PURL matching rules:

#### Matching Without Version
A PURL without a specified version (e.g., `pkg:maven/com.google.guava/guava`) matches all versions of that package.
This rule simplifies the application of vulnerability exceptions to all versions of a package.

**Example**: `pkg:maven/com.google.guava/guava` matches:

- All versions of `guava`, such as `com.google.guava:guava:24.1.1`, `com.google.guava:guava:30.0`.
 
#### Matching Without Qualifiers
A PURL without any qualifiers (e.g., `pkg:maven/com.google.guava/guava@24.1.1`) matches any variation of that package, irrespective of qualifiers.
This approach ensures broad matching capabilities, covering all architectural or platform-specific variations of a package version.

**Example**: `pkg:maven/com.google.guava/guava@24.1.1` matches:

- `pkg:maven/com.google.guava/guava@24.1.1?classifier=x86`
- `pkg:maven/com.google.guava/guava@24.1.1?type=pom`

#### Matching With Specific Qualifiers
A PURL that includes specific qualifiers (e.g., `pkg:maven/com.google.guava/guava@24.1.1?classifier=x86`) matches only those package versions that include the same qualifiers.

**Example**: `pkg:maven/com.google.guava/guava@24.1.1?classifier=x86` matches:

- `pkg:maven/com.google.guava/guava@24.1.1?classifier=x86&type=dll`
    - Extra qualifiers (e.g., `type=dll`) are ignored.

does not match:

- `pkg:maven/com.google.guava/guava@24.1.1`
    - `classifier=x86` is missing.
- `pkg:maven/com.google.guava/guava@24.1.1?classifier=sources`
    - `classifier` must have the same value.


[csaf]: https://oasis-open.github.io/csaf-documentation/specification.html
[openvex]: https://github.com/openvex/spec
[purl]: https://github.com/package-url/purl-spec
[purl-matching]: https://github.com/openvex/spec/issues/27

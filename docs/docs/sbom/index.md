# SBOM

## Generating
Trivy can generate the following SBOM formats.

- [CycloneDX][cyclonedx]
- [SPDX][spdx]

To generate SBOM, you can use the `--format` option for each subcommand such as `image` and `fs`.

```
$ trivy image --format spdx-json --output result.json alpine:3.15
```


```
$ trivy fs --format cyclonedx --output result.json /app/myproject
```

<details>
<summary>Result</summary>

```
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.3",
  "serialNumber": "urn:uuid:2be5773d-7cd3-4b4b-90a5-e165474ddace",
  "version": 1,
  "metadata": {
    "timestamp": "2022-02-22T15:11:40.270597Z",
    "tools": [
      {
        "vendor": "aquasecurity",
        "name": "trivy",
        "version": "dev"
      }
    ],
    "component": {
      "bom-ref": "pkg:oci/alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300?repository_url=index.docker.io%2Flibrary%2Falpine&arch=amd64",
      "type": "container",
      "name": "alpine:3.15",
      "version": "",
      "purl": "pkg:oci/alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300?repository_url=index.docker.io%2Flibrary%2Falpine&arch=amd64",
      "properties": [
        {
          "name": "aquasecurity:trivy:SchemaVersion",
          "value": "2"
        },
        {
          "name": "aquasecurity:trivy:ImageID",
          "value": "sha256:c059bfaa849c4d8e4aecaeb3a10c2d9b3d85f5165c66ad3a4d937758128c4d18"
        },
        {
          "name": "aquasecurity:trivy:RepoDigest",
          "value": "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"
        },
        {
          "name": "aquasecurity:trivy:DiffID",
          "value": "sha256:8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759"
        },
        {
          "name": "aquasecurity:trivy:RepoTag",
          "value": "alpine:3.15"
        }
      ]
    }
  },
  "components": [
    {
      "bom-ref": "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?distro=3.15.0",
      "type": "library",
      "name": "alpine-baselayout",
      "version": "3.2.0-r18",
      "licenses": [
        {
          "expression": "GPL-2.0-only"
        }
      ],
      "purl": "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?distro=3.15.0",
      "properties": [
        {
          "name": "aquasecurity:trivy:SrcName",
          "value": "alpine-baselayout"
        },
        {
          "name": "aquasecurity:trivy:SrcVersion",
          "value": "3.2.0-r18"
        },
        {
          "name": "aquasecurity:trivy:LayerDigest",
          "value": "sha256:59bf1c3509f33515622619af21ed55bbe26d24913cedbca106468a5fb37a50c3"
        },
        {
          "name": "aquasecurity:trivy:LayerDiffID",
          "value": "sha256:8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759"
        }
      ]
    },
    ...(snip)...
    {
      "bom-ref": "pkg:apk/alpine/zlib@1.2.11-r3?distro=3.15.0",
      "type": "library",
      "name": "zlib",
      "version": "1.2.11-r3",
      "licenses": [
        {
          "expression": "Zlib"
        }
      ],
      "purl": "pkg:apk/alpine/zlib@1.2.11-r3?distro=3.15.0",
      "properties": [
        {
          "name": "aquasecurity:trivy:SrcName",
          "value": "zlib"
        },
        {
          "name": "aquasecurity:trivy:SrcVersion",
          "value": "1.2.11-r3"
        },
        {
          "name": "aquasecurity:trivy:LayerDigest",
          "value": "sha256:59bf1c3509f33515622619af21ed55bbe26d24913cedbca106468a5fb37a50c3"
        },
        {
          "name": "aquasecurity:trivy:LayerDiffID",
          "value": "sha256:8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759"
        }
      ]
    },
    {
      "bom-ref": "3da6a469-964d-4b4e-b67d-e94ec7c88d37",
      "type": "operating-system",
      "name": "alpine",
      "version": "3.15.0",
      "properties": [
        {
          "name": "aquasecurity:trivy:Type",
          "value": "alpine"
        },
        {
          "name": "aquasecurity:trivy:Class",
          "value": "os-pkgs"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "3da6a469-964d-4b4e-b67d-e94ec7c88d37",
      "dependsOn": [
        "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?distro=3.15.0",
        "pkg:apk/alpine/alpine-keys@2.4-r1?distro=3.15.0",
        "pkg:apk/alpine/apk-tools@2.12.7-r3?distro=3.15.0",
        "pkg:apk/alpine/busybox@1.34.1-r3?distro=3.15.0",
        "pkg:apk/alpine/ca-certificates-bundle@20191127-r7?distro=3.15.0",
        "pkg:apk/alpine/libc-utils@0.7.2-r3?distro=3.15.0",
        "pkg:apk/alpine/libcrypto1.1@1.1.1l-r7?distro=3.15.0",
        "pkg:apk/alpine/libretls@3.3.4-r2?distro=3.15.0",
        "pkg:apk/alpine/libssl1.1@1.1.1l-r7?distro=3.15.0",
        "pkg:apk/alpine/musl@1.2.2-r7?distro=3.15.0",
        "pkg:apk/alpine/musl-utils@1.2.2-r7?distro=3.15.0",
        "pkg:apk/alpine/scanelf@1.3.3-r0?distro=3.15.0",
        "pkg:apk/alpine/ssl_client@1.34.1-r3?distro=3.15.0",
        "pkg:apk/alpine/zlib@1.2.11-r3?distro=3.15.0"
      ]
    },
    {
      "ref": "pkg:oci/alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300?repository_url=index.docker.io%2Flibrary%2Falpine&arch=amd64",
      "dependsOn": [
        "3da6a469-964d-4b4e-b67d-e94ec7c88d37"
      ]
    }
  ]
}

```

</details>

## Scanning
Trivy also can take the following SBOM formats as an input and scan for vulnerabilities.

- CycloneDX
- SPDX
- SPDX JSON
- CycloneDX-type attestation

To scan SBOM, you can use the `sbom` subcommand and pass the path to the SBOM.

```bash
$ trivy sbom /path/to/cyclonedx.json
```

See [here][cyclonedx] for the detail.

!!! note
    CycloneDX XML is not supported at the moment.

```bash
$ trivy sbom /path/to/spdx.json
```

See [here][spdx] for the detail.


You can also scan an SBOM attestation.
In the following example, [Cosign][Cosign] can get an attestation and trivy scan it. You must create CycloneDX-type attestation before trying the example. To learn more about how to create an CycloneDX-Type attestation and attach it to an image, see the [SBOM attestation page][sbom_attestation].
```bash
$ cosign verify-attestation --key /path/to/cosign.pub --type cyclonedx <IMAGE> > sbom.cdx.intoto.jsonl
$ trivy sbom ./sbom.cdx.intoto.jsonl

sbom.cdx.intoto.jsonl (alpine 3.7.3)
=========================
Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

┌────────────┬────────────────┬──────────┬───────────────────┬───────────────┬──────────────────────────────────────────────────────────┐
│  Library   │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                          Title                           │
├────────────┼────────────────┼──────────┼───────────────────┼───────────────┼──────────────────────────────────────────────────────────┤
│ musl       │ CVE-2019-14697 │ CRITICAL │ 1.1.18-r3         │ 1.1.18-r4     │ musl libc through 1.1.23 has an x87 floating-point stack │
│            │                │          │                   │               │ adjustment im ......                                     │
│            │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2019-14697               │
├────────────┤                │          │                   │               │                                                          │
│ musl-utils │                │          │                   │               │                                                          │
│            │                │          │                   │               │                                                          │
│            │                │          │                   │               │                                                          │
└────────────┴────────────────┴──────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────┘
```

[cyclonedx]: cyclonedx.md
[spdx]: spdx.md
[Cosign]: https://github.com/sigstore/cosign
[sbom_attestation]: ../attestation/sbom.md#sign-with-a-local-key-pair
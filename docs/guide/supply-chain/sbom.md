# SBOM

## Generating

Trivy can generate the following SBOM formats.

- [CycloneDX](#cyclonedx)
- [SPDX](#spdx)

### CLI commands
To generate SBOM, you can use the `--format` option for each subcommand such as `image`, `fs` and `vm`.

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

### Supported packages
Trivy supports the following packages.

- [OS packages][os_packages]
- [Language-specific packages][language_packages]

Trivy has a specific logic for package detection.
See the [package detection](../scanner/vulnerability.md#package-detection) section for more information.

### Formats
#### CycloneDX
Trivy can generate SBOM in the [CycloneDX][cyclonedx] format.
Note that XML format is not supported at the moment.

You can use the regular subcommands (like `image`, `fs` and `rootfs`) and specify `cyclonedx` with the `--format` option.

CycloneDX can represent either or both SBOM or BOV.

- [Software Bill of Materials (SBOM)][sbom]
- [Bill of Vulnerabilities (BOV)][bov]

By default, `--format cyclonedx` represents SBOM and doesn't include vulnerabilities in the CycloneDX output.

```
$ trivy image --format cyclonedx --output result.json alpine:3.15
2022-07-19T07:47:27.624Z        INFO    "--format cyclonedx" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the CycloneDX report.
```

<details>
<summary>Result</summary>

```
$ cat result.json | jq .
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:2be5773d-7cd3-4b4b-90a5-e165474ddace",
  "version": 1,
  "metadata": {
    "timestamp": "2022-02-22T15:11:40.270597Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "aquasecurity",
          "name": "trivy",
          "version": "dev"
        }
      ]
    },
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
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-42386",
      "source": {
        "name": "alpine",
        "url": "https://secdb.alpinelinux.org/"
      },
      "ratings": [
        {
          "source": {
            "name": "nvd"
          },
          "score": 7.2,
          "severity": "high",
          "method": "CVSSv31",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
        },
        {
          "source": {
            "name": "nvd"
          },
          "score": 6.5,
          "severity": "medium",
          "method": "CVSSv2",
          "vector": "AV:N/AC:L/Au:S/C:P/I:P/A:P"
        },
        {
          "source": {
            "name": "redhat"
          },
          "score": 6.6,
          "severity": "medium",
          "method": "CVSSv31",
          "vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
        }
      ],
      "cwes": [
        416
      ],
      "description": "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the nvalloc function",
      "advisories": [
        {
          "url": "https://access.redhat.com/security/cve/CVE-2021-42386"
        },
        {
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42386"
        }
      ],
      "published": "2021-11-15 21:15:00 +0000 UTC",
      "updated": "2022-01-04 17:14:00 +0000 UTC",
      "affects": [
        {
          "ref": "pkg:apk/alpine/busybox@1.33.1-r3?distro=3.14.2"
        },
        {
          "ref": "pkg:apk/alpine/ssl_client@1.33.1-r3?distro=3.14.2"
        }
      ]
    }
  ]
}

```

</details>

If you want to include vulnerabilities, you can enable vulnerability scanning via `--scanners vuln`.

```
$ trivy image --scanners vuln --format cyclonedx --output result.json alpine:3.15
```

#### SPDX
Trivy can generate SBOM in the [SPDX][spdx] format.

You can use the regular subcommands (like `image`, `fs` and `rootfs`) and specify `spdx` or `spdx-json` with the `--format` option.

```
$ trivy image --format spdx --output result.spdx alpine:3.15
```

<details>
<summary>Result</summary>

```spdx
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: alpine:3.15
DocumentNamespace: http://trivy.dev/container_image/alpine:3.15-12db86e1-4aa4-40ec-900b-5aaa5d82461b
Creator: Organization: aquasecurity
Creator: Tool: trivy-0.58.0
Created: 2025-02-11T07:43:38Z

##### Package: alpine:3.15

PackageName: alpine:3.15
SPDXID: SPDXRef-ContainerImage-d8b2a386253047e7
PackageDownloadLocation: NONE
PrimaryPackagePurpose: CONTAINER
FilesAnalyzed: false
ExternalRef: PACKAGE-MANAGER purl pkg:oci/alpine@sha256%3A19b4bcc4f60e99dd5ebdca0cbce22c503bbcff197549d7e19dab4f22254dc864?arch=amd64&repository_url=index.docker.io%2Flibrary%2Falpine

##### Package: alpine

PackageName: alpine
SPDXID: SPDXRef-OperatingSystem-c24750c3b737d897
PackageVersion: 3.15.11
PackageDownloadLocation: NONE
PrimaryPackagePurpose: OPERATING-SYSTEM
FilesAnalyzed: false

##### Package: libretls

PackageName: libretls
SPDXID: SPDXRef-Package-343391d704e00fbd
PackageVersion: 3.3.4-r3
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 67dfefe5456c45192b60d76ade98c501b0ae814f
PackageSourceInfo: built package from: libretls 3.3.4-r3
PackageLicenseConcluded: ISC AND BSD-3-Clause AND MIT
PackageLicenseDeclared: ISC AND BSD-3-Clause AND MIT
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/libretls@3.3.4-r3?arch=x86_64&distro=3.15.11

##### Package: libc-utils

PackageName: libc-utils
SPDXID: SPDXRef-Package-43343abe5c1a0439
PackageVersion: 0.7.2-r3
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 798de3ebb57f3e28f408080746935f213a099722
PackageSourceInfo: built package from: libc-dev 0.7.2-r3
PackageLicenseConcluded: BSD-2-Clause AND BSD-3-Clause
PackageLicenseDeclared: BSD-2-Clause AND BSD-3-Clause
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64&distro=3.15.11

##### Package: alpine-baselayout

PackageName: alpine-baselayout
SPDXID: SPDXRef-Package-64b7e662458dcd5f
PackageVersion: 3.2.0-r18
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 132992eab020986b3b5d886a77212889680467a0
PackageSourceInfo: built package from: alpine-baselayout 3.2.0-r18
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=x86_64&distro=3.15.11

##### Package: busybox

PackageName: busybox
SPDXID: SPDXRef-Package-6c7c9dac75e301b7
PackageVersion: 1.34.1-r7
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 21f9265e7a34c795fba4e99c8ae37b57f31cd1a2
PackageSourceInfo: built package from: busybox 1.34.1-r7
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/busybox@1.34.1-r7?arch=x86_64&distro=3.15.11

##### Package: ca-certificates-bundle

PackageName: ca-certificates-bundle
SPDXID: SPDXRef-Package-702c9bf0cfddb42e
PackageVersion: 20230506-r0
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 99894c0b834a3f5955e6e5d5f0d804943f05ff52
PackageSourceInfo: built package from: ca-certificates 20230506-r0
PackageLicenseConcluded: MPL-2.0 AND MIT
PackageLicenseDeclared: MPL-2.0 AND MIT
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/ca-certificates-bundle@20230506-r0?arch=x86_64&distro=3.15.11

##### Package: musl-utils

PackageName: musl-utils
SPDXID: SPDXRef-Package-92eb9ab29b057905
PackageVersion: 1.2.2-r9
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: f69aa6d6a57c90358005ce61ccb4ad96cdc303f4
PackageSourceInfo: built package from: musl 1.2.2-r9
PackageLicenseConcluded: MIT AND BSD-3-Clause AND GPL-2.0-or-later
PackageLicenseDeclared: MIT AND BSD-3-Clause AND GPL-2.0-or-later
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/musl-utils@1.2.2-r9?arch=x86_64&distro=3.15.11

##### Package: scanelf

PackageName: scanelf
SPDXID: SPDXRef-Package-988bca2f70cf58f6
PackageVersion: 1.3.3-r0
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: d7f7590e450870a4f79671c2369b31b5bb07349a
PackageSourceInfo: built package from: pax-utils 1.3.3-r0
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/scanelf@1.3.3-r0?arch=x86_64&distro=3.15.11

##### Package: apk-tools

PackageName: apk-tools
SPDXID: SPDXRef-Package-aa2e51a695e95cb9
PackageVersion: 2.12.7-r3
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: ddf3ddf8545768bc323649559feaae1560f29273
PackageSourceInfo: built package from: apk-tools 2.12.7-r3
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/apk-tools@2.12.7-r3?arch=x86_64&distro=3.15.11

##### Package: libcrypto1.1

PackageName: libcrypto1.1
SPDXID: SPDXRef-Package-ba5f079c5c32fc8
PackageVersion: 1.1.1w-r1
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: e378634f5c8af32ca75ac56f41ecf4e8d49584a0
PackageSourceInfo: built package from: openssl 1.1.1w-r1
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64&distro=3.15.11

##### Package: alpine-keys

PackageName: alpine-keys
SPDXID: SPDXRef-Package-be18726b6be779d1
PackageVersion: 2.4-r1
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 903176b2d2a8ddefd1ba6940f19ad17c2c1d4aff
PackageSourceInfo: built package from: alpine-keys 2.4-r1
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/alpine-keys@2.4-r1?arch=x86_64&distro=3.15.11

##### Package: ssl_client

PackageName: ssl_client
SPDXID: SPDXRef-Package-d9ad92ed9413c93b
PackageVersion: 1.34.1-r7
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: dddfa62dd51bd8807ee1d8660e860574a9dd78ed
PackageSourceInfo: built package from: busybox 1.34.1-r7
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/ssl_client@1.34.1-r7?arch=x86_64&distro=3.15.11

##### Package: musl

PackageName: musl
SPDXID: SPDXRef-Package-ee9b5186331e7a76
PackageVersion: 1.2.2-r9
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 7ebdef6cf7f9b58c0e213b333db946d22b00b777
PackageSourceInfo: built package from: musl 1.2.2-r9
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/musl@1.2.2-r9?arch=x86_64&distro=3.15.11

##### Package: libssl1.1

PackageName: libssl1.1
SPDXID: SPDXRef-Package-f00669065070476c
PackageVersion: 1.1.1w-r1
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: 9306ed15b3bdfc7553d5c14c472d87a41fef8541
PackageSourceInfo: built package from: openssl 1.1.1w-r1
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/libssl1.1@1.1.1w-r1?arch=x86_64&distro=3.15.11

##### Package: zlib

PackageName: zlib
SPDXID: SPDXRef-Package-fcb106f21773cad3
PackageVersion: 1.2.12-r3
PackageSupplier: NOASSERTION
PackageDownloadLocation: NONE
PrimaryPackagePurpose: LIBRARY
FilesAnalyzed: false
PackageChecksum: SHA1: ab98d0416bf1dcd245c7b0800f99cbceacfa48b3
PackageSourceInfo: built package from: zlib 1.2.12-r3
PackageLicenseConcluded: Zlib
PackageLicenseDeclared: Zlib
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&distro=3.15.11

##### Relationships

Relationship: SPDXRef-ContainerImage-d8b2a386253047e7 CONTAINS SPDXRef-OperatingSystem-c24750c3b737d897
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-ContainerImage-d8b2a386253047e7
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-343391d704e00fbd
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-43343abe5c1a0439
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-64b7e662458dcd5f
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-6c7c9dac75e301b7
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-702c9bf0cfddb42e
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-92eb9ab29b057905
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-988bca2f70cf58f6
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-aa2e51a695e95cb9
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-ba5f079c5c32fc8
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-be18726b6be779d1
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-d9ad92ed9413c93b
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-f00669065070476c
Relationship: SPDXRef-OperatingSystem-c24750c3b737d897 CONTAINS SPDXRef-Package-fcb106f21773cad3
Relationship: SPDXRef-Package-343391d704e00fbd DEPENDS_ON SPDXRef-Package-702c9bf0cfddb42e
Relationship: SPDXRef-Package-343391d704e00fbd DEPENDS_ON SPDXRef-Package-ba5f079c5c32fc8
Relationship: SPDXRef-Package-343391d704e00fbd DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-343391d704e00fbd DEPENDS_ON SPDXRef-Package-f00669065070476c
Relationship: SPDXRef-Package-43343abe5c1a0439 DEPENDS_ON SPDXRef-Package-92eb9ab29b057905
Relationship: SPDXRef-Package-64b7e662458dcd5f DEPENDS_ON SPDXRef-Package-6c7c9dac75e301b7
Relationship: SPDXRef-Package-64b7e662458dcd5f DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-6c7c9dac75e301b7 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-92eb9ab29b057905 DEPENDS_ON SPDXRef-Package-988bca2f70cf58f6
Relationship: SPDXRef-Package-92eb9ab29b057905 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-988bca2f70cf58f6 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-aa2e51a695e95cb9 DEPENDS_ON SPDXRef-Package-702c9bf0cfddb42e
Relationship: SPDXRef-Package-aa2e51a695e95cb9 DEPENDS_ON SPDXRef-Package-ba5f079c5c32fc8
Relationship: SPDXRef-Package-aa2e51a695e95cb9 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-aa2e51a695e95cb9 DEPENDS_ON SPDXRef-Package-f00669065070476c
Relationship: SPDXRef-Package-aa2e51a695e95cb9 DEPENDS_ON SPDXRef-Package-fcb106f21773cad3
Relationship: SPDXRef-Package-ba5f079c5c32fc8 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-d9ad92ed9413c93b DEPENDS_ON SPDXRef-Package-343391d704e00fbd
Relationship: SPDXRef-Package-d9ad92ed9413c93b DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-f00669065070476c DEPENDS_ON SPDXRef-Package-ba5f079c5c32fc8
Relationship: SPDXRef-Package-f00669065070476c DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
Relationship: SPDXRef-Package-fcb106f21773cad3 DEPENDS_ON SPDXRef-Package-ee9b5186331e7a76
```

</details>

```
$ trivy image --format spdx-json --output result.spdx alpine:3.15
```

<details>
<summary>Result</summary>

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "alpine:3.15",
  "documentNamespace": "http://trivy.dev/container_image/alpine:3.15-bbe0096f-0ed0-47b4-bbea-82121a9201f1",
  "creationInfo": {
    "creators": [
      "Organization: aquasecurity",
      "Tool: trivy-0.58.0"
    ],
    "created": "2025-02-13T12:22:22Z"
  },
  "packages": [
    {
      "name": "alpine:3.15",
      "SPDXID": "SPDXRef-ContainerImage-d8b2a386253047e7",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:oci/alpine@sha256%3A19b4bcc4f60e99dd5ebdca0cbce22c503bbcff197549d7e19dab4f22254dc864?arch=amd64\u0026repository_url=index.docker.io%2Flibrary%2Falpine"
        }
      ],
      "primaryPackagePurpose": "CONTAINER",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "DiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "ImageID: sha256:32b91e3161c8fc2e3baf2732a594305ca5093c82ff4e0c9f6ebbd2a879468e1d"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "RepoDigest: alpine@sha256:19b4bcc4f60e99dd5ebdca0cbce22c503bbcff197549d7e19dab4f22254dc864"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "RepoTag: alpine:3.15"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "SchemaVersion: 2"
        }
      ]
    },
    {
      "name": "alpine-baselayout",
      "SPDXID": "SPDXRef-Package-64b7e662458dcd5f",
      "versionInfo": "3.2.0-r18",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "132992eab020986b3b5d886a77212889680467a0"
        }
      ],
      "sourceInfo": "built package from: alpine-baselayout 3.2.0-r18",
      "licenseConcluded": "GPL-2.0-only",
      "licenseDeclared": "GPL-2.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/alpine-baselayout@3.2.0-r18?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: alpine-baselayout@3.2.0-r18"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "alpine-keys",
      "SPDXID": "SPDXRef-Package-be18726b6be779d1",
      "versionInfo": "2.4-r1",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "903176b2d2a8ddefd1ba6940f19ad17c2c1d4aff"
        }
      ],
      "sourceInfo": "built package from: alpine-keys 2.4-r1",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/alpine-keys@2.4-r1?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: alpine-keys@2.4-r1"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "apk-tools",
      "SPDXID": "SPDXRef-Package-aa2e51a695e95cb9",
      "versionInfo": "2.12.7-r3",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "ddf3ddf8545768bc323649559feaae1560f29273"
        }
      ],
      "sourceInfo": "built package from: apk-tools 2.12.7-r3",
      "licenseConcluded": "GPL-2.0-only",
      "licenseDeclared": "GPL-2.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/apk-tools@2.12.7-r3?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: apk-tools@2.12.7-r3"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "busybox",
      "SPDXID": "SPDXRef-Package-6c7c9dac75e301b7",
      "versionInfo": "1.34.1-r7",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "21f9265e7a34c795fba4e99c8ae37b57f31cd1a2"
        }
      ],
      "sourceInfo": "built package from: busybox 1.34.1-r7",
      "licenseConcluded": "GPL-2.0-only",
      "licenseDeclared": "GPL-2.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/busybox@1.34.1-r7?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: busybox@1.34.1-r7"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "ca-certificates-bundle",
      "SPDXID": "SPDXRef-Package-702c9bf0cfddb42e",
      "versionInfo": "20230506-r0",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "99894c0b834a3f5955e6e5d5f0d804943f05ff52"
        }
      ],
      "sourceInfo": "built package from: ca-certificates 20230506-r0",
      "licenseConcluded": "MPL-2.0 AND MIT",
      "licenseDeclared": "MPL-2.0 AND MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/ca-certificates-bundle@20230506-r0?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: ca-certificates-bundle@20230506-r0"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "libc-utils",
      "SPDXID": "SPDXRef-Package-43343abe5c1a0439",
      "versionInfo": "0.7.2-r3",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "798de3ebb57f3e28f408080746935f213a099722"
        }
      ],
      "sourceInfo": "built package from: libc-dev 0.7.2-r3",
      "licenseConcluded": "BSD-2-Clause AND BSD-3-Clause",
      "licenseDeclared": "BSD-2-Clause AND BSD-3-Clause",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: libc-utils@0.7.2-r3"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "libcrypto1.1",
      "SPDXID": "SPDXRef-Package-ba5f079c5c32fc8",
      "versionInfo": "1.1.1w-r1",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "e378634f5c8af32ca75ac56f41ecf4e8d49584a0"
        }
      ],
      "sourceInfo": "built package from: openssl 1.1.1w-r1",
      "licenseConcluded": "OpenSSL",
      "licenseDeclared": "OpenSSL",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: libcrypto1.1@1.1.1w-r1"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "libretls",
      "SPDXID": "SPDXRef-Package-343391d704e00fbd",
      "versionInfo": "3.3.4-r3",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "67dfefe5456c45192b60d76ade98c501b0ae814f"
        }
      ],
      "sourceInfo": "built package from: libretls 3.3.4-r3",
      "licenseConcluded": "ISC AND BSD-3-Clause AND MIT",
      "licenseDeclared": "ISC AND BSD-3-Clause AND MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/libretls@3.3.4-r3?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: libretls@3.3.4-r3"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "libssl1.1",
      "SPDXID": "SPDXRef-Package-f00669065070476c",
      "versionInfo": "1.1.1w-r1",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "9306ed15b3bdfc7553d5c14c472d87a41fef8541"
        }
      ],
      "sourceInfo": "built package from: openssl 1.1.1w-r1",
      "licenseConcluded": "OpenSSL",
      "licenseDeclared": "OpenSSL",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/libssl1.1@1.1.1w-r1?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: libssl1.1@1.1.1w-r1"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "musl",
      "SPDXID": "SPDXRef-Package-ee9b5186331e7a76",
      "versionInfo": "1.2.2-r9",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "7ebdef6cf7f9b58c0e213b333db946d22b00b777"
        }
      ],
      "sourceInfo": "built package from: musl 1.2.2-r9",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/musl@1.2.2-r9?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: musl@1.2.2-r9"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "musl-utils",
      "SPDXID": "SPDXRef-Package-92eb9ab29b057905",
      "versionInfo": "1.2.2-r9",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "f69aa6d6a57c90358005ce61ccb4ad96cdc303f4"
        }
      ],
      "sourceInfo": "built package from: musl 1.2.2-r9",
      "licenseConcluded": "MIT AND BSD-3-Clause AND GPL-2.0-or-later",
      "licenseDeclared": "MIT AND BSD-3-Clause AND GPL-2.0-or-later",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/musl-utils@1.2.2-r9?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: musl-utils@1.2.2-r9"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "scanelf",
      "SPDXID": "SPDXRef-Package-988bca2f70cf58f6",
      "versionInfo": "1.3.3-r0",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "d7f7590e450870a4f79671c2369b31b5bb07349a"
        }
      ],
      "sourceInfo": "built package from: pax-utils 1.3.3-r0",
      "licenseConcluded": "GPL-2.0-only",
      "licenseDeclared": "GPL-2.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/scanelf@1.3.3-r0?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: scanelf@1.3.3-r0"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "ssl_client",
      "SPDXID": "SPDXRef-Package-d9ad92ed9413c93b",
      "versionInfo": "1.34.1-r7",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "dddfa62dd51bd8807ee1d8660e860574a9dd78ed"
        }
      ],
      "sourceInfo": "built package from: busybox 1.34.1-r7",
      "licenseConcluded": "GPL-2.0-only",
      "licenseDeclared": "GPL-2.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/ssl_client@1.34.1-r7?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: ssl_client@1.34.1-r7"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "zlib",
      "SPDXID": "SPDXRef-Package-fcb106f21773cad3",
      "versionInfo": "1.2.12-r3",
      "supplier": "NOASSERTION",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "ab98d0416bf1dcd245c7b0800f99cbceacfa48b3"
        }
      ],
      "sourceInfo": "built package from: zlib 1.2.12-r3",
      "licenseConcluded": "Zlib",
      "licenseDeclared": "Zlib",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64\u0026distro=3.15.11"
        }
      ],
      "primaryPackagePurpose": "LIBRARY",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDiffID: sha256:2879a4821959ab702528e28a1c59cd26c4956112497f6d1dbfd86c8d88003983"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "LayerDigest: sha256:d078792c4f9122259f14b539315bd92cbd9490ed73e08255a08689122b143108"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgID: zlib@1.2.12-r3"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "PkgType: alpine"
        }
      ]
    },
    {
      "name": "alpine",
      "SPDXID": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "versionInfo": "3.15.11",
      "downloadLocation": "NONE",
      "filesAnalyzed": false,
      "primaryPackagePurpose": "OPERATING-SYSTEM",
      "annotations": [
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "Class: os-pkgs"
        },
        {
          "annotator": "Tool: trivy-0.58.0",
          "annotationDate": "2025-02-13T12:22:22Z",
          "annotationType": "OTHER",
          "comment": "Type: alpine"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-ContainerImage-d8b2a386253047e7",
      "relatedSpdxElement": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-ContainerImage-d8b2a386253047e7",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-343391d704e00fbd",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-43343abe5c1a0439",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-64b7e662458dcd5f",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-6c7c9dac75e301b7",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-702c9bf0cfddb42e",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-92eb9ab29b057905",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-988bca2f70cf58f6",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-aa2e51a695e95cb9",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-ba5f079c5c32fc8",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-be18726b6be779d1",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-d9ad92ed9413c93b",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-f00669065070476c",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-c24750c3b737d897",
      "relatedSpdxElement": "SPDXRef-Package-fcb106f21773cad3",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-Package-343391d704e00fbd",
      "relatedSpdxElement": "SPDXRef-Package-702c9bf0cfddb42e",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-343391d704e00fbd",
      "relatedSpdxElement": "SPDXRef-Package-ba5f079c5c32fc8",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-343391d704e00fbd",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-343391d704e00fbd",
      "relatedSpdxElement": "SPDXRef-Package-f00669065070476c",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-43343abe5c1a0439",
      "relatedSpdxElement": "SPDXRef-Package-92eb9ab29b057905",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-64b7e662458dcd5f",
      "relatedSpdxElement": "SPDXRef-Package-6c7c9dac75e301b7",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-64b7e662458dcd5f",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-6c7c9dac75e301b7",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-92eb9ab29b057905",
      "relatedSpdxElement": "SPDXRef-Package-988bca2f70cf58f6",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-92eb9ab29b057905",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-988bca2f70cf58f6",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-aa2e51a695e95cb9",
      "relatedSpdxElement": "SPDXRef-Package-702c9bf0cfddb42e",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-aa2e51a695e95cb9",
      "relatedSpdxElement": "SPDXRef-Package-ba5f079c5c32fc8",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-aa2e51a695e95cb9",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-aa2e51a695e95cb9",
      "relatedSpdxElement": "SPDXRef-Package-f00669065070476c",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-aa2e51a695e95cb9",
      "relatedSpdxElement": "SPDXRef-Package-fcb106f21773cad3",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-ba5f079c5c32fc8",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-d9ad92ed9413c93b",
      "relatedSpdxElement": "SPDXRef-Package-343391d704e00fbd",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-d9ad92ed9413c93b",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-f00669065070476c",
      "relatedSpdxElement": "SPDXRef-Package-ba5f079c5c32fc8",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-f00669065070476c",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-fcb106f21773cad3",
      "relatedSpdxElement": "SPDXRef-Package-ee9b5186331e7a76",
      "relationshipType": "DEPENDS_ON"
    }
  ]
}
```

</details>

## Scanning

### SBOM as Target
Trivy can take SBOM documents as input for scanning, e.g `trivy sbom ./sbom.spdx`.
See [here](../target/sbom.md) for more details.

### SBOM Detection inside Targets
Trivy searches for SBOM files in container images with the following extensions:

- `.spdx`
- `.spdx.json`
- `.cdx`
- `.cdx.json`

In addition, Trivy automatically detects SBOM files in [Bitnami images](https://github.com/bitnami/containers), [see here](../coverage/others/bitnami.md) for more details.

It is enabled in the following targets.

|     Target      | Enabled |
| :-------------: | :-----: |
| Container Image |    ✓    |
|   Filesystem    |         |
|     Rootfs      |    ✓    |
| Git Repository  |         |
|    VM Image     |    ✓    |
|   Kubernetes    |         |
|       AWS       |         |
|      SBOM       |         |

### SBOM Discovery for Container Images

When scanning container images, Trivy can discover SBOM for those images. [See here](../target/container_image.md) for more details.

[spdx]: https://spdx.github.io/spdx-spec/v2.2.2/

[cyclonedx]: https://cyclonedx.org/
[sbom]: https://cyclonedx.org/capabilities/sbom/
[bov]: https://cyclonedx.org/capabilities/bov/

[os_packages]: ../scanner/vulnerability.md#os-packages
[language_packages]: ../scanner/vulnerability.md#language-specific-packages

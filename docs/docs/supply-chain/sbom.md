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

You can use the regular subcommands (like `image`, `fs` and `rootfs`) and specify `spdx` with the `--format` option.

```
$ trivy image --format spdx --output result.spdx alpine:3.15
```

<details>
<summary>Result</summary>

```
$ cat result.spdx
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: alpine:3.15
DocumentNamespace: https://aquasecurity.github.io/trivy/container_image/alpine:3.15-bebf6b19-a94c-4e2c-af44-065f63923f48
Creator: Organization: aquasecurity
Creator: Tool: trivy-0.38.1
Created: 2022-04-28T07:32:57.142806Z

##### Package: zlib

PackageName: zlib
SPDXID: SPDXRef-12bc938ac028a5e1
PackageVersion: 1.2.12-r0
FilesAnalyzed: false
PackageLicenseConcluded: Zlib
PackageLicenseDeclared: Zlib

##### Package: apk-tools

PackageName: apk-tools
SPDXID: SPDXRef-26c274652190d87f
PackageVersion: 2.12.7-r3
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: libretls

PackageName: libretls
SPDXID: SPDXRef-2b021966d19a8211
PackageVersion: 3.3.4-r3
FilesAnalyzed: false
PackageLicenseConcluded: ISC AND (BSD-3-Clause OR MIT)
PackageLicenseDeclared: ISC AND (BSD-3-Clause OR MIT)

##### Package: busybox

PackageName: busybox
SPDXID: SPDXRef-317ce3476703f20d
PackageVersion: 1.34.1-r5
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: libcrypto1.1

PackageName: libcrypto1.1
SPDXID: SPDXRef-34f407fb4dbd67f4
PackageVersion: 1.1.1n-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: libc-utils

PackageName: libc-utils
SPDXID: SPDXRef-4bbc1cb449d54083
PackageVersion: 0.7.2-r3
FilesAnalyzed: false
PackageLicenseConcluded: BSD-2-Clause AND BSD-3-Clause
PackageLicenseDeclared: BSD-2-Clause AND BSD-3-Clause

##### Package: alpine-keys

PackageName: alpine-keys
SPDXID: SPDXRef-a3bdd174be1456b6
PackageVersion: 2.4-r1
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: ca-certificates-bundle

PackageName: ca-certificates-bundle
SPDXID: SPDXRef-ac6472ba26fb991c
PackageVersion: 20211220-r0
FilesAnalyzed: false
PackageLicenseConcluded: MPL-2.0 AND MIT
PackageLicenseDeclared: MPL-2.0 AND MIT

##### Package: libssl1.1

PackageName: libssl1.1
SPDXID: SPDXRef-b2d1b1d70fe90f7d
PackageVersion: 1.1.1n-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: scanelf

PackageName: scanelf
SPDXID: SPDXRef-c617077ba6649520
PackageVersion: 1.3.3-r0
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: musl

PackageName: musl
SPDXID: SPDXRef-ca80b810029cde0e
PackageVersion: 1.2.2-r7
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: alpine-baselayout

PackageName: alpine-baselayout
SPDXID: SPDXRef-d782e64751ba9faa
PackageVersion: 3.2.0-r18
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: musl-utils

PackageName: musl-utils
SPDXID: SPDXRef-e5e8a237f6162e22
PackageVersion: 1.2.2-r7
FilesAnalyzed: false
PackageLicenseConcluded: MIT BSD GPL2+
PackageLicenseDeclared: MIT BSD GPL2+

##### Package: ssl_client

PackageName: ssl_client
SPDXID: SPDXRef-fdf0ce84f6337be4
PackageVersion: 1.34.1-r5
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only
```

</details>

SPDX-JSON format is also supported by using `spdx-json` with the `--format` option.

```
$ trivy image --format spdx-json --output result.spdx.json alpine:3.15
```

<details>
<summary>Result</summary>

```
$ cat result.spdx.json | jq .
{
	"SPDXID": "SPDXRef-DOCUMENT",
	"creationInfo": {
		"created": "2022-04-28T08:16:55.328255Z",
		"creators": [
			"Tool: trivy-0.38.1",
			"Organization: aquasecurity"
		]
	},
	"dataLicense": "CC0-1.0",
	"documentNamespace": "http://aquasecurity.github.io/trivy/container_image/alpine:3.15-d9549e3a-a4c5-4ee3-8bde-8c78d451fbe7",
	"name": "alpine:3.15",
	"packages": [
		{
			"SPDXID": "SPDXRef-12bc938ac028a5e1",
			"filesAnalyzed": false,
			"licenseConcluded": "Zlib",
			"licenseDeclared": "Zlib",
			"name": "zlib",
			"versionInfo": "1.2.12-r0"
		},
		{
			"SPDXID": "SPDXRef-26c274652190d87f",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "apk-tools",
			"versionInfo": "2.12.7-r3"
		},
		{
			"SPDXID": "SPDXRef-2b021966d19a8211",
			"filesAnalyzed": false,
			"licenseConcluded": "ISC AND (BSD-3-Clause OR MIT)",
			"licenseDeclared": "ISC AND (BSD-3-Clause OR MIT)",
			"name": "libretls",
			"versionInfo": "3.3.4-r3"
		},
		{
			"SPDXID": "SPDXRef-317ce3476703f20d",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "busybox",
			"versionInfo": "1.34.1-r5"
		},
		{
			"SPDXID": "SPDXRef-34f407fb4dbd67f4",
			"filesAnalyzed": false,
			"licenseConcluded": "OpenSSL",
			"licenseDeclared": "OpenSSL",
			"name": "libcrypto1.1",
			"versionInfo": "1.1.1n-r0"
		},
		{
			"SPDXID": "SPDXRef-4bbc1cb449d54083",
			"filesAnalyzed": false,
			"licenseConcluded": "BSD-2-Clause AND BSD-3-Clause",
			"licenseDeclared": "BSD-2-Clause AND BSD-3-Clause",
			"name": "libc-utils",
			"versionInfo": "0.7.2-r3"
		},
		{
			"SPDXID": "SPDXRef-a3bdd174be1456b6",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"licenseDeclared": "MIT",
			"name": "alpine-keys",
			"versionInfo": "2.4-r1"
		},
		{
			"SPDXID": "SPDXRef-ac6472ba26fb991c",
			"filesAnalyzed": false,
			"licenseConcluded": "MPL-2.0 AND MIT",
			"licenseDeclared": "MPL-2.0 AND MIT",
			"name": "ca-certificates-bundle",
			"versionInfo": "20211220-r0"
		},
		{
			"SPDXID": "SPDXRef-b2d1b1d70fe90f7d",
			"filesAnalyzed": false,
			"licenseConcluded": "OpenSSL",
			"licenseDeclared": "OpenSSL",
			"name": "libssl1.1",
			"versionInfo": "1.1.1n-r0"
		},
		{
			"SPDXID": "SPDXRef-c617077ba6649520",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "scanelf",
			"versionInfo": "1.3.3-r0"
		},
		{
			"SPDXID": "SPDXRef-ca80b810029cde0e",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"licenseDeclared": "MIT",
			"name": "musl",
			"versionInfo": "1.2.2-r7"
		},
		{
			"SPDXID": "SPDXRef-d782e64751ba9faa",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "alpine-baselayout",
			"versionInfo": "3.2.0-r18"
		},
		{
			"SPDXID": "SPDXRef-e5e8a237f6162e22",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT BSD GPL2+",
			"licenseDeclared": "MIT BSD GPL2+",
			"name": "musl-utils",
			"versionInfo": "1.2.2-r7"
		},
		{
			"SPDXID": "SPDXRef-fdf0ce84f6337be4",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "ssl_client",
			"versionInfo": "1.34.1-r5"
		}
	],
	"spdxVersion": "SPDX-2.2"
}
```

</details>

## Scanning
Trivy can take SBOM documents as input for scanning.
See [here](../target/sbom.md) for more details.

Also, Trivy searches for SBOM files in container images.

```bash
$ trivy image bitnami/elasticsearch:8.7.1
```

For example, [Bitnami images](https://github.com/bitnami/containers) contain SBOM files in `/opt/bitnami` directory.
Trivy automatically detects the SBOM files and uses them for scanning.
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


[spdx]: https://spdx.dev/wp-content/uploads/sites/41/2020/08/SPDX-specification-2-2.pdf

[cyclonedx]: https://cyclonedx.org/
[sbom]: https://cyclonedx.org/capabilities/sbom/
[bov]: https://cyclonedx.org/capabilities/bov/

[os_packages]: ../scanner/vulnerability.md#os-packages
[language_packages]: ../scanner/vulnerability.md#language-specific-packages

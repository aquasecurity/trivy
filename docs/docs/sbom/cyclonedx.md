# CycloneDX generation
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
  "specVersion": "1.4",
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


[cyclonedx]: https://cyclonedx.org/
[sbom]: https://cyclonedx.org/capabilities/sbom/
[bov]: https://cyclonedx.org/capabilities/bov/

# Reporting

## Format
Trivy supports the following formats:

- Table
- JSON
- [SARIF][sarif-home]
- Template
- SBOM
- GitHub dependency snapshot

### Table (Default)

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

```bash
$ trivy image -f table golang:1.22.11-alpine3.20
```

<details>
<summary>Result</summary>

```
...

Report Summary

┌─────────────────────────────────────────────┬──────────┬─────────────────┬─────────┐
│                   Target                    │   Type   │ Vulnerabilities │ Secrets │
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ golang:1.22.11-alpine3.20 (alpine 3.20.5)   │  alpine  │        6        │    -    │
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ usr/local/go/bin/go                         │ gobinary │        1        │    -    │
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
...
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ usr/local/go/pkg/tool/linux_amd64/vet       │ gobinary │        1        │    -    │
└─────────────────────────────────────────────┴──────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)


golang:1.22.11-alpine3.20 (alpine 3.20.5)

Total: 6 (UNKNOWN: 2, LOW: 0, MEDIUM: 2, HIGH: 2, CRITICAL: 0)

┌────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬─────────────────────────────────────────────────────────────┐
│  Library   │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                            Title                            │
├────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│ libcrypto3 │ CVE-2024-12797 │ HIGH     │ fixed  │ 3.3.2-r1          │ 3.3.3-r0      │ openssl: RFC7250 handshakes with unauthenticated servers    │
│            │                │          │        │                   │               │ don't abort as expected                                     │
│            │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-12797                  │
│            ├────────────────┼──────────┤        │                   ├───────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-13176 │ MEDIUM   │        │                   │ 3.3.2-r2      │ openssl: Timing side-channel in ECDSA signature computation │
│            │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-13176                  │
├────────────┼────────────────┼──────────┤        │                   ├───────────────┼─────────────────────────────────────────────────────────────┤
│ libssl3    │ CVE-2024-12797 │ HIGH     │        │                   │ 3.3.3-r0      │ openssl: RFC7250 handshakes with unauthenticated servers    │
│            │                │          │        │                   │               │ don't abort as expected                                     │
│            │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-12797                  │
│            ├────────────────┼──────────┤        │                   ├───────────────┼─────────────────────────────────────────────────────────────┤
│            │ CVE-2024-13176 │ MEDIUM   │        │                   │ 3.3.2-r2      │ openssl: Timing side-channel in ECDSA signature computation │
│            │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2024-13176                  │
├────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│ musl       │ CVE-2025-26519 │ UNKNOWN  │        │ 1.2.5-r0          │ 1.2.5-r1      │ musl libc 0.9.13 through 1.2.5 before 1.2.6 has an          │
│            │                │          │        │                   │               │ out-of-bounds write ......                                  │
│            │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2025-26519                  │
├────────────┤                │          │        │                   │               │                                                             │
│ musl-utils │                │          │        │                   │               │                                                             │
│            │                │          │        │                   │               │                                                             │
│            │                │          │        │                   │               │                                                             │
└────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴─────────────────────────────────────────────────────────────┘

usr/local/go/bin/go (gobinary)

Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

┌─────────┬────────────────┬──────────┬────────┬───────────────────┬──────────────────────────────┬──────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Status │ Installed Version │        Fixed Version         │                            Title                             │
├─────────┼────────────────┼──────────┼────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ stdlib  │ CVE-2025-22866 │ MEDIUM   │ fixed  │ v1.22.11          │ 1.22.12, 1.23.6, 1.24.0-rc.3 │ crypto/internal/nistec: golang: Timing sidechannel for P-256 │
│         │                │          │        │                   │                              │ on ppc64le in crypto/internal/nistec                         │
│         │                │          │        │                   │                              │ https://avd.aquasec.com/nvd/cve-2025-22866                   │
└─────────┴────────────────┴──────────┴────────┴───────────────────┴──────────────────────────────┴──────────────────────────────────────────────────────────────┘

...
```

</details>

#### Table mode
!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports the following modes for `table` format:

|             Mode             | Enabled by default |
|:----------------------------:|:-----------------:|
|  [summary](#summary-table)   |       ✓[^1]       |
| [detailed](#detailed-tables) |         ✓         |

You can use `--table-mode` flag to enable/disable table mode(s). 


##### Summary table
Summary table contains general information about the scan performed.

Nuances of table contents:

- Table includes columns for enabled [scanners](../references/terminology.md#scanner) only. Use `--scanners` flag to enable/disable scanners.
- Table includes separate lines for the same targets but different scanners.
    - `-` means that the scanner didn't scan this target.
    - `0` means that the scanner scanned this target, but found no security issues.

!!! Note
    For the secret/license scanner, the Trivy report contains only findings.
    Therefore, we can’t say for sure whether Trivy scanned at least one file or simply didn’t find any findings.
    That’s why, for these scanners, the summary table uses “-” if no findings are found.

<details>
<summary>Report Summary</summary>

```
┌───────────────────────┬────────────┬─────────────────┬───────────────────┬─────────┬──────────┐
│        Target         │    Type    │ Vulnerabilities │ Misconfigurations │ Secrets │ Licenses │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ test (alpine 3.20.3)  │   alpine   │        2        │         -         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Java                  │    jar     │        2        │         -         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ app/Dockerfile        │ dockerfile │        -        │         2         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ requirements.txt      │    text    │        0        │         -         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ requirements.txt      │    text    │        -        │         -         │    1    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ OS Packages           │     -      │        -        │         -         │    -    │    1     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Java                  │     -      │        -        │         -         │    -    │    0     │
└───────────────────────┴────────────┴─────────────────┴───────────────────┴─────────┴──────────┘
```

</details>

##### Detailed tables
Detailed tables contain information about found security issues for each target with more detailed information (CVE-ID, severity, version, etc.).

<details>
<summary>Detailed tables</summary>

```

usr/local/go/bin/go (gobinary)

Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

┌─────────┬────────────────┬──────────┬────────┬───────────────────┬──────────────────────────────┬──────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Status │ Installed Version │        Fixed Version         │                            Title                             │
├─────────┼────────────────┼──────────┼────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ stdlib  │ CVE-2025-22866 │ MEDIUM   │ fixed  │ v1.22.11          │ 1.22.12, 1.23.6, 1.24.0-rc.3 │ crypto/internal/nistec: golang: Timing sidechannel for P-256 │
│         │                │          │        │                   │                              │ on ppc64le in crypto/internal/nistec                         │
│         │                │          │        │                   │                              │ https://avd.aquasec.com/nvd/cve-2025-22866                   │
└─────────┴────────────────┴──────────┴────────┴───────────────────┴──────────────────────────────┴──────────────────────────────────────────────────────────────┘

```
</details>

#### Show origins of vulnerable dependencies

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |           |
|      Secret      |           |
|     License      |           |

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Modern software development relies on the use of third-party libraries.
Third-party dependencies also depend on others so a list of dependencies can be represented as a dependency graph.
In some cases, vulnerable dependencies are not linked directly, and it requires analyses of the tree.
To make this task simpler Trivy can show a dependency origin tree with the `--dependency-tree` flag.
This flag is only available with the `--format table` flag.

The following OS package managers are currently supported:

| OS Package Managers |
|---------------------|
| apk                 |
| dpkg                |
| rpm                 |

The following languages are currently supported:

| Language | File                                       |
|----------|--------------------------------------------|
| Node.js  | [package-lock.json][nodejs-package-lock]   |
|          | [pnpm-lock.yaml][pnpm-lock]                |
|          | [yarn.lock][yarn-lock]                     |
| .NET     | [packages.lock.json][dotnet-packages-lock] |
| Python   | [poetry.lock][poetry-lock]                 |
|          | [uv.lock][uv-lock]                         |
| Ruby     | [Gemfile.lock][gemfile-lock]               |
| Rust     | [cargo-auditable binaries][cargo-binaries] |
| Go       | [go.mod][go-mod]                           |
| PHP      | [composer.lock][composer-lock]             |
| Java     | [pom.xml][pom-xml]                         |
|          | [*gradle.lockfile][gradle-lockfile]        |
|          | [*.sbt.lock][sbt-lockfile]                 |
| Dart     | [pubspec.lock][pubspec-lock]               |

This tree is the reverse of the dependency graph.
However, if you want to resolve a vulnerability in a particular indirect dependency, the reversed tree is useful to know where that dependency comes from and identify which package you actually need to update.

In table output, it looks like:

```sh
$ trivy fs --severity HIGH,CRITICAL --dependency-tree /path/to/your_node_project

package-lock.json (npm)
=======================
Total: 2 (HIGH: 1, CRITICAL: 1)

┌──────────────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│     Library      │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├──────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ follow-redirects │ CVE-2022-0155  │ HIGH     │ 1.14.6            │ 1.14.7        │ follow-redirects: Exposure of Private Personal Information │
│                  │                │          │                   │               │ to an Unauthorized Actor                                   │
│                  │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-0155                  │
├──────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ glob-parent      │ CVE-2020-28469 │ CRITICAL │ 3.1.0             │ 5.1.2         │ nodejs-glob-parent: Regular expression denial of service   │
│                  │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-28469                 │
└──────────────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘

Dependency Origin Tree (Reversed)
=================================
package-lock.json
├── follow-redirects@1.14.6, (HIGH: 1, CRITICAL: 0)
│   └── axios@0.21.4
└── glob-parent@3.1.0, (HIGH: 0, CRITICAL: 1)
    └── chokidar@2.1.8
        └── watchpack-chokidar2@2.0.1
            └── watchpack@1.7.5
                └── webpack@4.46.0
                    └── cra-append-sw@2.7.0
```

Vulnerable dependencies are shown in the top level of the tree.
Lower levels show how those vulnerabilities are introduced.
In the example above **axios@0.21.4** included in the project directly depends on the vulnerable **follow-redirects@1.14.6**.
Also, **glob-parent@3.1.0** with some vulnerabilities is included through chain of dependencies that is added by **cra-append-sw@2.7.0**.

Then, you can try to update **axios@0.21.4** and **cra-append-sw@2.7.0** to resolve vulnerabilities in **follow-redirects@1.14.6** and **glob-parent@3.1.0**.

### JSON

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

```
$ trivy image -f json -o results.json alpine:latest
```

<details>
<summary>JSON</summary>

```
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-12-26T21:58:15.943876+05:30",
  "ArtifactName": "alpine:latest",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "alpine",
      "Name": "3.20.3"
    },
    "ImageID": "sha256:511a44083d3a23416fadc62847c45d14c25cbace86e7a72b2b350436978a0450",
    "DiffIDs": [
      "sha256:651d9022c23486dfbd396c13db293af6845731cbd098a5f5606db4bc9f5573e8"
    ],
    "RepoTags": [
      "alpine:latest"
    ],
    "RepoDigests": [
      "alpine@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a"
    ],
    "ImageConfig": {
      "architecture": "arm64",
      "created": "2024-09-06T12:05:36Z",
      "history": [
        {
          "created": "2024-09-06T12:05:36Z",
          "created_by": "ADD alpine-minirootfs-3.20.3-aarch64.tar.gz / # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-06T12:05:36Z",
          "created_by": "CMD [\"/bin/sh\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:651d9022c23486dfbd396c13db293af6845731cbd098a5f5606db4bc9f5573e8"
        ]
      },
      "config": {
        "Cmd": [
          "/bin/sh"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "WorkingDir": "/",
        "ArgsEscaped": true
      }
    }
  },
  "Results": [
    {
      "Target": "alpine:latest (alpine 3.20.3)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-9143",
          "PkgID": "libcrypto3@3.3.2-r0",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64\u0026distro=3.20.3",
            "UID": "f705555b49cd2259"
          },
          "InstalledVersion": "3.3.2-r0",
          "FixedVersion": "3.3.2-r1",
          "Status": "fixed",
          "Layer": {
            "DiffID": "sha256:651d9022c23486dfbd396c13db293af6845731cbd098a5f5606db4bc9f5573e8"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-9143",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Low-level invalid GF(2^m) parameters lead to OOB memory access",
          "Description": "Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted\nexplicit values for the field polynomial can lead to out-of-bounds memory reads\nor writes.\n\nImpact summary: Out of bound memory writes can lead to an application crash or\neven a possibility of a remote code execution, however, in all the protocols\ninvolving Elliptic Curve Cryptography that we're aware of, either only \"named\ncurves\" are supported, or, if explicit curve parameters are supported, they\nspecify an X9.62 encoding of binary (GF(2^m)) curves that can't represent\nproblematic input values. Thus the likelihood of existence of a vulnerable\napplication is low.\n\nIn particular, the X9.62 encoding is used for ECC keys in X.509 certificates,\nso problematic inputs cannot occur in the context of processing X.509\ncertificates.  Any problematic use-cases would have to be using an \"exotic\"\ncurve encoding.\n\nThe affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(),\nand various supporting BN_GF2m_*() functions.\n\nApplications working with \"exotic\" explicit binary (GF(2^m)) curve parameters,\nthat make it possible to represent invalid field polynomials with a zero\nconstant term, via the above or similar APIs, may terminate abruptly as a\nresult of reading or writing outside of array bounds.  Remote code execution\ncannot easily be ruled out.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-9143",
            "https://github.com/openssl/openssl/commit/72ae83ad214d2eef262461365a1975707f862712",
            "https://github.com/openssl/openssl/commit/bc7e04d7c8d509fb78fc0e285aa948fb0da04700",
            "https://github.com/openssl/openssl/commit/c0d3e4d32d2805f49bec30547f225bc4d092e1f4",
            "https://github.com/openssl/openssl/commit/fdf6723362ca51bd883295efe206cb5b1cfa5154",
            "https://github.openssl.org/openssl/extended-releases/commit/8efc0cbaa8ebba8e116f7b81a876a4123594d86a",
            "https://github.openssl.org/openssl/extended-releases/commit/9d576994cec2b7aa37a91740ea7e680810957e41",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-9143",
            "https://openssl-library.org/news/secadv/20241016.txt",
            "https://www.cve.org/CVERecord?id=CVE-2024-9143"
          ],
          "PublishedDate": "2024-10-16T17:15:18.13Z",
          "LastModifiedDate": "2024-11-08T16:35:21.58Z"
        },
        {
          "VulnerabilityID": "CVE-2024-9143",
          "PkgID": "libssl3@3.3.2-r0",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.3.2-r0?arch=aarch64\u0026distro=3.20.3",
            "UID": "c4a39ef718e71832"
          },
          "InstalledVersion": "3.3.2-r0",
          "FixedVersion": "3.3.2-r1",
          "Status": "fixed",
          "Layer": {
            "DiffID": "sha256:651d9022c23486dfbd396c13db293af6845731cbd098a5f5606db4bc9f5573e8"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-9143",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Low-level invalid GF(2^m) parameters lead to OOB memory access",
          "Description": "Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted\nexplicit values for the field polynomial can lead to out-of-bounds memory reads\nor writes.\n\nImpact summary: Out of bound memory writes can lead to an application crash or\neven a possibility of a remote code execution, however, in all the protocols\ninvolving Elliptic Curve Cryptography that we're aware of, either only \"named\ncurves\" are supported, or, if explicit curve parameters are supported, they\nspecify an X9.62 encoding of binary (GF(2^m)) curves that can't represent\nproblematic input values. Thus the likelihood of existence of a vulnerable\napplication is low.\n\nIn particular, the X9.62 encoding is used for ECC keys in X.509 certificates,\nso problematic inputs cannot occur in the context of processing X.509\ncertificates.  Any problematic use-cases would have to be using an \"exotic\"\ncurve encoding.\n\nThe affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(),\nand various supporting BN_GF2m_*() functions.\n\nApplications working with \"exotic\" explicit binary (GF(2^m)) curve parameters,\nthat make it possible to represent invalid field polynomials with a zero\nconstant term, via the above or similar APIs, may terminate abruptly as a\nresult of reading or writing outside of array bounds.  Remote code execution\ncannot easily be ruled out.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-9143",
            "https://github.com/openssl/openssl/commit/72ae83ad214d2eef262461365a1975707f862712",
            "https://github.com/openssl/openssl/commit/bc7e04d7c8d509fb78fc0e285aa948fb0da04700",
            "https://github.com/openssl/openssl/commit/c0d3e4d32d2805f49bec30547f225bc4d092e1f4",
            "https://github.com/openssl/openssl/commit/fdf6723362ca51bd883295efe206cb5b1cfa5154",
            "https://github.openssl.org/openssl/extended-releases/commit/8efc0cbaa8ebba8e116f7b81a876a4123594d86a",
            "https://github.openssl.org/openssl/extended-releases/commit/9d576994cec2b7aa37a91740ea7e680810957e41",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-9143",
            "https://openssl-library.org/news/secadv/20241016.txt",
            "https://www.cve.org/CVERecord?id=CVE-2024-9143"
          ],
          "PublishedDate": "2024-10-16T17:15:18.13Z",
          "LastModifiedDate": "2024-11-08T16:35:21.58Z"
        }
      ]
    }
  ]
}

```

</details>

`VulnerabilityID`, `PkgName`, `InstalledVersion`, and `Severity` in `Vulnerabilities` are always filled with values, but other fields might be empty.

### SARIF
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

[SARIF][sarif-home] (Static Analysis Results Interchange Format) complying with [SARIF 2.1.0 OASIS standard][sarif-spec] can be generated with the `--format sarif` flag.

```
$ trivy image --format sarif -o report.sarif  golang:1.12-alpine
```

This SARIF file can be uploaded to several platforms, including:

- [GitHub code scanning results][sarif-github], and there is a [Trivy GitHub Action][action] for automating this process
- [SonarQube][sarif-sonar]

### GitHub dependency snapshot
Trivy supports the following packages:

- [OS packages][os_packages]
- [Language-specific packages][language_packages]

[GitHub dependency snapshots][github-sbom] can be generated with the `--format github` flag.

```
$ trivy image --format github -o report.gsbom alpine
```

This snapshot file can be [submitted][github-sbom-submit] to your GitHub repository.

### Template

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

#### Custom Template

{% raw %}
```
$ trivy image --format template --template "{{ range . }} {{ .Target }} {{ end }}" golang:1.12-alpine
```
{% endraw %}

<details>
<summary>Result</summary>

```
2020-01-02T18:02:32.856+0100    INFO    Detecting Alpine vulnerabilities...
 golang:1.12-alpine (alpine 3.10.2)
```
</details>

You can compute different figures within the template using [sprig][sprig] functions.
As an example you can summarize the different classes of issues:


{% raw %}
```
$ trivy image --format template --template '{{- $critical := 0 }}{{- $high := 0 }}{{- range . }}{{- range .Vulnerabilities }}{{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}{{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}{{- end }}{{- end }}Critical: {{ $critical }}, High: {{ $high }}' golang:1.12-alpine
```
{% endraw %}

<details>
<summary>Result</summary>

```
Critical: 0, High: 2
```
</details>

For other features of sprig, see the official [sprig][sprig] documentation.

#### Load templates from a file
You can load templates from a file prefixing the template path with an @.

```
$ trivy image --format template --template "@/path/to/template" golang:1.12-alpine
```

#### Default Templates

If Trivy is installed using rpm then default templates can be found at `/usr/local/share/trivy/templates`.

##### JUnit
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

In the following example using the template `junit.tpl` XML can be generated.
```
$ trivy image --format template --template "@contrib/junit.tpl" -o junit-report.xml  golang:1.12-alpine
```

##### ASFF
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |           |

Trivy also supports an [ASFF template for reporting findings to AWS Security Hub][asff]

##### HTML
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |           |
|     License      |           |

```
$ trivy image --format template --template "@contrib/html.tpl" -o report.html golang:1.12-alpine
```

The following example shows use of default HTML template when Trivy is installed using rpm.

```
$ trivy image --format template --template "@/usr/local/share/trivy/templates/html.tpl" -o report.html golang:1.12-alpine
```

### SBOM
See [here](../supply-chain/sbom.md) for details.

## Output
Trivy supports the following output destinations:

- File
- Plugin

### File
By specifying `--output <file_path>`, you can output the results to a file.
Here is an example:

```
$ trivy image --format json --output result.json debian:12
```

### Plugin
!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Plugins capable of receiving Trivy's results via standard input, called "output plugin", can be seamlessly invoked using the `--output` flag.

```
$ trivy <target> [--format <format>] --output plugin=<plugin_name> [--output-plugin-arg <plugin_flags>] <target_name>
```

This is useful for cases where you want to convert the output into a custom format, or when you want to send the output somewhere.
For more details, please check [here](../plugin/user-guide.md#output-mode-support).

## Converting
To generate multiple reports, you can generate the JSON report first and convert it to other formats with the `convert` subcommand.

```shell
$ trivy image --format json -o result.json debian:11
$ trivy convert --format cyclonedx --output result.cdx result.json
```

[Filtering options](./filtering.md) such as `--severity` are also available with `convert`.

```shell
# Output all severities in JSON
$ trivy image --format json -o result.json debian:11

# Output only critical issues in table format
$ trivy convert --format table --severity CRITICAL result.json
```

!!! note
    JSON reports from "trivy k8s" are not yet supported.

[cargo-auditable]: https://github.com/rust-secure-code/cargo-auditable/
[action]: https://github.com/aquasecurity/trivy-action
[asff]: ../../tutorials/integrations/aws-security-hub.md
[sarif-home]: https://sarifweb.azurewebsites.net
[sarif-spec]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
[sarif-github]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning
[sarif-sonar]: https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/importing-issues-from-sarif-reports/
[sprig]: http://masterminds.github.io/sprig/
[github-sbom]: https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#about-dependency-submissions
[github-sbom-submit]: https://docs.github.com/en/rest/dependency-graph/dependency-submission?apiVersion=2022-11-28#create-a-snapshot-of-dependencies-for-a-repository

[os_packages]: ../scanner/vulnerability.md#os-packages
[language_packages]: ../scanner/vulnerability.md#language-specific-packages

[nodejs-package-lock]: ../coverage/language/nodejs.md#npm
[pnpm-lock]: ../coverage/language/nodejs.md#pnpm
[yarn-lock]: ../coverage/language/nodejs.md#yarn
[dotnet-packages-lock]: ../coverage/language/dotnet.md#packageslockjson
[poetry-lock]: ../coverage/language/python.md#poetry
[uv-lock]: ../coverage/language/python.md#uv
[gemfile-lock]: ../coverage/language/ruby.md#bundler
[go-mod]: ../coverage/language/golang.md#go-module
[composer-lock]: ../coverage/language/php.md#composerlock
[pom-xml]: ../coverage/language/java.md#pomxml
[gradle-lockfile]: ../coverage/language/java.md#gradlelock
[sbt-lockfile]: ../coverage/language/java.md#sbt
[pubspec-lock]: ../coverage/language/dart.md#dart
[cargo-binaries]: ../coverage/language/rust.md#binaries

[^1]: To show summary table in `convert` mode - you need to enable the scanners used during JSON report generation.
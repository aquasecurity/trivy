# SPDX generation

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
DocumentNamespace: http://aquasecurity.github.io/trivy/container_image/alpine:3.15-bebf6b19-a94c-4e2c-af44-065f63923f48
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


[spdx]: https://spdx.dev/wp-content/uploads/sites/41/2020/08/SPDX-specification-2-2.pdf

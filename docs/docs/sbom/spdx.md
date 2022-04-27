# SPDX

Trivy generates reports in the [SPDX][spdx] format.

You can use the regular subcommands (like `image`, `fs` and `rootfs`) and specify `spdx` with the `--format` option.

```
$ trivy image --format spdx --output result.spdx alpine:3.15
```

<details>
<summary>Result</summary>

```
$ cat result.spdx | jq .
SPDXVersion: SPDX-2.1
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: alpine:3.15
DocumentNamespace: http://aquasecurity.github.io/trivy/container_image/alpine:3.15-3a658e97-3e0b-4a6c-abbc-9db23628a952
Creator: Organization: aquasecurity
Creator: Tool: trivy
Created: 2022-04-27T11:04:41.905118Z

##### Package: alpine-baselayout

PackageName: alpine-baselayout
SPDXID: SPDXRef-alpine-baselayout-3.2.0-r18
PackageVersion: 3.2.0-r18
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: alpine-keys

PackageName: alpine-keys
SPDXID: SPDXRef-alpine-keys-2.4-r1
PackageVersion: 2.4-r1
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: apk-tools

PackageName: apk-tools
SPDXID: SPDXRef-apk-tools-2.12.7-r3
PackageVersion: 2.12.7-r3
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: busybox

PackageName: busybox
SPDXID: SPDXRef-busybox-1.34.1-r5
PackageVersion: 1.34.1-r5
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: ca-certificates-bundle

PackageName: ca-certificates-bundle
SPDXID: SPDXRef-ca-certificates-bundle-20211220-r0
PackageVersion: 20211220-r0
FilesAnalyzed: false
PackageLicenseConcluded: MPL-2.0 AND MIT
PackageLicenseDeclared: MPL-2.0 AND MIT

##### Package: libc-utils

PackageName: libc-utils
SPDXID: SPDXRef-libc-utils-0.7.2-r3
PackageVersion: 0.7.2-r3
FilesAnalyzed: false
PackageLicenseConcluded: BSD-2-Clause AND BSD-3-Clause
PackageLicenseDeclared: BSD-2-Clause AND BSD-3-Clause

##### Package: libcrypto1.1

PackageName: libcrypto1.1
SPDXID: SPDXRef-libcrypto1.1-1.1.1n-r0
PackageVersion: 1.1.1n-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: libretls

PackageName: libretls
SPDXID: SPDXRef-libretls-3.3.4-r3
PackageVersion: 3.3.4-r3
FilesAnalyzed: false
PackageLicenseConcluded: ISC AND (BSD-3-Clause OR MIT)
PackageLicenseDeclared: ISC AND (BSD-3-Clause OR MIT)

##### Package: libssl1.1

PackageName: libssl1.1
SPDXID: SPDXRef-libssl1.1-1.1.1n-r0
PackageVersion: 1.1.1n-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: musl

PackageName: musl
SPDXID: SPDXRef-musl-1.2.2-r7
PackageVersion: 1.2.2-r7
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: musl-utils

PackageName: musl-utils
SPDXID: SPDXRef-musl-utils-1.2.2-r7
PackageVersion: 1.2.2-r7
FilesAnalyzed: false
PackageLicenseConcluded: MIT BSD GPL2+
PackageLicenseDeclared: MIT BSD GPL2+

##### Package: scanelf

PackageName: scanelf
SPDXID: SPDXRef-scanelf-1.3.3-r0
PackageVersion: 1.3.3-r0
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: ssl_client

PackageName: ssl_client
SPDXID: SPDXRef-ssl_client-1.34.1-r5
PackageVersion: 1.34.1-r5
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: zlib

PackageName: zlib
SPDXID: SPDXRef-zlib-1.2.12-r0
PackageVersion: 1.2.12-r0
FilesAnalyzed: false
PackageLicenseConcluded: Zlib
PackageLicenseDeclared: Zlib
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
		"created": "2022-04-27T11:06:33.057942Z",
		"creators": [
			"Tool: trivy",
			"Organization: aquasecurity"
		]
	},
	"dataLicense": "CC0-1.0",
	"documentNamespace": "http://aquasecurity.github.io/trivy/container_image/alpine:3.15-9bfb6660-101c-443c-a8ed-e50f746d5395",
	"name": "alpine:3.15",
	"packages": [
		{
			"SPDXID": "SPDXRef-alpine-baselayout-3.2.0-r18",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "alpine-baselayout",
			"versionInfo": "3.2.0-r18"
		},
		{
			"SPDXID": "SPDXRef-alpine-keys-2.4-r1",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"licenseDeclared": "MIT",
			"name": "alpine-keys",
			"versionInfo": "2.4-r1"
		},
		{
			"SPDXID": "SPDXRef-apk-tools-2.12.7-r3",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "apk-tools",
			"versionInfo": "2.12.7-r3"
		},
		{
			"SPDXID": "SPDXRef-busybox-1.34.1-r5",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "busybox",
			"versionInfo": "1.34.1-r5"
		},
		{
			"SPDXID": "SPDXRef-ca-certificates-bundle-20211220-r0",
			"filesAnalyzed": false,
			"licenseConcluded": "MPL-2.0 AND MIT",
			"licenseDeclared": "MPL-2.0 AND MIT",
			"name": "ca-certificates-bundle",
			"versionInfo": "20211220-r0"
		},
		{
			"SPDXID": "SPDXRef-libc-utils-0.7.2-r3",
			"filesAnalyzed": false,
			"licenseConcluded": "BSD-2-Clause AND BSD-3-Clause",
			"licenseDeclared": "BSD-2-Clause AND BSD-3-Clause",
			"name": "libc-utils",
			"versionInfo": "0.7.2-r3"
		},
		{
			"SPDXID": "SPDXRef-libcrypto1.1-1.1.1n-r0",
			"filesAnalyzed": false,
			"licenseConcluded": "OpenSSL",
			"licenseDeclared": "OpenSSL",
			"name": "libcrypto1.1",
			"versionInfo": "1.1.1n-r0"
		},
		{
			"SPDXID": "SPDXRef-libretls-3.3.4-r3",
			"filesAnalyzed": false,
			"licenseConcluded": "ISC AND (BSD-3-Clause OR MIT)",
			"licenseDeclared": "ISC AND (BSD-3-Clause OR MIT)",
			"name": "libretls",
			"versionInfo": "3.3.4-r3"
		},
		{
			"SPDXID": "SPDXRef-libssl1.1-1.1.1n-r0",
			"filesAnalyzed": false,
			"licenseConcluded": "OpenSSL",
			"licenseDeclared": "OpenSSL",
			"name": "libssl1.1",
			"versionInfo": "1.1.1n-r0"
		},
		{
			"SPDXID": "SPDXRef-musl-1.2.2-r7",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT",
			"licenseDeclared": "MIT",
			"name": "musl",
			"versionInfo": "1.2.2-r7"
		},
		{
			"SPDXID": "SPDXRef-musl-utils-1.2.2-r7",
			"filesAnalyzed": false,
			"licenseConcluded": "MIT BSD GPL2+",
			"licenseDeclared": "MIT BSD GPL2+",
			"name": "musl-utils",
			"versionInfo": "1.2.2-r7"
		},
		{
			"SPDXID": "SPDXRef-scanelf-1.3.3-r0",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "scanelf",
			"versionInfo": "1.3.3-r0"
		},
		{
			"SPDXID": "SPDXRef-ssl_client-1.34.1-r5",
			"filesAnalyzed": false,
			"licenseConcluded": "GPL-2.0-only",
			"licenseDeclared": "GPL-2.0-only",
			"name": "ssl_client",
			"versionInfo": "1.34.1-r5"
		},
		{
			"SPDXID": "SPDXRef-zlib-1.2.12-r0",
			"filesAnalyzed": false,
			"licenseConcluded": "Zlib",
			"licenseDeclared": "Zlib",
			"name": "zlib",
			"versionInfo": "1.2.12-r0"
		}
	],
	"spdxVersion": "SPDX-2.1"
}
```

</details>

[spdx]: https://spdx.dev/wp-content/uploads/sites/41/2020/08/SPDX-specification-2-2.pdf

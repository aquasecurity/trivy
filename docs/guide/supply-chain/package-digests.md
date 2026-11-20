# Package Digests

Trivy reports the digests it collects for a package. Each digest has an algorithm, a value and a source. The source tells where Trivy got the value and which bytes the value covers. Two digests with the same algorithm can cover different bytes.

| Source | Algorithm | Where the value comes from | What the value covers |
|---|---|---|---|
| `rpm-sigmd5` | MD5 | The `SIGMD5` tag of the RPM database | The header and the payload of the `.rpm` file, without the signature header |
| `dpkg-available-sha256` | SHA-256 | The `SHA256` field of `/var/lib/dpkg/available` | The whole `.deb` file |
| `apk-installed-db` | SHA-1, or MD5 in old databases | The `C:` field of `/lib/apk/db/installed` or `/usr/lib/apk/db/installed` | The compressed control section of the `.apk` file |
| `java-archive` | SHA-1 | Trivy computes it | The whole JAR, WAR, EAR or PAR file, including a nested one |
| `file-content` | SHA-1 | Trivy computes it | The metadata file that Trivy read, such as `METADATA`, `PKG-INFO`, `package.json`, a `.gemspec` file or a conda meta file. It does not cover the package archive. |
| `go-module-h1` | SHA-256 | The `go.sum` file or the build info of a Go binary | The list of the module files and their SHA-256 hashes. It does not match the SHA-256 of the module zip file. See [Module Checksums](../coverage/language/golang.md#module-checksums). |
| `sbom` | As stated in the SBOM | An SBOM that Trivy scanned, found in the target or fetched with `--sbom-sources`, for a hash without a `SourcedDigest` record | Unknown |
| `unknown` | Any | A JSON report of an older Trivy version, such as one passed to `trivy convert` | Unknown |

Trivy computes `java-archive` and `file-content` digests only for the SBOM formats: `cyclonedx`, `spdx` and `spdx-json`. Trivy does not verify any of the digests.

See [JSON](../configuration/reporting.md#json) and [SBOM](sbom.md#package-digests) for how the digests appear in each format.

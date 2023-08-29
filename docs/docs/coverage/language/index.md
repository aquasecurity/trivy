# Programming Language

Trivy supports programming languages for 

- [SBOM][sbom]
- [Vulnerabilities][vuln]
- [Licenses][license]

## Supported languages
The files analyzed vary depending on the target.
This is because Trivy primarily categorizes targets into two groups:

- Pre-build
- Post-build

If the target is a pre-build project, like a code repository, Trivy will analyze files used for building, such as lock files.
On the other hand, when the target is a post-build artifact, like a container image, Trivy will analyze installed package metadata like `.gemspec`, binary files, and so on.

| Language             | File                                                                                       | Image[^5] | Rootfs[^6] | Filesystem[^7] | Repository[^8] |
| -------------------- | ------------------------------------------------------------------------------------------ | :-------: | :--------: | :------------: | :------------: |
| [Ruby](ruby.md)      | Gemfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
|                      | gemspec                                                                                    |     ✅     |     ✅      |       -        |       -        |
| [Python](python.md)  | Pipfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
|                      | poetry.lock                                                                                |     -     |     -      |       ✅        |       ✅        |
|                      | requirements.txt                                                                           |     -     |     -      |       ✅        |       ✅        |
|                      | egg package[^1]                                                                            |     ✅     |     ✅      |       -        |       -        |
|                      | wheel package[^2]                                                                          |     ✅     |     ✅      |       -        |       -        |
|                      | conda package[^3]                                                                          |     ✅     |     ✅      |       -        |       -        |
| [PHP](php.md)        | composer.lock                                                                              |     ✅     |     ✅      |       ✅        |       ✅        |
| [Node.js](nodejs.md) | package-lock.json                                                                          |     -     |     -      |       ✅        |       ✅        |
|                      | yarn.lock                                                                                  |     -     |     -      |       ✅        |       ✅        |
|                      | pnpm-lock.yaml                                                                             |     -     |     -      |       ✅        |       ✅        |
|                      | package.json                                                                               |     ✅     |     ✅      |       -        |       -        |
| [.NET](dotnet.md)    | packages.lock.json                                                                         |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | packages.config                                                                            |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | .deps.json                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        |
| [Java](java.md)      | JAR/WAR/PAR/EAR[^4]                                                                        |     ✅     |     ✅      |       -        |       -        |
|                      | pom.xml                                                                                    |     -     |     -      |       ✅        |       ✅        |
|                      | *gradle.lockfile                                                                           |     -     |     -      |       ✅        |       ✅        |
| [Go](golang.md)      | Binaries built by Go                                                                       |     ✅     |     ✅      |       -        |       -        |
|                      | go.mod                                                                                     |     -     |     -      |       ✅        |       ✅        |
| [Rust](rust.md)      | Cargo.lock                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | Binaries built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) |     ✅     |     ✅      |       -        |       -        |
| [C/C++](c.md)        | conan.lock                                                                                 |     -     |     -      |       ✅        |       ✅        |
| [Elixir](elixir.md)  | mix.lock[^10]                                                                              |     -     |     -      |       ✅        |       ✅        |
| [Dart](dart.md)      | pubspec.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
| [Swift](swift.md)    | Podfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |

The path of these files does not matter.

Example: [Dockerfile](https://github.com/aquasecurity/trivy-ci-test/blob/main/Dockerfile)

[sbom]: ../../supply-chain/sbom.md
[vuln]: ../../scanner/vulnerability.md
[license]: ../../scanner/license.md

[^1]: `*.egg-info`, `*.egg-info/PKG-INFO`, `*.egg` and `EGG-INFO/PKG-INFO`
[^2]: `.dist-info/META-DATA`
[^3]: `envs/*/conda-meta/*.json`
[^4]: `*.jar`, `*.war`, `*.par` and `*.ear`
[^5]: ✅ means "enabled" and `-` means "disabled" in the image scanning
[^6]: ✅ means "enabled" and `-` means "disabled" in the rootfs scanning
[^7]: ✅ means "enabled" and `-` means "disabled" in the filesystem scanning
[^8]: ✅ means "enabled" and `-` means "disabled" in the git repository scanning
[^9]: ✅ means that Trivy detects line numbers where each dependency is declared in the scanned file. Only supported in [json](../../configuration/reporting.md#json) and [sarif](../../configuration/reporting.md#sarif) formats. SARIF uses `startline == 1 and endline == 1` for unsupported file types
[^10]: To scan a filename other than the default filename use [file-patterns](../../configuration/skipping.md#file-patterns)

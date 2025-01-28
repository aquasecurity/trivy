# Programming Language

Trivy scans programming languages packages in the following scanners: 

- [SBOM][sbom]
- [Vulnerabilities][vuln]
- [Licenses][license]

## Pre/Post Build
Trivy categorizes targets into either Pre-build and Post-build. The files analyzed vary depending on the target type.   
Pre-build is meant for scanning code projects, where packages are likely in package manager lock files (e.g `package-lock.json`). Post-build is meant for scanning deployable artifacts (e.g vm, container) where packages are likely "installed" (e.g in `node_modules`) and source code (including lock files) is not available.

## Supported languages

The following table lists the supported languages and the way Trivy scans each language in each target:

| Language             | File                                                                                       | Image[^4] | Rootfs[^5] | Filesystem[^6] | Repository[^7] |
|----------------------|--------------------------------------------------------------------------------------------|:---------:|:----------:|:--------------:|:--------------:|
| [Ruby](ruby.md)      | Gemfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
|                      | gemspec                                                                                    |     ✅     |     ✅      |       -        |       -        |
| [Python](python.md)  | Pipfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
|                      | poetry.lock                                                                                |     -     |     -      |       ✅        |       ✅        |
|                      | uv.lock                                                                                    |     -     |     -      |       ✅        |       ✅        |
|                      | requirements.txt                                                                           |     -     |     -      |       ✅        |       ✅        |
|                      | egg package[^1]                                                                            |     ✅     |     ✅      |       -        |       -        |
|                      | wheel package[^2]                                                                          |     ✅     |     ✅      |       -        |       -        |
| [PHP](php.md)        | composer.lock                                                                              |     -     |     -      |       ✅        |       ✅        |
|                      | installed.json                                                                             |     ✅     |     ✅      |       -        |       -        |
| [Node.js](nodejs.md) | package-lock.json                                                                          |     -     |     -      |       ✅        |       ✅        |
|                      | yarn.lock                                                                                  |     -     |     -      |       ✅        |       ✅        |
|                      | pnpm-lock.yaml                                                                             |     -     |     -      |       ✅        |       ✅        |
|                      | package.json                                                                               |     ✅     |     ✅      |       -        |       -        |
| [.NET](dotnet.md)    | packages.lock.json                                                                         |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | packages.config                                                                            |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | .deps.json                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | *Packages.props[^9]                                                                        |     ✅     |     ✅      |       ✅        |       ✅        |
| [Java](java.md)      | JAR/WAR/PAR/EAR[^3]                                                                        |     ✅     |     ✅      |       -        |       -        |
|                      | pom.xml                                                                                    |     -     |     -      |       ✅        |       ✅        |
|                      | *gradle.lockfile                                                                           |     -     |     -      |       ✅        |       ✅        |
|                      | *.sbt.lock                                                                                 |     -     |     -      |       ✅        |       ✅        |
| [Go](golang.md)      | Binaries built by Go                                                                       |     ✅     |     ✅      |       -        |       -        |
|                      | go.mod                                                                                     |     -     |     -      |       ✅        |       ✅        |
| [Rust](rust.md)      | Cargo.lock                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        |
|                      | Binaries built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) |     ✅     |     ✅      |       -        |       -        |
| [C/C++](c.md)        | conan.lock                                                                                 |     -     |     -      |       ✅        |       ✅        |
| [Elixir](elixir.md)  | mix.lock[^8]                                                                               |     -     |     -      |       ✅        |       ✅        |
| [Dart](dart.md)      | pubspec.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
| [Swift](swift.md)    | Podfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        |
|                      | Package.resolved                                                                           |     -     |     -      |       ✅        |       ✅        |
| [Julia](julia.md)    | Manifest.toml                                                                              |     ✅     |     ✅      |       ✅        |       ✅        |

The path of these files does not matter.

Example: [Dockerfile](https://github.com/aquasecurity/trivy-ci-test/blob/main/Dockerfile)

[sbom]: ../../supply-chain/sbom.md
[vuln]: ../../scanner/vulnerability.md
[license]: ../../scanner/license.md

[^1]: `*.egg-info`, `*.egg-info/PKG-INFO`, `*.egg` and `EGG-INFO/PKG-INFO`
[^2]: `.dist-info/META-DATA`
[^3]: `*.jar`, `*.war`, `*.par` and `*.ear`
[^4]: ✅ means "enabled" and `-` means "disabled" in the image scanning
[^5]: ✅ means "enabled" and `-` means "disabled" in the rootfs scanning
[^6]: ✅ means "enabled" and `-` means "disabled" in the filesystem scanning
[^7]: ✅ means "enabled" and `-` means "disabled" in the git repository scanning
[^8]: To scan a filename other than the default filename use [file-patterns](../../configuration/skipping.md#file-patterns)
[^9]: `Directory.Packages.props` and  legacy `Packages.props` file names are supported

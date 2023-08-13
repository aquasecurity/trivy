# Programming Language

Trivy supports programming languages for 

- [SBOM][sbom]
- [vulnerabilities][vuln]
- [licenses][license].

## Supported languages

| Language             | File                                                                                       | Image[^5] | Rootfs[^6] | Filesystem[^7] | Repository[^8] | Dev dependencies             | Dependency location[^9] |
| -------------------- | ------------------------------------------------------------------------------------------ | :-------: | :--------: | :------------: | :------------: | ---------------------------- | :---------------------: |
| [Ruby](ruby.md)      | Gemfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        | included                     |            -            |
|                      | gemspec                                                                                    |     ✅     |     ✅      |       -        |       -        | included                     |            -            |
| [Python](python.md)  | Pipfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        | excluded                     |            ✅            |
|                      | poetry.lock                                                                                |     -     |     -      |       ✅        |       ✅        | excluded                     |            -            |
|                      | requirements.txt                                                                           |     -     |     -      |       ✅        |       ✅        | included                     |            -            |
|                      | egg package[^1]                                                                            |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
|                      | wheel package[^2]                                                                          |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
|                      | conda package[^3]                                                                          |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
| [PHP](php.md)        | composer.lock                                                                              |     ✅     |     ✅      |       ✅        |       ✅        | excluded                     |            ✅            |
| [Node.js](nodejs.md) | package-lock.json                                                                          |     -     |     -      |       ✅        |       ✅        | [excluded](./nodejs.md#npm)  |            ✅            |
|                      | yarn.lock                                                                                  |     -     |     -      |       ✅        |       ✅        | [excluded](./nodejs.md#yarn) |            ✅            |
|                      | pnpm-lock.yaml                                                                             |     -     |     -      |       ✅        |       ✅        | excluded                     |            -            |
|                      | package.json                                                                               |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
| [.NET](dotnet.md)    | packages.lock.json                                                                         |     ✅     |     ✅      |       ✅        |       ✅        | included                     |            ✅            |
|                      | packages.config                                                                            |     ✅     |     ✅      |       ✅        |       ✅        | excluded                     |            -            |
|                      | .deps.json                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        | excluded                     |            ✅            |
| [Java](java.md)      | JAR/WAR/PAR/EAR[^4]                                                                        |     ✅     |     ✅      |       -        |       -        | included                     |            -            |
|                      | pom.xml                                                                                    |     -     |     -      |       ✅        |       ✅        | excluded                     |            -            |
|                      | *gradle.lockfile                                                                           |     -     |     -      |       ✅        |       ✅        | excluded                     |            -            |
| [Go](golang.md)      | Binaries built by Go                                                                       |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
|                      | go.mod                                                                                     |     -     |     -      |       ✅        |       ✅        | included                     |            -            |
| [Rust](rust.md)      | Cargo.lock                                                                                 |     ✅     |     ✅      |       ✅        |       ✅        | excluded                     |            ✅            |
|                      | Binaries built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) |     ✅     |     ✅      |       -        |       -        | excluded                     |            -            |
| [C/C++](c.md)        | conan.lock                                                                                 |     -     |     -      |       ✅        |       ✅        | excluded                     |            -            |
| [Elixir](elixir.md)  | mix.lock[^13]                                                                              |     -     |     -      |       ✅        |       ✅        | excluded                     |            ✅            |
| [Dart](dart.md)      | pubspec.lock                                                                               |     -     |     -      |       ✅        |       ✅        | included                     |            -            |
| [Swift](swift.md)    | Podfile.lock                                                                               |     -     |     -      |       ✅        |       ✅        | included                     |            -            |

The path of these files does not matter.

Example: [Dockerfile](https://github.com/aquasecurity/trivy-ci-test/blob/main/Dockerfile)

[^1]: `*.egg-info`, `*.egg-info/PKG-INFO`, `*.egg` and `EGG-INFO/PKG-INFO`
[^2]: `.dist-info/META-DATA`
[^3]: `envs/*/conda-meta/*.json`
[^4]: `*.jar`, `*.war`, `*.par` and `*.ear`
[^5]: ✅ means "enabled" and `-` means "disabled" in the image scanning
[^6]: ✅ means "enabled" and `-` means "disabled" in the rootfs scanning
[^7]: ✅ means "enabled" and `-` means "disabled" in the filesystem scanning
[^8]: ✅ means "enabled" and `-` means "disabled" in the git repository scanning
[^9]: ✅ means that Trivy detects line numbers where each dependency is declared in the scanned file. Only supported in [json](../../../configuration/reporting.md#json) and [sarif](../../../configuration/reporting.md#sarif) formats. SARIF uses `startline == 1 and endline == 1` for unsupported file types
[^13]: To scan a filename other than the default filename use [file-patterns](../../../configuration/others.md#file-patterns)

## Data Sources

| Language | Source                                              | Commercial Use | Delay[^1] |
| -------- | --------------------------------------------------- | :------------: | :-------: |
| PHP      | [PHP Security Advisories Database][php]             |       ✅        |     -     |
|          | [GitHub Advisory Database (Composer)][php-ghsa]     |       ✅        |     -     |
| Python   | [GitHub Advisory Database (pip)][python-ghsa]       |       ✅        |     -     |
|          | [Open Source Vulnerabilities (PyPI)][python-osv]    |       ✅        |     -     |
| Ruby     | [Ruby Advisory Database][ruby]                      |       ✅        |     -     |
|          | [GitHub Advisory Database (RubyGems)][ruby-ghsa]    |       ✅        |     -     |
| Node.js  | [Ecosystem Security Working Group][nodejs]          |       ✅        |     -     |
|          | [GitHub Advisory Database (npm)][nodejs-ghsa]       |       ✅        |     -     |
| Java     | [GitLab Advisories Community][gitlab]               |       ✅        |  1 month  |
|          | [GitHub Advisory Database (Maven)][java-ghsa]       |       ✅        |     -     |
| Go       | [GitHub Advisory Database (Go)][go-ghsa]            |       ✅        |     -     |
| Rust     | [Open Source Vulnerabilities (crates.io)][rust-osv] |       ✅        |     -     |
| .NET     | [GitHub Advisory Database (NuGet)][dotnet-ghsa]     |       ✅        |     -     |
| C/C++    | [GitLab Advisories Community][gitlab]               |       ✅        |  1 month  |
| Dart     | [GitHub Advisory Database (Pub)][pub-ghsa]          |       ✅        |     -     |
| Elixir   | [GitHub Advisory Database (Erlang)][erlang-ghsa]    |       ✅        |           |

[^1]: Intentional delay between vulnerability disclosure and registration in the DB

[php-ghsa]: https://github.com/advisories?query=ecosystem%3Acomposer
[python-ghsa]: https://github.com/advisories?query=ecosystem%3Apip
[ruby-ghsa]: https://github.com/advisories?query=ecosystem%3Arubygems
[nodejs-ghsa]: https://github.com/advisories?query=ecosystem%3Anpm
[java-ghsa]: https://github.com/advisories?query=ecosystem%3Amaven
[dotnet-ghsa]: https://github.com/advisories?query=ecosystem%3Anuget
[pub-ghsa]: https://github.com/advisories?query=ecosystem%3Apub
[erlang-ghsa]: https://github.com/advisories?query=ecosystem%3Aerlang
[go-ghsa]: https://github.com/advisories?query=ecosystem%3Ago

[php]: https://github.com/FriendsOfPHP/security-advisories
[ruby]: https://github.com/rubysec/ruby-advisory-db
[nodejs]: https://github.com/nodejs/security-wg
[gitlab]: https://gitlab.com/gitlab-org/advisories-community

[python-osv]: https://osv.dev/list?q=&ecosystem=PyPI
[rust-osv]: https://osv.dev/list?q=&ecosystem=crates.io
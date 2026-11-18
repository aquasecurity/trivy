# Go

## Overview
Trivy supports two types of Go scanning, Go Modules and binaries built by Go.

The following scanners are supported.

| Artifact | SBOM | Vulnerability |    License    |
|----------|:----:|:-------------:|:-------------:|
| Modules  |  ✓   |       ✓       | [✓](#license) |
| Binaries |  ✓   |       ✓       |       -       |

The table below provides an outline of the features Trivy offers.

| Artifact | Offline[^1] | Dev dependencies | [Dependency graph][dependency-graph] |         Stdlib         | [Detection Priority][detection-priority] |
|----------|:-----------:|:-----------------|:------------------------------------:|:----------------------:|:----------------------------------------:|
| Modules  |      ✅      | Include          |        [✅](#dependency-graph)        |   [✅](#gomod-stdlib)   |            [✅](#gomod-stdlib)            |
| Binaries |      ✅      | Exclude          |                  -                   | [✅](#go-binary-stdlib) |                Not needed                |

!!! note
    When scanning Go projects (go.mod or binaries built with Go), Trivy scans only dependencies of the project, and does not detect vulnerabilities of application itself. 
    For example, when scanning the Docker project (Docker's source code with go.mod or the Docker binary), Trivy might find vulnerabilities in Go modules that Docker depends on, but won't find vulnerabilities of Docker itself. Moreover, when scanning the Trivy project, which happens to use Docker, Docker's vulnerabilities might be detected as dependencies of Trivy.

## Data Sources
The data sources are listed [here](../../scanner/vulnerability.md#langpkg-data-sources).
Trivy uses Go Vulnerability Database for [standard library](https://pkg.go.dev/std) and uses GitHub Advisory Database for other Go modules.

## Go Module
Depending on Go versions, the required files are different.

| Version | Required files | Offline |
| ------- | :------------: | :-----: |
| \>=1.17 |     go.mod     |    ✅    |
| <1.17   | go.mod, go.sum |    ✅    |

In Go 1.17+ projects, Trivy uses `go.mod` for direct/indirect dependencies.
On the other hand, it uses `go.mod` for direct dependencies and `go.sum` for indirect dependencies in Go 1.16 or less.

Go 1.17+ holds actually needed indirect dependencies in `go.mod`, and it reduces false detection.
`go.sum` in Go 1.16 or less contains all indirect dependencies that are even not needed for compiling.
If you want to have better detection, please consider updating the Go version in your project.
See [go.sum](#gomod-gosum) for why Trivy does not take dependencies from `go.sum` in Go 1.17+ projects.

!!! note
    The Go version doesn't mean your Go tool version, but the Go version in your go.mod.

    ```
    module github.com/aquasecurity/trivy
    
    go 1.18
    
    require (
            github.com/CycloneDX/cyclonedx-go v0.5.0
            ...
    )
    ```

    To update the Go version in your project, you need to run the following command.

    ```
    $ go mod tidy -go=1.18
    ```

### go.sum { #gomod-gosum }
In Go 1.17+ projects, Trivy does not take dependencies from `go.sum`, because it lists more modules than the build uses. Trivy still reads `go.sum` for [module checksums](#module-checksums).

A common extra entry is a module that another module needs to run its own tests. Go keeps such a module out of `go.mod` and never compiles it into your binary, so a vulnerability in it does not affect your project. Your own tests are a different case. Their dependencies are listed in `go.mod`, and Trivy reports them.

To check whether a module is part of the build, list the dependencies of your packages.

{% raw %}
```
$ go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./... | grep -Fx 'golang.org/x/mod'
```
{% endraw %}

Empty output means the module is not in the build. Add the `-test` flag to also cover the tests of your own packages.

To see exactly what a build linked in, scan the compiled binary instead of the source tree. See [Go Binary](#go-binary).

### Main Module { #gomod-main }
Trivy scans only dependencies of the project, and does not detect vulnerabilities of the main module. 
For example, when scanning the Docker project (Docker's source code with go.mod), Trivy might find vulnerabilities in Go modules that Docker depends on, but won't find vulnerabilities of Docker itself.
Moreover, when scanning the Trivy project, which happens to use Docker, Docker's vulnerabilities might be detected as dependencies of Trivy.

### Standard Library { #gomod-stdlib }
Detecting the version of Go used in the project can be tricky.
The go.mod file include hints that allows Trivy to guess the Go version but it eventually depends on the Go tool version in the build environment.
Since this strategy is not fully deterministic and accurate, it is enabled only in [--detection-priority comprehensive][detection-priority] mode.
When enabled, Trivy detects stdlib version as the minimum between the `go` and the `toolchain` directives in the `go.mod` file.
To obtain reproducible scan results Trivy doesn't check the locally installed version of `Go`.

!!! note
    Trivy detects `stdlib` only for `Go` 1.21 or higher.

    The version from the `go` line (for `Go` 1.20 or early) is not a minimum required version.
    For details, see [this](https://go.googlesource.com/proposal/+/master/design/57001-gotoolchain.md).

It possibly produces false positives.
See [the caveat](#stdlib-vulnerabilities) for details.

### License
To identify licenses, you need to download modules to local cache beforehand, such as `go mod download`, `go mod tidy`, `go mod vendor`, etc.
If the `vendor` directory exists, Trivy uses this directory when scanning for license files.
For other cases Trivy traverses `$GOPATH/pkg/mod`dir and collects those extra information.

### Dependency Graph
Same as licenses, you need to download modules to local cache beforehand.

## Go Binary
Trivy scans Go binaries when it encounters them during scans such as container images or file systems. 
When scanning binaries built by Go, Trivy finds dependencies and Go version information as [embedded in the binary by Go tool at build time](https://tip.golang.org/doc/go1.18#go-version).

```
$ trivy rootfs ./your_binary
```

!!! note
    It doesn't work with UPX-compressed binaries.

### Main Module
Go binaries installed using the `go install` command contains correct (semver) version for the main module and therefore are detected by Trivy.
In other cases, Go uses the `(devel)` version[^2].
In this case, Trivy will attempt to parse any `-ldflags` as it's a common practice to pass versions this way.
If the `-ldflags` are not available (e.g., due to the Go `-trimpath` flag), Trivy will attempt to extract the version from the ELF symbol table.
If unsuccessful, the version will be empty[^3].

### Standard Library { #go-binary-stdlib }
Trivy detects the Go version used to compile the binary and detects its vulnerabilities in the standard libraries.
It possibly produces false positives.
See [the caveat](#stdlib-vulnerabilities) for details.

## Module Checksums
Trivy records the h1 checksum of a Go module as a SHA-256 digest of the package with the `go-module-h1` source. For a replaced module, Trivy reports the replacement and its checksum. The h1 checksum is a SHA-256 hash over the list of the module files and their SHA-256 hashes, so it does not match the SHA-256 of the module zip file. See [go.sum files](https://go.dev/ref/mod#go-sum-files) for details.

For Go modules, Trivy takes the checksum from the `go.sum` file next to `go.mod`. A module gets no checksum if `go.sum` has only its `/go.mod` line, because that line covers only the `go.mod` file of the module.

For Go binaries, Trivy takes the checksum from the build info. A module replaced with a local directory has no checksum. The main module has a checksum only if the binary was built with `go install module@version`.

Trivy does not verify the checksums against the [checksum database](https://go.dev/ref/mod#checksum-database) or the module contents.

To compare a digest with the h1 form that Go uses, convert the hex value to base64 and add the `h1:` prefix. Then compare it with the line in `go.sum` or with the `Sum` field from `go mod download -json`.

```
$ echo 828d5b2bf0ff045655d88f1c21077534a119fb4a304931b57c34dc8b822a15c1 | xxd -r -p | base64
go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=
$ go mod download -json golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1 | jq -r .Sum
h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=
```

## Caveats

### Stdlib Vulnerabilities
Trivy does not know if or how you use stdlib functions, therefore it is possible that stdlib vulnerabilities are not applicable to your use case.
There are a few ways to mitigate this:

1. Analyze vulnerability reachability using a tool such as [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck). This will ensure that reported vulnerabilities are applicable to your project.
2. Suppress non-applicable vulnerabilities using either [ignore file](../../configuration/filtering.md) for self-use or [VEX Hub](../../supply-chain/vex/repo.md) for public use.

### Empty Version
As described in the [Main Module](#gomod-main) section, the main module of Go binaries might have an empty version.
Also, dependencies replaced with local ones will have an empty version.

[^1]: It doesn't require the Internet access.
[^2]: See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477
[^3]: See https://github.com/golang/go/issues/63432#issuecomment-1751610604

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[toolchain]: https://go.dev/doc/toolchain
[detection-priority]: ../../scanner/vulnerability.md#detection-priority

# Go

## Data Sources
The data sources are listed [here](../../scanner/vulnerability.md#data-sources-1).
Trivy uses Go Vulnerability Database for [standard library](https://pkg.go.dev/std) and uses GitHub Advisory Database for other Go modules.

## Features
Trivy supports two types of Go scanning, Go Modules and binaries built by Go.

The following scanners are supported.

| Artifact | SBOM  | Vulnerability | License |
| -------- | :---: | :-----------: | :-----: |
| Modules  |   ✓   |       ✓       |  ✓[^2]  |
| Binaries |   ✓   |       ✓       |    -    |

The table below provides an outline of the features Trivy offers.

| Artifact | Offline[^1] | Dev dependencies | [Dependency graph][dependency-graph] | Stdlib | [Detection Priority][detection-priority] |
|----------|:-----------:|:-----------------|:------------------------------------:|:------:|:----------------------------------------:|
| Modules  |      ✅      | Include          |                ✅[^2]                 | ✅[^6]  |               [✅](#stdlib)               |
| Binaries |      ✅      | Exclude          |                  -                   | ✅[^4]  |                Not needed                |

!!! note
    When scanning Go projects (go.mod or binaries built with Go), Trivy scans only dependencies of the project, and does not detect vulnerabilities of application itself. 
    For example, when scanning the Docker project (Docker's source code with go.mod or the Docker binary), Trivy might find vulnerabilities in Go modules that Docker depends on, but won't find vulnerabilities of Docker itself. Moreover, when scanning the Trivy project, which happens to use Docker, Docker's vulnerabilities might be detected as dependencies of Trivy.

### Go Modules
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

To identify licenses and dependency relationships, you need to download modules to local cache beforehand,
such as `go mod download`, `go mod tidy`, etc.
Trivy traverses `$GOPATH/pkg/mod` and collects those extra information.

#### Standard Library
Detecting the version of Go used in the project can be tricky. The go.mod file include hints that allows Trivy to guess the Go version but it eventually depends on the Go tool version in the build environment. Since this strategy is not fully deterministic and accurate, it is enabled only in [--detection-priority comprehensive][detection-priority] mode.
When enabled, Trivy detects stdlib version as the minimum between the `go` and the [toolchain][^6] directives in the `go.mod` file.
To obtain reproducible scan results Trivy doesn't check the locally installed version of `Go`.

!!! note
    Trivy detects `stdlib` only for `Go` 1.21 or higher.

    The version from the `go` line (for `Go` 1.20 or early) is not a minimum required version.
    For details, see [this](https://go.googlesource.com/proposal/+/master/design/57001-gotoolchain.md).

Trivy does not know if or how you use stdlib functions, therefore it is possible that stdlib vulnerabilities are not applicable to your use case. There are a few ways to mitigate this:
1. set `--detection-priority precise` to disable stdlib detection.
2. Analyze vulnerability reachability using a tool such as [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck). This will ensure that reported vulnerabilities are applicable to your project.
3. Suppress non-applicable vulnerabilities using either [ignore file](../../configuration/ignore.md) for self-use or [VEX Hub](../../supply-chain/vex/repo.md) for public use.

### Go binaries
Trivy scans Go binaries when it encounters them during scans such as container images or file systems. 
When scanning binaries built by Go, Trivy finds dependencies and Go version information as [embedded in the binary by Go tool at build time](https://tip.golang.org/doc/go1.18#go-version).

```
$ trivy rootfs ./your_binary
```

!!! note
    It doesn't work with UPX-compressed binaries.

#### Empty versions
Go binaries installed using the `go install` command contains correct (semver) version for the main module and therefor are detected by Trivy. In other cases, Go uses the `(devel)` version[^3]. In this case, Trivy will attempt to parse any `-ldflags` as it's a common practice to pass versions this way. If unsuccessful, the version will be empty[^5].

[^1]: It doesn't require the Internet access.
[^2]: Need to download modules to local cache beforehand
[^3]: See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477
[^4]: Identify the Go version used to compile the binary and detect its vulnerabilities
[^5]: See https://github.com/golang/go/issues/63432#issuecomment-1751610604
[^6]: Only available if `toolchain` directive exists

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[toolchain]: https://go.dev/doc/toolchain
[detection-priority]: ../../scanner/vulnerability.md#detection-priority

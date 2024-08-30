# Go

## Data Sources
The data sources are listed [here](../../scanner/vulnerability.md#data-sources-1).
Trivy uses Go Vulnerability Database for standard packages, such as `net/http`, and uses GitHub Advisory Database for third-party packages.

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
    Trivy scans only dependencies of the Go project.
    Let's say you scan the Docker binary, Trivy doesn't detect vulnerabilities of Docker itself.
    Also, when you scan go.mod in Kubernetes, the Kubernetes vulnerabilities will not be found.

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
    The Go version doesn't mean your CLI version, but the Go version in your go.mod.

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

#### stdlib
If [--detection-priority comprehensive][detection-priority] is passed, Trivy determines the minimum version of `Go` and saves it as a `stdlib` dependency.

By default, `Go` selects the higher version from of `toolchan` or local version of `Go`. 
See [toolchain] for more details.

To obtain reproducible scan results Trivy doesn't check the local version of `Go`.
Trivy shows the minimum required version for the `go.mod` file, obtained from `toolchain` line (or from the `go` line, if `toolchain` line is omitted).

!!! note
    Trivy detects `stdlib` only for `Go` 1.21 or higher.

    The version from the `go` line (for `Go` 1.20 or early) is not a minimum required version.
    For details, see [this](https://go.googlesource.com/proposal/+/master/design/57001-gotoolchain.md).
    
    

### Go binaries
Trivy scans binaries built by Go, which include [module information](https://tip.golang.org/doc/go1.18#go-version).
If there is a Go binary in your container image, Trivy automatically finds and scans it.

Also, you can scan your local binaries.

```
$ trivy rootfs ./your_binary
```

!!! note
    It doesn't work with UPX-compressed binaries.

#### Empty versions
There are times when Go uses the `(devel)` version for modules/dependencies.

- Only Go binaries installed using the `go install` command contain correct (semver) version for the main module. 
  In other cases, Go uses the `(devel)` version[^3].
- Dependencies replaced with local ones use the `(devel)` versions.

In the first case, Trivy will attempt to parse any `-ldflags` as a secondary source, and will leave the version
empty if it cannot do so[^5]. For the second case, the version of such packages is empty.

[^1]: It doesn't require the Internet access.
[^2]: Need to download modules to local cache beforehand
[^3]: See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477
[^4]: Identify the Go version used to compile the binary and detect its vulnerabilities
[^5]: See https://github.com/golang/go/issues/63432#issuecomment-1751610604
[^6]: Only available if `toolchain` directive exists

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[toolchain]: https://go.dev/doc/toolchain
[detection-priority]: ../../scanner/vulnerability.md#detection-priority

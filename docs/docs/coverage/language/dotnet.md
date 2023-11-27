# .NET

Trivy supports `.NET core` and `NuGet` package managers.

The following scanners are supported.

| Artifact  | SBOM | Vulnerability | License |
|-----------|:----:|:-------------:|:-------:|
| .Net Core |  ✓   |       ✓       |    -    |
| NuGet     |  ✓   |       ✓       |    ✓    |

The following table provides an outline of the features Trivy offers.

| Package manager | File               | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|:---------------:|--------------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
|    .Net Core    | *.deps.json        |            ✓            |     Excluded     |                  -                   |    ✓     |
|      NuGet      | packages.config    |            ✓            |     Excluded     |                  -                   |    -     |
|      NuGet      | packages.lock.json |            ✓            |     Included     |                  ✓                   |    ✓     |

## *.deps.json
Trivy parses `*.deps.json` files. Trivy currently excludes dev dependencies from the report.

## packages.config
Trivy only finds dependency names and versions from `packages.config` files. To build dependency graph, it is better to use `packages.lock.json` files.

### license detection
`packages.config` files don't have information about the licenses used.
Trivy uses [*.nuspec][nuspec] files from [global packages folder][global-packages] to detect licenses.
!!! note
    The `licenseUrl` field is [deprecated][license-url]. Trivy doesn't parse this field and only checks the [license] field (license `expression` type only).
Currently only the default path and `NUGET_PACKAGES` environment variable are supported.

## packages.lock.json
Don't forgot to [enable][enable-lock] lock files in your project.

!!! tip
    Please make sure your lock file is up-to-date after modifying dependencies.

### license detection
Same as [packages.config](#license-detection)

[enable-lock]: https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#enabling-the-lock-file
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[nuspec]: https://learn.microsoft.com/en-us/nuget/reference/nuspec
[global-packages]: https://learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
[license]: https://learn.microsoft.com/en-us/nuget/reference/nuspec#license
[license-url]: https://learn.microsoft.com/en-us/nuget/reference/nuspec#licenseurl

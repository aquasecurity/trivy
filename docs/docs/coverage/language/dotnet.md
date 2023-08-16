# .NET

Trivy supports `.NET core` and `NuGet` package managers.

The following scanners are supported.

| Artifact  | SBOM | Vulnerability | License |
|-----------|:----:|:-------------:|:-------:|
| .Net Core |  ✓   |       ✓       |    -    |
| NuGet     |  ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Package manager | File               | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|:---------------:|--------------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
|    .Net Core    | *.deps.json        |            ✓            |     Excluded     |                  -                   |    ✓     |
|      NuGet      | packages.config    |            ✓            |     Excluded     |                  -                   |    -     |
|      NuGet      | packages.lock.json |            ✓            |     Included     |                  ✓                   |    ✓     |

### *.deps.json
Trivy parses `*.deps.json` files. Trivy currently excludes dev dependencies from the report.

### packages.config
Trivy only finds dependency names and versions from `packages.config` files. To build dependency graph, it is better to use `packages.lock.json` files.

### packages.lock.json
Don't forgot to [enable][enable-lock] lock files in your project.

!!! tip
    Please make sure your lock file is up-to-date after modifying dependencies.


[enable-lock]: https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#enabling-the-lock-file
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

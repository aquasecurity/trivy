# Conda

Trivy supports the following scanners for Conda packages.

|    Scanner    | Supported |
|:-------------:|:---------:|
|     SBOM      |     ✓     |
| Vulnerability |     -     |
|    License    |     ✓     |

| Package manager | File            | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position | [Detection Priority][detection-priority] |
|-----------------|-----------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|:----------------------------------------:|
| Conda           | environment.yml |            -            |     Include      |                  -                   |    ✓     |                    -                     |


## `<package>.json`
### SBOM
Trivy parses `<conda-root>/envs/<env>/conda-meta/<package>.json` files to find the dependencies installed in your env.

### License
The `<package>.json` files contain package license information.
Trivy includes licenses for the packages it finds without having to parse additional files.

## `environment.yml`[^1]
### SBOM
Trivy supports parsing [environment.yml][environment.yml][^1] files to find dependency list.

`environment.yml`[^1] files supports [version range][env-version-range]. We can't be sure about versions for these dependencies.
Therefore, you need to use `conda env export` command to get dependency list in `Conda` default format before scanning `environment.yml`[^1] file.

!!! note
    For dependencies in a non-Conda format, Trivy doesn't include a version of them.

### License
Trivy parses `conda-meta/<package>.json` files at the [prefix] path.

To correctly define licenses, make sure your `environment.yml`[^1] contains `prefix` field and `prefix` directory contains `package.json` files.

!!! note 
    To get correct `environment.yml`[^1] file and fill `prefix` directory - use `conda env export` command.

[^1]: Trivy supports both `yaml` and `yml` extensions.

[environment.yml]: https://conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html#sharing-an-environment
[env-version-range]: https://docs.conda.io/projects/conda-build/en/latest/resources/package-spec.html#examples-of-package-specs
[prefix]: https://conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html#specifying-a-location-for-an-environment
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[detection-priority]: ../../scanner/vulnerability.md#detection-priority

# Conda

Trivy supports the following scanners for Conda packages.

|    Scanner    | Supported |
|:-------------:|:---------:|
|     SBOM      |     ✓     |
| Vulnerability |     -     |
|    License    |   ✓[^1]   |


## SBOM
Trivy detects packages that have been installed with `Conda`.


### `<package>.json`
Trivy parses `<conda-root>/envs/<env>/conda-meta/<package>.json` files to find the version and license for the dependencies installed in your env.

### `environment.yml`[^2]
Trivy supports parsing [environment.yml][environment.yml][^2] files to find dependency list.

!!! note
    License detection is currently not supported.

`environment.yml`[^2] files supports [version range][env-version-range]. We can't be sure about versions for these dependencies.
Therefore, you need to use `conda env export` command to get dependency list in `Conda` default format before scanning `environment.yml`[^2] file.

!!! note
    For dependencies in a non-Conda format, Trivy doesn't include a version of them.


[^1]: License detection is only supported for `<package>.json` files
[^2]: Trivy supports both `yaml` and `yml` extensions.

[environment.yml]: https://conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html#sharing-an-environment
[env-version-range]: https://docs.conda.io/projects/conda-build/en/latest/resources/package-spec.html#examples-of-package-specs

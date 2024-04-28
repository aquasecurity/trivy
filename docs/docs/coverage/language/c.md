# C/C++

Trivy supports [Conan][conan] C/C++ Package Manager.

The following scanners are supported.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Conan           |  ✓   |       ✓       |  ✓[^1]  |

The following table provides an outline of the features Trivy offers.

| Package manager | File           | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|-----------------|----------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
| Conan           | conan.lock[^2] |            ✓            |     Excluded     |                  ✓                   |    ✓     |

## Conan
In order to detect dependencies, Trivy searches for `conan.lock`[^1].

### Licenses
The Conan lock file doesn't contain any license information.
To obtain licenses we parse the `conanfile.py` files from the [conan cache directory][conan-cache-dir].
To correctly detection licenses, ensure that the cache directory contains all dependencies used.

[conan]: https://docs.conan.io/1/index.html
[conan-cache-dir]: https://docs.conan.io/1/mastering/custom_cache.html
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[^1]: The local cache should contain the dependencies used. See [licenses](#licenses).
[^2]: `conan.lock` is default name. To scan a custom filename use [file-patterns](../../configuration/skipping.md#file-patterns).
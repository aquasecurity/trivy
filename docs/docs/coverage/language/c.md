# C/C++

Trivy supports Conan C/C++ Package Manager ([v1][conanV1] and [v2][conanV2] with limitations).

The following scanners are supported.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Conan           |  ✓   |       ✓       |  ✓[^1]  |

The following table provides an outline of the features Trivy offers.

| Package manager       | File           | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|-----------------------|----------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
| Conan (lockfile v1)   | conan.lock[^2] |            ✓            |     Excluded     |                  ✓                   |    ✓     |
| Conan (lockfile v2)   | conan.lock[^2] |            ✓ [^3]       |     Excluded     |                  -                   |    ✓     |

## Conan
In order to detect dependencies, Trivy searches for `conan.lock`[^1].

[conanV1]: https://docs.conan.io/1/index.html
[conanV2]: https://docs.conan.io/2/

### Licenses
The Conan lock file doesn't contain any license information.
To obtain licenses we parse the `conanfile.py` files from the [conan v1 cache directory][conan-v1-cache-dir] and [conan v2 cache directory][conan-v2-cache-dir].
To correctly detection licenses, ensure that the cache directory contains all dependencies used.

[conan-v1-cache-dir]: https://docs.conan.io/1/mastering/custom_cache.html
[conan-v2-cache-dir]: https://docs.conan.io/2/reference/environment.html#conan-home
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[^1]: The local cache should contain the dependencies used. See [licenses](#licenses).
[^2]: `conan.lock` is default name. To scan a custom filename use [file-patterns](../../configuration/skipping.md#file-patterns).
[^3]: For `conan.lock` in version 2, indirect dependencies are included in analysis but not flagged explicitly in dependency tree

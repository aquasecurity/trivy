# C/C++

Trivy supports [Conan][conan] C/C++ Package Manager.

The following scanners are supported.

| Package manager | SBOM  | Vulnerability | License |
|-----------------| :---: | :-----------: |:-------:|
| Conan           |   ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Package manager | File           | Transitive dependencies | Dev dependencies | Dependency graph | Position |
|-----------------|----------------|:-----------------------:|:----------------:|:----------------:|:--------:|
| Conan           | conan.lock[^1] |            ✓            |     Excluded     |        ✓         |    -     |

## Conan
In order to detect dependencies, Trivy searches for `conan.lock`[^1].

[conan]: https://docs.conan.io/1/index.html

[^1]: `conan.lock` is default name. To scan a custom filename use [file-patterns](../../configuration/others)
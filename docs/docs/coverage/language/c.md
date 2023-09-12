# C/C++

Trivy supports [Conan][conan] C/C++ Package Manager.

The following scanners are supported.

| Package manager | SBOM  | Vulnerability | License |
| --------------- | :---: | :-----------: | :-----: |
| Conan           |   ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Package manager | File           | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
| --------------- | -------------- | :---------------------: | :--------------: | :----------------------------------: | :------: |
| Conan           | conan.lock[^1] |            ✓            |     Excluded     |                  ✓                   |    ✓     |

## Conan
In order to detect dependencies, Trivy searches for `conan.lock`[^1].

[conan]: https://docs.conan.io/1/index.html
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[^1]: `conan.lock` is default name. To scan a custom filename use [file-patterns](../../configuration/skipping.md#file-patterns)
# PHP

Trivy supports [Composer][composer], which is a tool for dependency management in PHP.

The following scanners are supported.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Composer        |  ✓   |       ✓       |    ✓    |

The following table provides an outline of the features Trivy offers.


| Package manager | File           | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|-----------------|----------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
| Composer        | composer.lock  |            ✓            |     Excluded     |                  ✓                   |    ✓     |
| Composer        | installed.json |            ✓            |     Excluded     |                  -                   |    ✓     |

## composer.lock
In order to detect dependencies, Trivy searches for `composer.lock`.

Trivy also supports dependency trees; however, to display an accurate tree, it needs to know whether each package is a direct dependency of the project.
Since this information is not included in `composer.lock`, Trivy parses `composer.json`, which should be located next to `composer.lock`.
If you want to see the dependency tree, please ensure that `composer.json` is present.

## installed.json
Trivy also supports dependency detection for `installed.json` files. By default, you can find this file at `path_to_app/vendor/composer/installed.json`.

[composer]: https://getcomposer.org/
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
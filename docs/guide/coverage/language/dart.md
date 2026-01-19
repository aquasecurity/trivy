# Dart

Trivy supports [Dart][dart].

The following scanners are supported.

| Package manager         | SBOM | Vulnerability | License |
|-------------------------|:----:|:-------------:|:-------:|
| [Dart][dart-repository] |  ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.


| Package manager         | File         | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position | [Detection Priority][detection-priority] |
|-------------------------|--------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|:----------------------------------------:|
| [Dart][dart-repository] | pubspec.lock |            ✓            |     Included     |                  ✓                   |    -     |                    ✓                     |

## Dart
In order to detect dependencies, Trivy searches for `pubspec.lock`.

Trivy marks indirect dependencies, but `pubspec.lock` file doesn't have options to separate root and dev transitive dependencies.
So Trivy includes all dependencies in report.

### SDK dependencies
Dart uses version `0.0.0` for SDK dependencies (e.g. Flutter).
It is not possible to accurately determine the versions of these dependencies.
Trivy just treats them as `0.0.0`.

If [--detection-priority comprehensive][detection-priority] is passed, Trivy uses the minimum version of the constraint for the SDK.
For example, in the following case, the version of `flutter` would be `3.3.0`:

```yaml
flutter:
  dependency: "direct main"
  description: flutter
  source: sdk
  version: "0.0.0"
sdks:
  dart: ">=2.18.0 <3.0.0"
  flutter: "^3.3.0"
```

### Dependency tree
To build `dependency tree` Trivy parses [cache directory][cache-directory]. Currently supported default directories and `PUB_CACHE` environment (absolute path only).

!!! note
    Make sure the cache directory contains all the dependencies installed in your application. To download missing dependencies, use `dart pub get` command.     

[dart]: https://dart.dev/
[dart-repository]: https://pub.dev/
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[cache-directory]: https://dart.dev/tools/pub/glossary#system-cache
[detection-priority]: ../../scanner/vulnerability.md#detection-priority
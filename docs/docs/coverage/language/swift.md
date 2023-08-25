# Swift

Trivy supports [CocoaPods][cocoapods] and [Swift][swift] package managers.

The following scanners are supported.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Swift           |  ✓   |       ✓       |    -    |
| CocoaPods       |  ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Package manager | File             | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|:---------------:|------------------|:-----------------------:|:----------------:|:------------------------------------:|:--------:|
|      Swift      | Package.resolved |            ✓            |     Included     |                  -                   |    ✓     |
|    Cocoapods    | Podfile.lock     |            ✓            |     Included     |                  ✓                   |    -     |

These may be enabled or disabled depending on the target.
See [here](./index.md) for the detail.

## swift
Trivy parses [Package.resolved][package-resolved] file to find dependencies. Don't forger to update (`swift package update` command) this file before scanning.

## cocoapods
Cocoapods uses package names in `PodFile.lock`, but [GitHub advisory database][ghsa] uses git links. 
We parse [Cocoapods Specs][cocoapods-specs] to match package names and links.

[cocoapods]: https://cocoapods.org/
[cocoapods-specs]: https://github.com/CocoaPods/Specs
[ghsa]: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift
[swift]: https://www.swift.org/package-manager/
[package-resolved]: https://github.com/apple/swift-package-manager/blob/main/Documentation/Usage.md#resolving-versions-packageresolved-file
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
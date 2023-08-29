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
|    CocoaPods    | Podfile.lock     |            ✓            |     Included     |                  ✓                   |    -     |

These may be enabled or disabled depending on the target.
See [here](./index.md) for the detail.

## Swift
Trivy parses [Package.resolved][package-resolved] file to find dependencies. Don't forger to update (`swift package update` command) this file before scanning.

## CocoaPods
CocoaPods uses package names in `PodFile.lock`, but [GitHub Advisory Database][ghsa] uses git links. 
We parse [CocoaPods Specs][cocoapods-specs] to match package names and links.

`GitHub Advisory Database` currently uses advisories for root module. But modules and submodules of `CocoaPods` use same git link.
We can't select only vulnerable submodule. 
That is why Trivy shows vulnerabilities for all modules with the same URL.

[cocoapods]: https://cocoapods.org/
[cocoapods-specs]: https://github.com/CocoaPods/Specs
[ghsa]: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift
[swift]: https://www.swift.org/package-manager/
[package-resolved]: https://github.com/apple/swift-package-manager/blob/4a42f2519e3f7b8a731c5ed89b47ed577df8f86c/Documentation/Usage.md#resolving-versions-packageresolved-file
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
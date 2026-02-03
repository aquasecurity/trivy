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
Trivy parses [Package.resolved][package-resolved] file to find dependencies.
Don't forget to update (`swift package update` command) this file before scanning.

## CocoaPods
CocoaPods uses package names in `PodFile.lock`, but [GitHub Advisory Database (GHSA)][ghsa] Trivy relies on uses Git URLs. 
We parse [the CocoaPods Specs][cocoapods-specs] to match package names and links.

!!! note "Limitation"
    Since [GHSA][ghsa] holds only Git URLs, such as github.com/apple/swift-nio, 
    Trivy can't identify affected submodules, and detect all submodules maintained by the same URL.
    For example, [SwiftNIOHTTP1][niohttp1] and [SwiftNIOWebSocket][niowebsocket] both are maintained under `github.com/apple/swift-nio`,
    and Trivy detect CVE-2022-3215 for both of them, even though only [SwiftNIOHTTP1][niohttp1] is actually affected.

[cocoapods]: https://cocoapods.org/
[cocoapods-specs]: https://github.com/CocoaPods/Specs
[ghsa]: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift
[swift]: https://www.swift.org/package-manager/
[package-resolved]: https://github.com/apple/swift-package-manager/blob/4a42f2519e3f7b8a731c5ed89b47ed577df8f86c/Documentation/Usage.md#resolving-versions-packageresolved-file
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

[niohttp1]: https://cocoapods.org/pods/SwiftNIOHTTP1
[niowebsocket]: https://cocoapods.org/pods/SwiftNIOWebSocket
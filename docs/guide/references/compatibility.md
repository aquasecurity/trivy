# Compatibility and Stability

Trivy is designed, distributed, and supported primarily as a CLI application.

The Trivy project strives to preserve compatibility between releases for documented user-facing interfaces, except for features explicitly marked as experimental or subject to change. Unintended compatibility issues in stable interfaces are generally treated as bugs.

## Stable Interfaces

The following interfaces documented in the official Trivy documentation are covered by this compatibility policy:

- CLI commands, subcommands, flags, and arguments
- Configuration file options and environment variables
- Exit codes and the conditions under which they are returned
- Machine-readable output formats
- Data fields used by custom templates

Adding a new command, flag, configuration option, or output field is considered compatible as long as it does not change existing usage.

When the documentation and implementation disagree, neither is automatically considered authoritative. We determine the intended behavior by considering existing usage, user impact, and consistency with other features, and then correct either the implementation or the documentation.

Trivy's JSON output includes a `SchemaVersion` that identifies the output structure. Within the same `SchemaVersion`, optional fields may be added or omitted, so consumers should ignore unknown fields and must not assume that optional fields are always present. Removing or renaming an existing field, changing its type, or changing its meaning incompatibly generally requires an update to `SchemaVersion` and is documented as a breaking change in the release notes.

## Interfaces Outside the Compatibility Policy

The following are not part of Trivy's stable user-facing interfaces:

- Go packages, types, functions, methods, and other Go APIs in the Trivy repository
- Required versions of Go, Mage, and other build tools, as well as development commands and build scripts
- The exact formatting of terminal output, logs, warnings, error messages, and progress displays
- Scan results, including detected vulnerabilities, misconfigurations, secrets, and licenses, as well as their content and ordering
- Internal formats and protocols, such as caches, vulnerability databases, on-disk data, internal RPC, and Protocol Buffers definitions
- Compatibility between different versions of the Trivy client and Trivy server
- Experimental or preview features, canary builds, and prerelease versions
- Changes in behavior or coverage caused by external specifications, services, platforms, or data sources

Trivy is not designed or supported for use as a Go library. Interfaces outside this policy may be changed or removed without a deprecation period.

Even if such a change breaks external code or a custom build procedure, it is not, by itself, considered a breaking change to the Trivy CLI. As a rule, these changes are not identified as breaking changes in the release notes or announced separately. Users should not assume that they will be announced in advance.

## Scan Asset Version Support

Some [scan assets](terminology.md#scan-assets) use versioned formats that are tied to particular Trivy CLI versions:

- Vulnerability Database ([trivy-db](https://github.com/aquasecurity/trivy-db)): schema version
- Java Index Database ([trivy-java-db](https://github.com/aquasecurity/trivy-java-db)): schema version
- Checks Bundle ([trivy-checks](https://github.com/aquasecurity/trivy-checks)): major version

Each Trivy CLI version is compatible with particular versions of these assets.

When updates for an older scan asset version end, Trivy CLI versions that depend on it can no longer receive newly published vulnerability information, Java artifact identification data, or misconfiguration checks from that asset.

Before ending updates for a scan asset version, the Trivy project announces the affected CLI versions, the end date for updates, and the minimum CLI version to which users should upgrade. A scan asset version change is not considered a breaking change to the Trivy CLI. However, because users must upgrade to continue receiving current scan asset updates, it is announced separately from ordinary internal changes.

## Breaking Changes

A change that requires users to modify an existing valid use of a stable interface is considered a breaking change.

When a breaking change is necessary, we identify it in the release notes and provide migration guidance whenever possible. We announce a deprecation before making the change when practical, but do not guarantee a fixed deprecation period for every interface.

The usual deprecation process may not be possible when responding to an urgent security issue, an incompatible change in an external system, an obvious bug, or a risk of significant false positives, false negatives, data corruption, or other safety issues. Even in these cases, we describe changes with significant user impact in the release notes whenever possible.

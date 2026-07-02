# Seal Security

!!! warning "EXPERIMENTAL"
    Scanning results may be inaccurate.

This page describes the details of the [Seal Security](https://sealsecurity.io/) vulnerability feed.
Seal provides security advisories and patched versions for both OS packages and application dependencies.

## OS Packages

Seal provides patched versions for multiple Linux distributions, including [Debian](../os/debian.md), [Ubuntu](../os/ubuntu.md), [Alpine](../os/alpine.md), [Red Hat Enterprise Linux](../os/rhel.md), [CentOS](../os/centos.md), [Oracle Linux](../os/oracle.md), and [Azure Linux (CBL‑Mariner)](../os/azure.md).

Seal OS package advisories are used when Trivy finds packages that indicate Seal-provided components:

- Packages whose name or source name starts with `seal-` (for example, `seal-wget`, `seal-zlib`).

When such Seal packages are detected, Trivy automatically enables Seal scanning for those packages while continuing to use the base OS scanner for the rest.

!!! note
    For vulnerabilities, Trivy prefers severity from the base OS vendor when available.

For details on supported scanners, features, and behavior for each base OS, refer to their respective pages:

- [Debian](../os/debian.md)
- [Ubuntu](../os/ubuntu.md)
- [Alpine](../os/alpine.md)
- [Red Hat Enterprise Linux](../os/rhel.md)
- [CentOS](../os/centos.md)
- [Oracle Linux](../os/oracle.md)
- [Azure Linux (CBL‑Mariner)](../os/azure.md)

## Application Dependencies

Seal also provides patched versions of application dependencies with their own vulnerability advisories. Seal ships these packages under two naming schemes, and Trivy detects both. When Trivy detects a Seal-patched package by either scheme, it automatically uses Seal Security advisories for vulnerability scanning.

Both public (`spN`) and private (`spNpM`) sealed versions are recognized. A private version carries an extra `pM` iteration on top of the sealed version, for example `ejs` `3.1.8-sp2p1`.

For details on Seal's naming and versioning, see the Seal documentation:

- [The `-sp[N]` model](https://docs.sealsecurity.io/reference/naming-and-versioning/sp-model)
- [Per-ecosystem nuances](https://docs.sealsecurity.io/reference/naming-and-versioning/per-ecosystem)
- [Renamed packages](https://docs.sealsecurity.io/reference/naming-and-versioning/renamed-packages)

### Renamed packages

Renamed packages carry an ecosystem-specific name prefix. See the [Seal documentation](https://docs.sealsecurity.io/reference/naming-and-versioning/renamed-packages) for the full naming and versioning details.

| Ecosystem | Package Pattern | Example |
|-----------|----------------|---------|
| Python (pip) | `seal-*` | `seal-requests` |
| Node.js (npm) | `@seal-security/*` | `@seal-security/ejs` |
| Go | `sealsecurity.io/*` | `sealsecurity.io/github.com/Masterminds/goutils` |
| Java (Maven) | `seal.sp*` | `seal.sp1.org.eclipse.jetty:jetty-http` |
| Ruby (RubyGems) | `seal-*` | `seal-rack` |

### No-prefix packages

Some Seal packages keep their upstream (no-prefix) name and only add a patch-level version suffix. Trivy detects these by the version suffix:

| Ecosystem | Version Suffix | Example |
|-----------|----------------|---------|
| Java (Maven) | `+spN` | `org.eclipse.jetty:jetty-http` `9.4.48+sp1` |
| Python (pip) | `+spN` | `requests` `2.14.2+sp1` |
| Node.js (npm) | `-spN` | `ejs` `3.1.8-sp1` |
| Go | `-spN` | `golang.org/x/crypto` `0.26.0-sp1` |
| Ruby (RubyGems) | `.0.1.spN` | `rack` `2.0.7.0.1.sp1` |

For Maven and pip, the `+spN` suffix cannot collide with real package versions, so the match is authoritative.
For npm, Go, and Ruby, the `-spN` / `.0.1.spN` suffix can also appear on real packages, so Trivy confirms the match by looking the package up in the Seal advisory database; if the package is not found there, it falls back to the standard ecosystem advisories.

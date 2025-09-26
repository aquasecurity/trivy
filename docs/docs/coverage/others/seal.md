# Seal Security

!!! warning "EXPERIMENTAL"
    Scanning results may be inaccurate.

While it is not an OS, this page describes the details of the [Seal Security]( https://sealsecurity.io/) vulnerability feed.
Seal provides security advisories and patched versions for multiple Linux distributions, including [Debian](../os/debian.md), [Ubuntu](../os/ubuntu.md), [Alpine](../os/alpine.md), [Red Hat Enterprise Linux](../os/rhel.md), [CentOS](../os/centos.md), [Oracle Linux](../os/oracle.md), and [Azure Linux (CBL‑Mariner)](../os/azure.md).

Seal advisories are used when Trivy finds packages that indicate Seal-provided components:

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


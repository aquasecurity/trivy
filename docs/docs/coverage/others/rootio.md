# Root.io

!!! warning "EXPERIMENTAL"
    Scanning results may be inaccurate.

While it is not an OS, this page describes the details of [Root.io](https://root.io/) patch distribution service.
Root.io provides security patches for [Debian](../os/debian.md), [Ubuntu](../os/ubuntu.md), [Rocky](../os/rocky.md), and [Alpine](../os/alpine.md)-based container images.
Root.io patches are detected when Trivy finds packages with specific version suffixes:

- **Debian/Ubuntu/Rocky**: packages with `.root.io` in version string
- **Alpine**: packages with `-r\d007\d` pattern in version string (e.g., `-r10071`, `-r20072`)

When Root.io patches are detected, Trivy automatically switches to Root.io scanning mode for vulnerability detection.
Even when the original OS distributor (Debian, Ubuntu, Rocky, Alpine) has not provided a patch for a vulnerability, Trivy will display Root.io patches if they are available.

!!! note
    For vulnerabilities, Trivy uses the severity level from the original OS vendor (if the vendor has specified a severity).

For detailed information about supported scanners, features, and functionality, please refer to the documentation for the underlying OS:

- [Debian](../os/debian.md)
- [Ubuntu](../os/ubuntu.md) 
- [Alpine](../os/alpine.md)
- [Rocky](../os/rocky.md)
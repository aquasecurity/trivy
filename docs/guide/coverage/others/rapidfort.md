# RapidFort

This page describes the details of the [RapidFort](https://www.rapidfort.com/) curated vulnerability feed.
RapidFort publishes curated builds of [Ubuntu](../os/ubuntu.md), [Alpine](../os/alpine.md), and [Red Hat Enterprise Linux](../os/rhel.md)-based container images together with the corresponding security advisories.

RapidFort images are identified by the image config `maintainer` label — if its value contains `rapidfort` (case-insensitive), Trivy uses the [RapidFort security-advisories feed](https://github.com/rapidfort/security-advisories) for that image instead of the base OS vendor's advisories.

Because RapidFort curates its own advisories for the packages it ships — including RapidFort-built rebuilds (identified by the `rf-` prefix) and any third-party packages present in the image — Trivy scans all of them against the RapidFort feed instead of skipping them as it would under a standard base OS scan.

!!! note
    For vulnerabilities, Trivy uses the severity provided by the RapidFort feed rather than the base OS vendor's severity.

For details on supported scanners, features, and behaviour for each base OS, refer to the corresponding page:

- [Ubuntu](../os/ubuntu.md)
- [Alpine](../os/alpine.md)
- [Red Hat Enterprise Linux](../os/rhel.md)

# Others

In this section we have placed images, package managers and files that we can't assign to existing sections.

Trivy supports them for

- [SBOM][sbom]
- [Vulnerabilities][vuln]
- [Licenses][license]

## Supported elements

| Element                        | File                                                | Image[^1] | Rootfs[^2] | Filesystem[^3] | Repository[^4] |
|--------------------------------|-----------------------------------------------------|:---------:|:----------:|:--------------:|:--------------:|
| [Bitnami packages](bitnami.md) | `/opt/bitnami/<component>/.spdx-<component>.spdx`   |     ✅     |     ✅      |       -        |       -        |
| [Conda](conda.md)              | `<conda-root>/envs/<env>/conda-meta/<package>.json` |     ✅     |     ✅      |       -        |       -        |
|                                | `environment.yml`                                   |     -     |     -      |       ✅        |       ✅        |
| [RPM Archives](rpm.md)         | `*.rpm`                                             |   ✅[^5]   |   ✅[^5]    |     ✅[^5]      |     ✅[^5]      |

[sbom]: ../../supply-chain/sbom.md
[vuln]: ../../scanner/vulnerability.md
[license]: ../../scanner/license.md

[^1]: ✅ means "enabled" and `-` means "disabled" in the image scanning
[^2]: ✅ means "enabled" and `-` means "disabled" in the rootfs scanning
[^3]: ✅ means "enabled" and `-` means "disabled" in the filesystem scanning
[^4]: ✅ means "enabled" and `-` means "disabled" in the git repository scanning
[^5]: Only if the `TRIVY_EXPERIMENTAL_RPM_ARCHIVE` env is set.

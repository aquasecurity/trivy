# Overview

Trivy detects two types of security issues:

- [Vulnerabilities][vuln]
    - [OS packages][os] (Alpine, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, AlmaLinux, Rocky Linux, CBL-Mariner, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
    - [Language-specific packages][lang] (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
- [Misconfigurations][misconf]
    - Kubernetes
    - Docker
    - Terraform
    - CloudFormation
    - more coming soon

Trivy can scan three different artifacts:

- [Container Images][container]
- [Filesystem][filesystem]
- [Git Repositories][repo]

It is designed to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [Integrations][integrations] for details.

[vuln]: ../docs/vulnerability/scanning/index.md
[os]: ../docs/vulnerability/detection/os.md
[lang]: ../docs/vulnerability/detection/language.md

[misconf]: ../docs/misconfiguration/index.md

[container]: ../docs/vulnerability/scanning/image.md
[rootfs]: ../docs/vulnerability/scanning/rootfs.md
[filesystem]: ../docs/vulnerability/scanning/filesystem.md
[repo]: ../docs/vulnerability/scanning/git-repository.md

[integrations]: ../docs/integrations/index.md

[license]:  https://github.com/aquasecurity/trivy/blob/main/LICENSE

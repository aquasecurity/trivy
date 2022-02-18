# Overview

Trivy detects two types of security issues:

- [Vulnerabilities][vuln]
- [Misconfigurations][misconf]

Trivy can scan three different artifacts:

- [Container Images][container]
- [Filesystem][filesystem] and [Rootfs][rootfs]
- [Git Repositories][repo]

Trivy can be run in two different modes:

- [Standalone][standalone]
- [Client/Server][client-server]

It is designed to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [Integrations][integrations] for details.

## Features

- Comprehensive vulnerability detection
    - [OS packages][os] (Alpine, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, AlmaLinux, Rocky Linux, CBL-Mariner, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
    - [**Language-specific packages**][lang] (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
- Detect IaC misconfigurations
    - A wide variety of [built-in policies][builtin] are provided **out of the box**:
        - Kubernetes
        - Docker
        - Terraform
        - more coming soon
    - Support custom policies
- Simple
    - Specify only an image name, a directory containing IaC configs, or an artifact name
    - See [Quick Start][quickstart]
- Fast
    - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish in single seconds.
    - Unlike other scanners that take long to fetch vulnerability information (~10 minutes) on the first run, and encourage you to maintain a durable vulnerability database, Trivy is stateless and requires no maintenance or preparation.
- Easy installation
    - `apt-get install`, `yum install` and `brew install` is possible (See [Installation](tutorials/installation.md))
    - **No pre-requisites** such as installation of DB, libraries, etc.
- High accuracy
    - **Especially Alpine Linux and RHEL/CentOS**
    - Other OSes are also high
- DevSecOps
    - **Suitable for CI** such as Travis CI, CircleCI, Jenkins, GitLab CI, etc.
    - See [CI Example][integrations]
- Support multiple formats
    - container image
        - A local image in Docker Engine which is running as a daemon
        - A local image in [Podman][podman] (>=2.0) which is exposing a socket
        - A remote image in Docker Registry such as Docker Hub, ECR, GCR and ACR
        - A tar archive stored in the `docker save` / `podman save` formatted file
        - An image directory compliant with [OCI Image Format][oci]
    - local filesystem and rootfs
    - remote git repository

Please see [LICENSE][license] for Trivy licensing information.

[vuln]: how-to-guides/vulnerability/scanning/index.md
[misconf]: how-to-guides/misconfiguration/index.md
[container]: how-to-guides/vulnerability/scanning/image.md
[rootfs]: how-to-guides/vulnerability/scanning/rootfs.md
[filesystem]: how-to-guides/vulnerability/scanning/filesystem.md
[repo]: how-to-guides/vulnerability/scanning/git-repository.md

[standalone]: how-to-guides/modes/standalone.md
[client-server]: how-to-guides/modes/client-server.md
[integrations]: how-to-guides/integrations/index.md

[os]: how-to-guides/vulnerability/detection/os.md
[lang]: how-to-guides/vulnerability/detection/language.md

[builtin]: how-to-guides/misconfiguration/policy/builtin.md
[quickstart]: tutorials/getting-started.md
[podman]: how-to-guides/container/podman.md

[oci]: https://github.com/opencontainers/image-spec
[license]:  https://github.com/aquasecurity/trivy/blob/main/LICENSE

# Overview

Trivy detects two types of security issues:

- Vulnerabilities
- Misconfigurations

Trivy can scan three different artifacts:

- [Container Images](./scanning/image.md)
- [Filesystem](./scanning/filesystem.md)
- [Git Repositories](./scanning/git-repository.md)

Trivy can be run in two different modes:

- [Standalone](./modes/standalone.md)
- [Client/Server](./modes/client-server.md)

It is designed to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [here](./integrations/index.md) for details.

## Features

- Detect comprehensive vulnerabilities
    - OS packages (Alpine, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
    - **Language-specific packages** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
- Detect IaC misconfigurations
    - **Out of the box**
        - A wide variety of built-in policies are provided
    - Supported IaC configs
        - Kubernetes
        - Docker  
        - Terraform
- Simple
    - Specify only an image name, a directory containing IaC configs, or an artifact name
    - See [Quick Start](quickstart.md) and [Examples](examples/index.md)
- Fast
    - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish in single seconds.
    - Unlike other scanners that take long to fetch vulnerability information (~10 minutes) on the first run, and encourage you to maintain a durable vulnerability database, Trivy is stateless and requires no maintenance or preparation.
- Easy installation
    - `apt-get install`, `yum install` and `brew install` is possible (See [Installation](getting-started/installation.md))
    - **No pre-requisites** such as installation of DB, libraries, etc.
- High accuracy
    - **Especially Alpine Linux and RHEL/CentOS**
    - Other OSes are also high
- DevSecOps
    - **Suitable for CI** such as Travis CI, CircleCI, Jenkins, GitLab CI, etc.
    - See [CI Example](integrations/index.md)
- Support multiple formats
    - container image
        - A local image in Docker Engine which is running as a daemon
        - A local image in Podman (>=2.0) which is exposing a socket
        - A remote image in Docker Registry such as Docker Hub, ECR, GCR and ACR
        - A tar archive stored in the `docker save` / `podman save` formatted file
        - An image directory compliant with [OCI Image Format](https://github.com/opencontainers/image-spec)
    - local filesystem
    - remote git repository

Please see [LICENSE](https://github.com/aquasecurity/trivy/blob/main/LICENSE) for Trivy licensing information.

!!! note
    Trivy uses vulnerability information from a variety of sources, some of which are licensed for non-commercial use only.

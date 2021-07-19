# Welcome to {{ config.site_name }} 

A Simple and Comprehensive Vulnerability Scanner for Containers and other Artifacts, Suitable for CI.

# Abstract
`Trivy` (`tri` pronounced like **tri**gger, `vy` pronounced like en**vy**) is a simple and comprehensive vulnerability scanner for containers and other artifacts.
A software vulnerability is a glitch, flaw, or weakness present in the software or in an Operating System.
`Trivy` detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.).
`Trivy` is easy to use. Just install the binary and you're ready to scan. All you need to do for scanning is to specify a target such as an image name of the container.

<img src="imgs/overview.png" width="700">

Trivy can be run in two different modes:

- [Standalone](./modes/standalone.md)
- [Client/Server](./modes/client-server.md)

Trivy can scan three different artifacts:

- [Container Images](./scanning/image.md)
- [Filesystem](./scanning/filesystem.md)
- [Git Repositories](./scanning/git-repository.md)

<img src="imgs/usage.gif" width="700">
<img src="imgs/usage1.png" width="600">
<img src="imgs/usage2.png" width="600">

It is considered to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [here](./integrations/index.md) for details.

## Features

- Detect comprehensive vulnerabilities
    - OS packages (Alpine, **Red Hat Universal Base Image**, Red Hat Enterprise Linux, CentOS, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
    - **Application dependencies** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
- Simple
    - Specify only an image name or artifact name
    - See [Quick Start](quickstart.md) and [Examples](examples/index.md)
- Fast
    - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish in single seconds.
    - Unlike other scanners that take long to fetch vulnerability information (~10 minutes) on the first run, and encourage you to maintain a durable vulnerability database, Trivy is stateless and requires no maintenance or preparation.
- Easy installation
    - `apt-get install`, `yum install` and `brew install` is possible (See [Installation](installation.md))
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

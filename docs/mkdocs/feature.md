- Detect comprehensive vulnerabilities
  - OS packages (Alpine, **Red Hat Universal Base Image**, Red Hat Enterprise Linux, CentOS, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
  - **Application dependencies** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, and Maven)
- Simple
  - Specify only an image name or artifact name
  - See [Quick Start][quick-start] and [Examples][examples]
- Fast
  - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish in single seconds.
  - Unlike other scanners that take long to fetch vulnerability information (~10 minutes) on the first run, and encourage you to maintain a durable vulnerability database, Trivy is stateless and requires no maintenance or preparation.
- Easy installation
  - `apt-get install`, `yum install` and `brew install` is possible (See [Installation][installation])
  - **No pre-requisites** such as installation of DB, libraries, etc.
- High accuracy
  - **Especially Alpine Linux and RHEL/CentOS**
  - Other OSes are also high
- DevSecOps
  - **Suitable for CI** such as Travis CI, CircleCI, Jenkins, GitLab CI, etc.
  - See [CI Example][ci]
- Support multiple formats
  - container image
    - A local image in Docker Engine which is running as a daemon
    - A local image in Podman (>=2.0) which is exposing a socket
    - A remote image in Docker Registry such as Docker Hub, ECR, GCR and ACR
    - A tar archive stored in the `docker save` / `podman save` formatted file
    - An image directory compliant with [OCI Image Format][oci-img-fmt]
  - local filesystem
  - remote git repository

Please see [LICENSE][license] for Trivy licensing information. Note that Trivy uses vulnerability information from a variety of sources, some of which are licensed for non-commercial use only.

[quick-start]: quick-start/index.md
[examples]: examples/index.md
[installation]: installation/index.md
[ci]: continuous-integration/index.md
[oci-img-fmt]: https://github.com/opencontainers/image-spec
[license]: https://github.com/aquasecurity/trivy/blob/main/LICENSE

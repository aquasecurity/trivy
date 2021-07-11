<img src="docs/imgs/logo.png" width="150">


[![GitHub Release][release-img]][release]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls][docker-pulls]


Simple Vulnerability and Misconfiguration Scanner for Containers and other Artifacts, Suitable for CI.

# Abstract
`Trivy` (`tri` pronounced like **tri**gger, `vy` pronounced like en**vy**) is a simple and comprehensive vulnerability/misconfiguration scanner for containers and other artifacts.
A software vulnerability is a glitch, flaw, or weakness present in the software or in an Operating System.
`Trivy` detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and language-specific packages (Bundler, Composer, npm, yarn, etc.).
In addition, `Trivy` scans Infrastructure as Code (IaC) files such as Terraform and Kubernetes, to detect potential configuration issues that expose your deployments to the risk of attack.
`Trivy` is easy to use. Just install the binary and you're ready to scan.
All you need to do for scanning is to specify a target such as an image name of the container.

<img src="docs/imgs/overview.png" width="700">

<figure style="text-aligh: center">
  <img src="docs/imgs/vuln-demo.gif" width="1000">
  <figcaption>Demo: Vulnerability Detection</figcaption>
</figure>

<figure style="text-aligh: center">
  <img src="docs/imgs/misconf-demo.gif" width="1000">
  <figcaption>Demo: Misconfiguration Detection</figcaption>
</figure>

# Quick Start
## Scan Image for Vulnerabilities
Simply specify an image name (and a tag).

```
$ trivy image [YOUR_IMAGE_NAME]
```

For example:

```
$ trivy image python:3.4-alpine
```

<details>
<summary>Result</summary>

```
2019-05-16T01:20:43.180+0900    INFO    Updating vulnerability database...
2019-05-16T01:20:53.029+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```
</details>

## Scan Directory for Misconfigurations

Simply specify a directory containing IaC files such as Terraform and Dockerfile.

```
$ trivy config [YOUR_IAC_DIR]
```

For example:

```
$ ls build/
Dockerfile
$ trivy config ./build
```

<details>
<summary>Result</summary>

```
2021-07-09T10:06:29.188+0300    INFO    Need to update the built-in policies
2021-07-09T10:06:29.188+0300    INFO    Downloading the built-in policies...
2021-07-09T10:06:30.520+0300    INFO    Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+
```

</details>


# Features

- Comprehensive vulnerability detection
  - OS packages (Alpine, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
  - **Language-specific packages** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
- Misconfiguration detection (IaC scanning) 
  - A wide variety of built-in policies are provided **out of the box**
    - Kubernetes, Docker, Terraform, and more coming soon
  - Support custom policies
- Simple
  - Specify only an image name or artifact name
- Fast
  - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish in single seconds.
- Easy installation
  - `apt-get install`, `yum install` and `brew install` are possible.
  - **No pre-requisites** such as installation of DB, libraries, etc.
- High accuracy
  - **Especially [Alpine Linux][alpine] and RHEL/CentOS**
  - Other OSes are also high
- DevSecOps
  - **Suitable for CI** such as [GitHub Actions][action], Jenkins, GitLab CI, etc.
- Support multiple targets
  - container image, local filesystem and remote git repository

# Documentation
The official documentation, which provides detailed installation, configuration, and quick start guides, is available at https://aquasecurity.github.io/trivy/.

[go-report]: https://goreportcard.com/report/github.com/aquasecurity/trivy
[go-report-img]: https://goreportcard.com/badge/github.com/aquasecurity/trivy
[release]: https://github.com/aquasecurity/trivy/releases
[release-img]: https://img.shields.io/github/release/aquasecurity/trivy.svg?logo=github
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/trivy/total?logo=github
[docker-pulls]: https://img.shields.io/docker/pulls/aquasec/trivy?logo=docker&label=docker%20pulls%20%2F%20trivy
[license]: https://github.com/aquasecurity/trivy/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg

[alpine]: https://ariadne.space/2021/06/08/the-vulnerability-remediation-lifecycle-of-alpine-containers/
[action]: https://github.com/aquasecurity/trivy-action
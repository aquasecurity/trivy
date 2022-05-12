<img src="docs/imgs/logo.png" width="200">

[Documentation](docs)

Trivy is the world’s most popular open source security scanner. It is reliable, fast, extremely easy to use, and it works wherever you need it.

Trivy has different *scanners* that look for different security issues, and different *targets* where it can find those issues.

Targets:
- Container Image
- Filesystem
- Git repository (remote)
- Kubernetes cluster or resource

Scanners:
- OS packages and software dependencies in use (SBOM)
- Known vulnerabilities (CVEs)
- IaC misconfigurations
- Sensitive information and secrets

Much more scanners and targets are coming up. Missing something? Let us know!

Read more in the [Trivy Documentation](docs)

# Quick Start

General usage:

```bash
trivy <target> [--security-checks <scanner1,scanner2>]
```

Examples:

```bash
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

```bash
$ trivy fs --security-checks vuln,secret,config myproject/
```

<details>
<summary>Result</summary>

```bash
2021-07-09T12:03:27.564+0300    INFO    Number of language-specific files: 1
2021-07-09T12:03:27.564+0300    INFO    Detecting pipenv vulnerabilities...
2021-07-09T12:03:27.566+0300    INFO    Detected config files: 1

Pipfile.lock (pipenv)
=====================
Total: 1 (HIGH: 1, CRITICAL: 0)

+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| LIBRARY  | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+
| httplib2 | CVE-2021-21240   | HIGH     | 0.12.1            | 0.19.0        | python-httplib2: Regular              |
|          |                  |          |                   |               | expression denial of                  |
|          |                  |          |                   |               | service via malicious header          |
|          |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-21240 |
+----------+------------------+----------+-------------------+---------------+---------------------------------------+

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+
```
</details>


Find out more in the [Trivy Documentation](docs) - [Getting Started](getting-started)


# Highlights

- Comprehensive vulnerability detection
  - OS packages (Alpine Linux, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, AlmaLinux, Rocky Linux, CBL-Mariner, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
  - **Language-specific packages** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
  - High accuracy, especially [Alpine Linux][alpine] and RHEL/CentOS
- Supply chain security (SBOM support)
  - Support CycloneDX
  - Support SPDX
- Misconfiguration detection (IaC scanning) 
  - Wide variety of security checks are provided **out of the box**
  - Kubernetes, Docker, Terraform, and more
  - User-defined policies using [OPA Rego][rego]
- Secret detection
  - A wide variety of built-in rules are provided **out of the box**
  - User-defined patterns
  - Efficient scanning of container images
- Simple
  - Available in apt, yum, brew, dockerhub
  - **No pre-requisites** such as a database, system libraries, or eny environmental requirements. The binary runs anywhere.
  - The first scan will finish within 10 seconds (depending on your network). Consequent scans will finish instantaneously.
- Fits your workflow
  - **Great for CI** such as GitHub Actions, Jenkins, GitLab CI, etc.
  - Available as extension for IDEs such as vscode, jetbrains, vim
  - Available as extension for Docker Desktop, Rancher Desktop
  - See [integrations] section in the documentation.

---

Trivy is an [Aqua Security][aquasec] open source project.  
Learn about our open source work and portfolio [here][oss].  
Contact us about any matter by opening a GitHub Discussion [here][discussions]


[getting-started]: https://aquasecurity.github.io/trivy/v0.27.1/getting-started/overview/
[docs]: https://aquasecurity.github.io/trivy
[integrations]:https://aquasecurity.github.io/trivy/v0.27.1/docs/integrations/
[alpine]: https://ariadne.space/2021/06/08/the-vulnerability-remediation-lifecycle-of-alpine-containers/
[rego]: https://www.openpolicyagent.org/docs/latest/#rego
[aquasec]: https://aquasec.com
[oss]: https://www.aquasec.com/products/open-source-projects/
[discussions]: https://github.com/aquasecurity/trivy/discussions

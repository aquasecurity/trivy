---
hide:
- toc
---
![logo](imgs/logo.png){ align=right }

# Trivy Documentation

👋 Welcome to Trivy Documentation! To help you get around, please notice the different sections at the top global menu:

- You are currently in the [Getting Started] section where you can find general information and help with first steps.
- In the [Tutorials] section you can find step-by-step guides that help you accomplish specific tasks.
- In the [CLI] section you will find the complete reference documentation for all of the different features and settings that Trivy has to offer.
- In the [Ecosystem] section you will find how Trivy works together with other tools and applications that you might already use.
- In the [Contributing] section you will find instructions about developing Trivy, and contribution guidelines.

# About Trivy

Trivy ([pronunciation][pronunciation]) is a comprehensive and versatile security scanner. Trivy has *scanners* that look for security issues, and *targets* where it can find those issues.

Targets (what Trivy can scan):

- Container Image
- Filesystem
- Git Repository (remote)
- Virtual Machine Image
- Kubernetes
- AWS

Scanners (what Trivy can find there):

- OS packages and software dependencies in use (SBOM)
- Known vulnerabilities (CVEs)
- IaC issues and misconfigurations
- Sensitive information and secrets
- Software licenses

## Quick Start

### Get Trivy

Trivy is available in most common distribution methods. The full list of installation options is available in the [Installation] page, here are a few popular options:

- `apt-get install trivy`
- `yum install trivy`
- `brew install aquasecurity/trivy/trivy`
- `docker run aquasec/trivy`
- Download binary from <https://github.com/aquasecurity/trivy/releases/latest/>

Trivy is integrated with many popular platforms and applications. The full list of integrations is available in the [Ecosystem] page. Here are a few popular options:

- [GitHub Actions](https://github.com/aquasecurity/trivy-action)
- [CircleCI](https://circleci.com/developer/orbs/orb/fifteen5/trivy-orb)
- [Kubernetes operator](https://github.com/aquasecurity/trivy-operator)
- [VS Code plugin](https://github.com/aquasecurity/trivy-vscode-extension)


### General usage

```bash
trivy <target> [--security-checks <scanner1,scanner2>] <subject>
```

Examples:

```bash
trivy image python:3.4-alpine
```

<details>
<summary>Result</summary>

<figure style="text-align: center">
  <video width="1000" autoplay muted controls loop>
    <source src="https://user-images.githubusercontent.com/1161307/171013513-95f18734-233d-45d3-aaf5-d6aec687db0e.mov" type="video/mp4" />
  </video>
  <figcaption>Demo: Vulnerability Detection</figcaption>
</figure>

</details>

```bash
trivy fs --security-checks vuln,secret,config myproject/
```

<details>
<summary>Result</summary>

<figure style="text-align: center">
  <video width="1000" autoplay muted controls loop>
    <source src="https://user-images.githubusercontent.com/1161307/171013917-b1f37810-f434-465c-b01a-22de036bd9b3.mov" type="video/mp4" />
  </video>
  <figcaption>Demo: Misconfiguration Detection</figcaption>
</figure>

</details>

```bash
trivy k8s --report summary cluster
```

<details>
<summary>Result</summary>

<figure style="text-align: center">
  <img src="imgs/secret-demo.gif" width="1000">
  <figcaption>Demo: Secret Detection</figcaption>
</figure>

</details>

## Highlights

- Comprehensive vulnerability detection
    - OS packages (Alpine Linux, Red Hat Universal Base Image, Red Hat Enterprise Linux, CentOS, AlmaLinux, Rocky Linux, CBL-Mariner, Oracle Linux, Debian, Ubuntu, Amazon Linux, openSUSE Leap, SUSE Enterprise Linux, Photon OS and Distroless)
    - **Language-specific packages** (Bundler, Composer, Pipenv, Poetry, npm, yarn, Cargo, NuGet, Maven, and Go)
    - High accuracy, especially [Alpine Linux][alpine] and RHEL/CentOS
- Supply chain security (SBOM support)
    - Support CycloneDX
    - Support SPDX
    - Generating and Scanning SBOM
    - Leveraging in-toto attestations
    - Integrated with [Sigstore]
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
    - See [Ecosystem] section in the documentation.

## FAQ

### How to pronounce the name "Trivy"?

`tri` is pronounced like **tri**gger, `vy` is pronounced like en**vy**.

---

Trivy is an [Aqua Security][aquasec] open source project.  
Learn about our open source work and portfolio [here][oss].  
Contact us about any matter by opening a GitHub Discussion [here][discussions]

[Ecosystem]: ./ecosystem/overview
[Installation]: getting-started/installation/
[pronunciation]: #how-to-pronounce-the-name-trivy

[aquasec]: https://aquasec.com
[oss]: https://www.aquasec.com/products/open-source-projects/
[discussions]: https://github.com/aquasecurity/trivy/discussions

[Tutorials]: ./tutorials/overview
[CLI]: ./docs
[Contributing]: ./contributing/issue

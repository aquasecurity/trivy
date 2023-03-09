<div align="center">
<img src="docs/imgs/logo.png" width="200">

[![GitHub Release][release-img]][release]
[![Test][test-img]][test]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![GitHub Downloads][github-downloads-img]][release]
![Docker Pulls][docker-pulls]

[📖 Documentation][docs]
</div>

Trivy ([pronunciation][pronunciation]) is a comprehensive and versatile security scanner.
Trivy has *scanners* that look for security issues, and *targets* where it can find those issues.

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

To learn more, go to the [Trivy homepage][homepage] for feature highlights, or to the [Documentation site][docs] for detailed information.

## Quick Start

### Get Trivy

Trivy is available in most common distribution channels. The full list of installation options is available in the [Installation] page. Here are a few popular examples:

- `brew install trivy`
- `docker run aquasec/trivy`
- Download binary from <https://github.com/aquasecurity/trivy/releases/latest/>
- See [Installation] for more

Trivy is integrated with many popular platforms and applications. The complete list of integrations is available in the [Ecosystem] page. Here are a few popular examples:

- [GitHub Actions](https://github.com/aquasecurity/trivy-action)
- [Kubernetes operator](https://github.com/aquasecurity/trivy-operator)
- [VS Code plugin](https://github.com/aquasecurity/trivy-vscode-extension)
- See [Ecosystem] for more

### Canary builds
There are canary builds ([Docker Hub](https://hub.docker.com/r/aquasec/trivy/tags?page=1&name=canary), [GitHub](https://github.com/aquasecurity/trivy/pkgs/container/trivy/75776514?tag=canary), [ECR](https://gallery.ecr.aws/aquasecurity/trivy#canary) images and [binaries](https://github.com/aquasecurity/trivy/actions/workflows/canary.yaml)) as generated every push to main branch.

Please be aware: canary builds might have critical bugs, it's not recommended for use in production.

### General usage

```bash
trivy <target> [--scanners <scanner1,scanner2>] <subject>
```

Examples:

```bash
trivy image python:3.4-alpine
```

<details>
<summary>Result</summary>

https://user-images.githubusercontent.com/1161307/171013513-95f18734-233d-45d3-aaf5-d6aec687db0e.mov

</details>

```bash
trivy fs --scanners vuln,secret,config myproject/
```

<details>
<summary>Result</summary>

https://user-images.githubusercontent.com/1161307/171013917-b1f37810-f434-465c-b01a-22de036bd9b3.mov

</details>

```bash
trivy k8s --report summary cluster
```

<details>
<summary>Result</summary>

![k8s summary](docs/imgs/trivy-k8s.png)

</details>

## FAQ

### How to pronounce the name "Trivy"?

`tri` is pronounced like **tri**gger, `vy` is pronounced like en**vy**.

---

Trivy is an [Aqua Security][aquasec] open source project.  
Learn about our open source work and portfolio [here][oss].  
Contact us about any matter by opening a GitHub Discussion [here][discussions]

[test]: https://github.com/aquasecurity/trivy/actions/workflows/test.yaml
[test-img]: https://github.com/aquasecurity/trivy/actions/workflows/test.yaml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/aquasecurity/trivy
[go-report-img]: https://goreportcard.com/badge/github.com/aquasecurity/trivy
[release]: https://github.com/aquasecurity/trivy/releases
[release-img]: https://img.shields.io/github/release/aquasecurity/trivy.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/aquasecurity/trivy/total?logo=github
[docker-pulls]: https://img.shields.io/docker/pulls/aquasec/trivy?logo=docker&label=docker%20pulls%20%2F%20trivy
[license]: https://github.com/aquasecurity/trivy/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[homepage]: https://trivy.dev
[docs]: https://aquasecurity.github.io/trivy
[pronunciation]: #how-to-pronounce-the-name-trivy

[Installation]:https://aquasecurity.github.io/trivy/latest/getting-started/installation/
[Ecosystem]: https://aquasecurity.github.io/trivy/latest/ecosystem/

[alpine]: https://ariadne.space/2021/06/08/the-vulnerability-remediation-lifecycle-of-alpine-containers/
[rego]: https://www.openpolicyagent.org/docs/latest/#rego
[sigstore]: https://www.sigstore.dev/

[aquasec]: https://aquasec.com
[oss]: https://www.aquasec.com/products/open-source-projects/
[discussions]: https://github.com/aquasecurity/trivy/discussions

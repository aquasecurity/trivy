---
hide:
- navigation
- toc
---

![logo](imgs/logo.png){ align=left }

Trivy (tri pronounced like trigger, vy pronounced like envy) is a comprehensive security scanner. It is reliable, fast, extremely easy to use, and it works wherever you need it.

Trivy has different scanners that look for different security issues, and different targets where it can find those issues.

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

Much more scanners and targets are coming up. [Join the Slack][slack] channel to stay up to date, ask questions, and let us know what features you would like to see.

<figure style="text-align: center">
  <img src="imgs/vuln-demo.gif" width="1000">
  <figcaption>Demo: Vulnerability Detection</figcaption>
</figure>

<figure style="text-align: center">
  <img src="imgs/misconf-demo.gif" width="1000">
  <figcaption>Demo: Misconfiguration Detection</figcaption>
</figure>

<figure style="text-align: center">
  <img src="imgs/secret-demo.gif" width="1000">
  <figcaption>Demo: Secret Detection</figcaption>
</figure>

It is designed to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [Integrations][integrations] for details.


Please see [LICENSE][license] for Trivy licensing information.

## Getting Started

- [Installation](./home/installation.md)
- [Quick Start](./home/quickstart.md)

[integrations]: ./tutorials/integrations/index.md
[slack]: https://slack.aquasec.com
[license]:  https://github.com/aquasecurity/trivy/blob/main/LICENSE
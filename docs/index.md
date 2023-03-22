---
hide:
- toc
---
![logo](imgs/logo.png){ align=right }

# Trivy Documentation

👋 Welcome to Trivy Documentation! To help you get around, please notice the different sections at the top global menu:

- You are currently in the [Getting Started] section where you can find general information and help with first steps.
- In the [Tutorials] section you can find step-by-step guides that help you accomplish specific tasks.
- In the [Docs] section you can find the complete reference documentation for all of the different features and settings that Trivy has to offer.
- In the [Ecosystem] section you can find how Trivy works together with other tools and applications that you might already use.
- In the [Contributing] section you can find technical developer documentation and contribution guidelines.

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

To learn more, go to the [Trivy homepage][homepage] for feature highlights, or to the [Documentation site][Docs] for detailed information.

## Quick Start

### Get Trivy

Trivy is available in most common distribution channels. The complete list of installation options is available in the [Installation] page. Here are a few popular examples:

- `brew install trivy`
- `docker run aquasec/trivy`
- Download binary from <https://github.com/aquasecurity/trivy/releases/latest/>
- See [Installation] for more

Trivy is integrated with many popular platforms and applications. The complete list of integrations is available in the [Ecosystem] page. Here are a few popular options examples:

- [GitHub Actions](https://github.com/aquasecurity/trivy-action)
- [Kubernetes operator](https://github.com/aquasecurity/trivy-operator)
- [VS Code plugin](https://github.com/aquasecurity/trivy-vscode-extension)
- See [Ecosystem] for more

---

Trivy is an [Aqua Security][aquasec] open source project.  
Learn about our open source work and portfolio [here][oss].  
Contact us about any matter by opening a GitHub Discussion [here][discussions]

[Ecosystem]: ./ecosystem/index.md
[Installation]: getting-started/installation.md
[pronunciation]: #how-to-pronounce-the-name-trivy

[aquasec]: https://aquasec.com
[oss]: https://www.aquasec.com/products/open-source-projects/
[discussions]: https://github.com/aquasecurity/trivy/discussions

[homepage]: https://trivy.dev
[Tutorials]: ./tutorials/overview
[Docs]: ./docs
[Getting Started]: ./
[Contributing]: ./community/contribute/issue

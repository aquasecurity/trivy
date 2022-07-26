---
hide:
- toc
---

![logo](imgs/logo.png){ align=right }

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

It is designed to be used in CI. Before pushing to a container registry or deploying your application, you can scan your local container image and other artifacts easily.
See [Integrations][integrations] for details.

Much more scanners and targets are coming up. [Join the Slack][slack] channel to stay up to date, ask questions, and let us know what features you would like to see.

Please see [LICENSE][license] for Trivy licensing information.

<figure style="text-align: center">
  <video width="1000" autoplay muted controls loop>
    <source src="https://user-images.githubusercontent.com/1161307/171013513-95f18734-233d-45d3-aaf5-d6aec687db0e.mov" type="video/mp4" />
  </video>
  <figcaption>Demo: Vulnerability Detection</figcaption>
</figure>

<figure style="text-align: center">
  <video width="1000" autoplay muted controls loop>
    <source src="https://user-images.githubusercontent.com/1161307/171013917-b1f37810-f434-465c-b01a-22de036bd9b3.mov" type="video/mp4" />
  </video>
  <figcaption>Demo: Misconfiguration Detection</figcaption>
</figure>

<figure style="text-align: center">
  <img src="imgs/secret-demo.gif" width="1000">
  <figcaption>Demo: Secret Detection</figcaption>
</figure>

[integrations]: ./tutorials/integrations/index.md
[slack]: https://slack.aquasec.com
[license]:  https://github.com/aquasecurity/trivy/blob/main/LICENSE
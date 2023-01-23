# Quick Start

## Get Trivy

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

## General usage

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

[Ecosystem]: ../ecosystem/index.md
[Installation]: installation.md
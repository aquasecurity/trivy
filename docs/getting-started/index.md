# First steps with Trivy

## Get Trivy

Trivy is available in most common distribution channels. The complete list of installation options is available in the [Installation](./installation.md) page. Here are a few popular examples:

- macOS: `brew install trivy`
- Docker: `docker run aquasec/trivy`
- Download binary from [GitHub Release](https://github.com/aquasecurity/trivy/releases/latest/)
- See [Installation](./installation.md) for more

Trivy is integrated with many popular platforms and applications. The complete list of integrations is available in the [Ecosystem](../ecosystem/index.md) page. Here are a few popular options examples:

- [GitHub Actions](https://github.com/aquasecurity/trivy-action)
- [Kubernetes operator](https://github.com/aquasecurity/trivy-operator)
- [VS Code plugin](https://github.com/aquasecurity/trivy-vscode-extension)
- See [Ecosystem](../ecosystem/index.md) for more

## General usage

Trivy's Command Line Interface pattern follows its major concepts: targets (what you want to scan), and scanners (what you want to scan for):

```bash
trivy <target> [--scanners <scanner1,scanner2>] <subject>
```

### Examples

Scan a container image from registry, with the default scanner which is Vulnerabilities scanner:

```bash
trivy image python:3.4-alpine
```

<video width="1000" muted controls>
  <source src="https://user-images.githubusercontent.com/1161307/171013513-95f18734-233d-45d3-aaf5-d6aec687db0e.mov" type="video/mp4" />
</video>

Scan a local code repository, for vulnerabilities, exposed secrets and misconfigurations:

```bash
trivy fs --scanners vuln,secret,misconfig /path/to/myproject
```

<video width="1000" muted controls>
  <source src="https://user-images.githubusercontent.com/1161307/171013917-b1f37810-f434-465c-b01a-22de036bd9b3.mov" type="video/mp4" />
</video>

Scan a Kubernetes cluster, with all available scanners, and show a summary report:

```bash
trivy k8s --report summary cluster
```

<img src="../imgs/trivy-k8s.png" width="1000" alt="trivy-k8s"/>

For a more complete introduction, check out the basic Trivy Demo: <https://github.com/itaysk/trivy-demo>

## Learn more

Now that you up and ready, here are some resources to help you deepen your knowledge:

- Learn more about Trivy's capabilities by exploring the complete [documentation](../docs/index.md).
- Explore community questions and under [GitHub Discussions](https://github.com/aquasecurity/trivy/discussions).
- Stay up to date by watching for [New Releases & Announcements](https://github.com/aquasecurity/trivy/discussions/categories/announcements).
- Follow Trivy on Twitter/X: [@aquatrivy](https://x.com/aquatrivy)
- Explore and subscribe to our YouTube channel [@AquaSecOSS](http://youtube.com/@aquasecoss)

# Want more? Check out Aqua

If you liked Trivy, you will love Aqua which builds on top of Trivy to provide even more enhanced capabilities for a complete security management offering.  
You can find a high level comparison table specific to Trivy users [here](../commercial/compare.md).  
In addition, check out the <https://aquasec.com> website for more information about our products and services.
If you'd like to contact Aqua or request a demo, please use this form: <https://www.aquasec.com/demo>

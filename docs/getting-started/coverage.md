# Scanning Coverage

Trivy can detect security issues in many different platforms and languages. This page gives a general overview of that coverage, and can help answer the frequently asked question "Does Trivy support X?". For more detailed information about the specific features and options, check the relevant scanner documentation.

## Vulnerabilities & SBOM

### Programming languages
Trivy detects code dependencies for the purpose of SBOM generation and vulnerability detection. The following programming languages have some level of support:

- Ruby
- Python
- PHP
- Node.js
- .NET
- Java
- Go
- Rust
- C/C++
- Elixir
- Dart
- Swift

Some features might be not be universally supported. For a full supportability matrix, [see here](../docs/scanner/vulnerability/language/index.md).

### OS
Trivy detects installed packages for the purpose of vulnerability detection. The following package managers are supported:

- Alpine Linux
- Wolfi Linux
- Chainguard
- Red Hat Universal Base Image
- Red Hat Enterprise Linux
- CentOS
- AlmaLinux
- Rocky Linux
- Oracle Linux
- CBL-Mariner
- Amazon Linux
- openSUSE Leap
- SUSE Enterprise Linux
- Photon OS
- Debian GNU/Linux
- Ubuntu
- Distroless

Some features might be not be universally supported. For a full supportability matrix, [see here](../docs/scanner/vulnerability/os.md).

## IaC & configuration
Trivy reads IaC & configuration languages for the purpose of misconfiguration detection and custom checks.

- Kubernetes
- Dockerfile, Containerfile
- Terraform 
- CloudFormation
- Azure ARM Template
- Helm Chart

For more information about checks [see here](../docs/scanner/misconfiguration/policy/builtin.md).

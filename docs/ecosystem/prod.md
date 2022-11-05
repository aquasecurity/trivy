# Production and cloud Integrations

## Kubernetes 

[Kubernetes](https://kubernetes.io/) is an open-source system for automating deployment, scaling, and management of containerized applications.

### Trivy Operator (Official)

Using the Trivy Operator you can install Trivy into a Kubernetes cluster so that it automatically and continuously scan your workloads and cluster for security issues.

👉 Get it at: <https://github.com/aquasecurity/trivy-operator>

## Harbor (Official)
[Harbor](https://goharbor.io/) is an open source cloud native container and artifact registry.

Trivy is natively integrated into Harbor, no installation is needed. More info in Harbor documentation: <https://goharbor.io/docs/2.6.0/administration/vulnerability-scanning>

## Kyverno (Community)
[Kyverno](https://kyverno.io/) is a policy management tool for Kubernetes.

You can use Kyverno to ensure and enforce that deployed workloads' images are scanned for vulnerabilities.

👉 Get it at: <https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno>

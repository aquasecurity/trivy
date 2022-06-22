# Trivy Operator

There are lots of security tools in the cloud native world, created by Aqua and by others, for identifying and informing users about security issues in Kubernetes workloads and infrastructure components. However powerful and useful they might be, they tend to sit alongside Kubernetes, with each new product requiring users to learn a separate set of commands and installation steps in order to operate them and find critical security information.

Trivy-Operator leverage the trivy security tools by incorporating it outputs into Kubernetes CRDs (Custom Resource Definitions) and from there, making security reports accessible through the Kubernetes API. This way users can find and view the risks that relate to different resources in what we call a Kubernetes-native way.

Trivy-Operator provides:

- Automated vulnerability scanning for Kubernetes workloads.
- Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- Custom Resource Definitions and a Go module to work with and integrate a range of security scanners.
- The Lens Extension that make security reports available through familiar Kubernetes interfaces.

## Resources
The repository: [https://github.com/aquasecurity/trivy-operator](https://github.com/aquasecurity/trivy-operator)
The documentation: [https://aquasecurity.github.io/trivy-operator/latest/](https://aquasecurity.github.io/trivy-operator/latest/)
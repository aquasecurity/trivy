# Infrastructure as Code

## Scanner
Trivy scans Infrastructure as Code (IaC) files for 

- [Misconfigurations][misconf]
- [Secrets][secret]

## Supported configurations

| Config type                         | File patterns                 |
| ----------------------------------- | ----------------------------- |
| [Kubernetes](kubernetes.md)         | *.yml, *.yaml, *.json         |
| [Docker](docker.md)                 | Dockerfile, Containerfile     |
| [Terraform](terraform.md)           | *.tf, *.tf.json, *.tfvars,    |
| [CloudFormation](cloudformation.md) | *.yml, *.yaml, *.json         |
| [Azure ARM Template](azure-arm.md)  | *.json                        |
| [Helm](helm.md)                     | *.yaml, *.tpl, *.tar.gz, etc. |

[misconf]: ../../scanner/misconfiguration/index.md
[secret]: ../../scanner/secret.md

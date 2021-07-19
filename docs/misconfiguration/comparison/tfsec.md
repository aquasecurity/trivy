# vs tfsec
[tfsec][tfsec] uses static analysis of your Terraform templates to spot potential security issues.
Trivy uses tfsec internally to scan Terraform HCL files, but Trivy doesn't support some features provided by tfsec.
This section describes the differences between Trivy and tfsec.

| Feature                     | Trivy                                   | tfsec                |
| --------------------------- | --------------------------------------- | -------------------- |
| Built-in Policies           | :material-check:                        | :material-check:     |
| Custom Policies             | Rego[^1]                                | JSON and YAML        |
| Policy Metadata[^2]         | :material-check:                        | :material-check:     |
| Show Successes              | :material-check:                        | :material-check:     |
| Disable Policies            | :material-check:                        | :material-check:     |
| Show Issue Lines            | :material-close:                        | :material-check:     |
| Support .tfvars             | :material-close:                        | :material-check:     |
| View Statistics             | :material-close:                        | :material-check:     |
| Filtering by Severity       | :material-check:                        | :material-close:     |
| Supported Formats           | Dockerfile, JSON, YAML, Terraform, etc. | Terraform            |

[^1]: Terraform HCL files are not supported.
[^2]: To enrich the results such as ID, Title, Description, Severity, etc.

tfsec is designed for Terraform.
People who use only Terraform should use tfsec.
People who want to scan a wide range of configuration files should use Trivy.

[tfsec]: https://github.com/tfsec/tfsec
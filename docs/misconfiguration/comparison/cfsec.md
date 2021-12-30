# vs cfsec
[cfsec][cfsec] uses static analysis of your CloudFormation templates to spot potential security issues.
Trivy uses cfsec internally to scan both JSON and YAML configuration files, but Trivy doesn't support some features provided by cfsec.
This section describes the differences between Trivy and cfsec.

| Feature                     | Trivy                                   | cfsec                |
| --------------------------- | --------------------------------------- | -------------------- |
| Built-in Policies           | :material-check:                        | :material-check:     |
| Custom Policies             | Rego[^1]                                | :material-close:     |
| Policy Metadata[^2]         | :material-check:                        | :material-check:     |
| Show Successes              | :material-check:                        | :material-check:     |
| Disable Policies            | :material-check:                        | :material-check:     |
| Show Issue Lines            | :material-close:                        | :material-check:     |
| View Statistics             | :material-close:                        | :material-check:     |
| Filtering by Severity       | :material-check:                        | :material-close:     |
| Supported Formats           | Dockerfile, JSON, YAML, Terraform, etc. | CloudFormation JSON and YAML       |

[^1]: CloudFormation files are not supported
[^2]: To enrich the results such as ID, Title, Description, Severity, etc.

cfsec is designed for CloudFormation.
People who use only want to scan their CloudFormation templates should use cfsec.
People who want to scan a wide range of configuration files should use Trivy.

[cfsec]: https://github.com/aquasecurity/cfsec
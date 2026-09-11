# Security Policy

## Supported Versions

This is an open source project that is provided as-is without warranty or liability.
As such, there is no supportability commitment. The maintainers will do the best they can to address any report promptly and responsibly.

## Reporting a Vulnerability

Before submitting a report, please review the [project scope and principles](docs/community/principles.md#intentional-attacks) and the relevant security considerations:

- [Configuration files](docs/guide/configuration/index.md#security-considerations)
- [Report templates](docs/guide/configuration/reporting.md#custom-template)
- [Client/server deployments](docs/guide/references/modes/client-server.md#security-considerations)
- [Plugins](docs/guide/plugin/index.md#security-considerations) and [modules](docs/guide/advanced/modules.md#overview)
- [Terraform remote modules](docs/guide/coverage/iac/terraform.md#remote-modules) and [filesystem functions](docs/guide/coverage/iac/terraform.md#filesystem-functions)
- [Registry credentials](docs/guide/advanced/private-registries/index.md#passing-credentials) and [Maven mirror credentials](docs/guide/coverage/language/java.md#config-file-mirrors)
- [VEX attestations](docs/guide/supply-chain/vex/oci.md#step-3-use-vex-attestation-with-trivy)
- [HTTP request/response tracing](docs/guide/references/troubleshooting.md#http-requestresponse-tracing)

Please use the "Private vulnerability reporting" feature in the GitHub repository (under the "Security" tab).  

⚠️ **Important:**  
This policy is intended for vulnerabilities in **Trivy itself** (e.g., core functionality, scanning logic, or security features).  

If you discover a vulnerability in a **dependency module** (e.g., a third-party library used by Trivy), please **do not report it here**.  
Instead, open a ticket in [GitHub Discussions](https://github.com/aquasecurity/trivy/discussions) so that the maintainers and community can evaluate and address it appropriately.


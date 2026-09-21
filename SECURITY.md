# Security Policy

## Supported Versions

This is an open source project that is provided as-is without warranty or liability.
As such, there is no supportability commitment. The maintainers will do the best they can to address any report promptly and responsibly.

## Reporting a Vulnerability

Before submitting a report, please review the [project scope and principles](https://trivy.dev/docs/latest/community/principles/#intentional-attacks) and the relevant security considerations:

- [Configuration files](https://trivy.dev/docs/latest/guide/configuration/#security-considerations)
- [Report templates](https://trivy.dev/docs/latest/guide/configuration/reporting/#custom-template)
- [Client/server deployments](https://trivy.dev/docs/latest/guide/references/modes/client-server/#security-considerations)
- [Plugins](https://trivy.dev/docs/latest/guide/plugin/#security-considerations) and [modules](https://trivy.dev/docs/latest/guide/advanced/modules/#overview)
- [Terraform remote modules](https://trivy.dev/docs/latest/guide/coverage/iac/terraform/#remote-modules) and [filesystem functions](https://trivy.dev/docs/latest/guide/coverage/iac/terraform/#filesystem-functions)
- [Registry credentials](https://trivy.dev/docs/latest/guide/advanced/private-registries/#passing-credentials) and [Maven mirror credentials](https://trivy.dev/docs/latest/guide/coverage/language/java/#config-file-mirrors)
- [VEX attestations](https://trivy.dev/docs/latest/guide/supply-chain/vex/oci/#step-3-use-vex-attestation-with-trivy)
- [HTTP request/response tracing](https://trivy.dev/docs/latest/guide/references/troubleshooting/#http-requestresponse-tracing)

Please use the "Private vulnerability reporting" feature in the GitHub repository (under the "Security" tab).  

⚠️ **Important:**  
This policy is intended for vulnerabilities in **Trivy itself** (e.g., core functionality, scanning logic, or security features).  

If you discover a vulnerability in a **dependency module** (e.g., a third-party library used by Trivy), please **do not report it here**.  
Instead, open a ticket in [GitHub Discussions](https://github.com/aquasecurity/trivy/discussions) so that the maintainers and community can evaluate and address it appropriately.


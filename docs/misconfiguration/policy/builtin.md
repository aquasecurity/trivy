# Builtin Policies

## Policy Sources

Builtin policies are mainly written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/).
Those policies are managed under [AppShield repository](https://github.com/aquasecurity/appshield).
Only Terraform's policies are currently powered by [tfsec](https://github.com/tfsec/tfsec).

| Config type    | Source                                                                              |
| ---------------| ------------------------------------------------------------------------------------|
| Kubernetes     | [AppShield](https://github.com/aquasecurity/appshield/tree/master/kubernetes)       |
| Dockerfile     | [AppShield](https://github.com/aquasecurity/appshield/tree/master/docker)           |
| Terraform      | [tfsec](https://tfsec.dev/docs/aws/home/)                                           |

CloudFormation and Ansible are coming soon.

## Policy Distribution
AppShield policies are destributed as OPA bundle on [GitHub Container Registry](https://github.com/aquasecurity/appshield/pkgs/container/appshield) (GHCR).
When misconfiguration detection is enabled, Trivy pulls OPA bundle from GHCR as OCI artifact and stores it in the cache.
Then, those policies are loaded into Trivy OPA engine and used for detecting misconfigurations.

## Update Interval
Trivy checks for updates to OPA bundle on GHCR every 24 hours and pulls it if there are any updates.
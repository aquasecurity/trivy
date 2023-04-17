# Built-in Policies

## Policy Sources

Built-in policies are mainly written in [Rego][rego] and Go.
Those policies are managed under [defsec repository][defsec].

| Config type               | Source               |
|---------------------------|----------------------|
| Kubernetes                | [defsec][kubernetes] |
| Dockerfile, Containerfile | [defsec][docker]     |
| Terraform                 | [defsec][defsec]     |
| CloudFormation            | [defsec][defsec]     |
| Azure ARM Template        | [defsec][defsec]     |
| Helm Chart                | [defsec][kubernetes] |      

For suggestions or issues regarding policy content, please open an issue under the [defsec][defsec] repository.

Helm Chart scanning will resolve the chart to Kubernetes manifests then run the [kubernetes][kubernetes] checks.

## Policy Distribution
defsec policies are distributed as an OPA bundle on [GitHub Container Registry][ghcr] (GHCR).
When misconfiguration detection is enabled, Trivy pulls the OPA bundle from GHCR as an OCI artifact and stores it in the cache.
Those policies are then loaded into Trivy OPA engine and used for detecting misconfigurations.
If Trivy is unable to pull down newer policies, it will use the embedded set of policies as a fallback. This is also the case in air-gap environments where `--skip-policy-update` might be passed.

## Update Interval
Trivy checks for updates to OPA bundle on GHCR every 24 hours and pulls it if there are any updates.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[defsec]: https://github.com/aquasecurity/defsec
[kubernetes]: https://github.com/aquasecurity/defsec/tree/master/rules/kubernetes/policies
[docker]: https://github.com/aquasecurity/defsec/tree/master/rules/docker/policies
[ghcr]: https://github.com/aquasecurity/defsec/pkgs/container/defsec

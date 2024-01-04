# Built-in Policies

## Policy Sources
Built-in policies are mainly written in [Rego][rego] and Go.
Those policies are managed under [trivy-policies repository][trivy-policies].
See [here](../../../coverage/iac/index.md) for the list of supported config types.

For suggestions or issues regarding policy content, please open an issue under the [trivy-policies][trivy-policies] repository.

## Policy Distribution
Trivy policies are distributed as an OPA bundle on [GitHub Container Registry][ghcr] (GHCR).
When misconfiguration detection is enabled, Trivy pulls the OPA bundle from GHCR as an OCI artifact and stores it in the cache.
Those policies are then loaded into Trivy OPA engine and used for detecting misconfigurations.
If Trivy is unable to pull down newer policies, it will use the embedded set of policies as a fallback. This is also the case in air-gap environments where `--skip-policy-update` might be passed.

## Update Interval
Trivy checks for updates to OPA bundle on GHCR every 24 hours and pulls it if there are any updates.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/

[kubernetes-policies]: https://github.com/aquasecurity/trivy-policies/tree/main/rules/kubernetes/policies
[docker-policies]: https://github.com/aquasecurity/trivy-policies/tree/main/rules/docker/policies
[trivy-policies]: https://github.com/aquasecurity/trivy-policies
[ghcr]: https://github.com/aquasecurity/trivy-policies/pkgs/container/trivy-policies
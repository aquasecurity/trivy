# Built-in Checks 

## Check Sources
Built-in checks are mainly written in [Rego][rego] and Go.
Those checks are managed under [trivy-checks repository][trivy-checks].
See [here](../../../coverage/iac/index.md) for the list of supported config types.

For suggestions or issues regarding policy content, please open an issue under the [trivy-checks][trivy-checks] repository.

## Check Distribution
Trivy checks are distributed as an OPA bundle on [GitHub Container Registry][ghcr] (GHCR).
When misconfiguration detection is enabled, Trivy pulls the OPA bundle from GHCR as an OCI artifact and stores it in the cache.
Those checks are then loaded into Trivy OPA engine and used for detecting misconfigurations.
If Trivy is unable to pull down newer checks, it will use the embedded set of checks as a fallback. This is also the case in air-gap environments where `--skip-policy-update` might be passed.

## Update Interval
Trivy checks for updates to OPA bundle on GHCR every 24 hours and pulls it if there are any updates.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[trivy-checks]: https://github.com/aquasecurity/trivy-checks
[ghcr]: https://github.com/aquasecurity/trivy-checks/pkgs/container/trivy-checks
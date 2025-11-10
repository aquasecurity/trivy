# Built-in Checks 

## Checks Sources
Trivy has an extensive library of misconfiguration checks that is maintained at <https://github.com/aquasecurity/trivy-checks>.  
Trivy checks are mainly written in [Rego][rego], while some checks are written in Go.  
See [here](../../../coverage/iac/index.md) for the list of supported config types.

## Checks Bundle
When performing a misconfiguration scan, Trivy will automatically download the relevant Checks bundle. The bundle is cached locally and Trivy will reuse it for subsequent scans on the same machine. Trivy takes care of updating the cache automatically, so normally users can be oblivious to it.

## Checks Distribution
Trivy checks are distributed as an [OPA bundle][opa-bundle] hosted in the following GitHub Container Registry: <https://ghcr.io/aquasecurity/trivy-checks>.  
Trivy checks for updates to OPA bundle on GHCR every 24 hours and pulls it if there are any updates.

### External connectivity
Trivy needs to connect to the internet to download the bundle. If you are running Trivy in an air-gapped environment, or an tightly controlled network, please refer to the [Advanced Network Scenarios document](../../../advanced/air-gap.md).  
The Checks bundle is also embedded in the Trivy binary (at build time), and will be used as a fallback if Trivy is unable to download the bundle. This means that you can still scan for misconfigurations in an air-gapped environment using the Checks from the time of the Trivy release you are using.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[opa-bundle]: https://www.openpolicyagent.org/docs/latest/management-bundles/

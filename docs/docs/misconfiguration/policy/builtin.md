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
| Helm Chart                | [defsec][kubernetes] |      

For suggestions or issues regarding policy content, please open an issue under the [defsec][defsec] repository.

Helm Chart scanning will resolve the chart to Kubernetes manifests then run the [kubenetes][kubernetes] checks.

Ansible scanning is coming soon.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[defsec]: https://github.com/aquasecurity/defsec
[kubernetes]: https://github.com/aquasecurity/defsec/tree/master/internal/rules/kubernetes
[docker]: https://github.com/aquasecurity/defsec/tree/master/internal/rules/docker

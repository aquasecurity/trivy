# Misconfiguration Scanning
Trivy provides built-in policies to detect configuration issues in Docker, Kubernetes and Terraform.
Also, you can write your own policies in [Rego][rego] to scan JSON, YAML, HCL, etc, like [Conftest][conftest].

![misconf](../imgs/misconf.png)

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[conftest]: https://github.com/open-policy-agent/conftest/
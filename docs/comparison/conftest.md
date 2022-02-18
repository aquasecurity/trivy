# vs Conftest
[Conftest][conftest] is a really nice tool to help you write tests against structured configuration data.
Misconfiguration detection in Trivy is heavily inspired by Conftest and provides similar features Conftest has.
This section describes the differences between Trivy and Conftest.

| Feature                     | Trivy                | Conftest             |
| --------------------------- | -------------------- | -------------------- |
| Support Rego Language       | :material-check:     | :material-check:     |
| Built-in Policies           | :material-check:     | :material-close:     |
| Custom Policies             | :material-check:     | :material-check:     |
| Custom Data                 | :material-check:     | :material-check:     |
| Combine                     | :material-check:     | :material-check:     |
| Combine per Policy          | :material-check:     | :material-close:     |
| Policy Input Selector[^1]   | :material-check:     | :material-close:     |
| Policy Metadata[^2]         | :material-check:     | :material-close:[^3] |
| Filtering by Severity       | :material-check:     | :material-close:     |
| Rule-based Exceptions       | :material-check:     | :material-check:     |
| Namespace-based Exceptions  | :material-check:     | :material-close:     |
| Sharing Policies            | :material-close:     | :material-check:     |
| Show Successes              | :material-check:     | :material-close:     |
| Flexible Exit Code          | :material-check:     | :material-close:     |
| Rego Unit Tests             | :material-close:[^4] | :material-check:     |
| Go Testing                  | :material-check:     | :material-close:     |
| Verbose Trace               | :material-check:     | :material-check:     |
| Supported Formats           | 6 formats[^5]        | 14 formats[^6]       |

Trivy offers built-in policies and a variety of options, while Conftest only supports custom policies.
In other words, Conftest is simpler and lighter.

Conftest is a general testing tool for configuration files, and Trivy is more security-focused.
People who need an out-of-the-box misconfiguration scanner should use Trivy.
People who don't need built-in policies and write your policies should use Conftest.

[^1]: Pass only the types of configuration file as input, specified in selector
[^2]: To enrich the results such as ID, Title, Description, etc.
[^3]: Conftest supports [structured errors in rules][conftest-structured], but they are free format and not natively supported by Conftest.
[^4]: Trivy is not able to run `*_test.rego` like `conftest verify`.
[^5]: Dockerfile, HCL, HCL2, JSON, TOML, and YAML
[^6]: CUE, Dockerfile, EDN, HCL, HCL2, HOCON, Ignore files, INI, JSON, Jsonnet, TOML, VCL, XML, and YAML


[conftest-structured]: https://github.com/open-policy-agent/conftest/pull/243
[conftest]: https://github.com/open-policy-agent/conftest
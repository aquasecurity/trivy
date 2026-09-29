# Custom Data

Custom checks may require additional data in order to make a resolution. You can pass arbitrary data files to Trivy to be used when evaluating rego checks using the `--config-data` flag. 
Trivy recursively searches the specified data paths for JSON (`*.json`) and YAML (`*.yaml`) files.

For example, consider an allowed list of resources that can be created. 
Instead of hardcoding this information inside your check, you can maintain the list in a separate file.

Example data file:

```yaml
services:
  ports:
    - "20"
    - "20/tcp"
    - "20/udp"
    - "23"
    - "23/tcp"
```

Example usage in a Rego check:

```rego
import data.services

ports := services.ports
```

Example loading the data file:

```bash
trivy config --config-check ./checks --config-data ./data --namespaces user ./configs
```

## Customizing default checks data

Some checks allow you to customize the default data values. To do this, simply pass a data file via `--config-data` (see the section above).

Table of supported data for customizing and their paths:

| Check ID                                                                                                                                                     | Data path                    | Description                                                  |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|--------------------------------------------------------------|
| [KSV0125](https://github.com/aquasecurity/trivy-checks/blob/db2e49de5ff5fd5c8e5cd702b7891f9d9e971a65/checks/kubernetes/uses_untrusted_registry.rego#L76-L78) | `ksv0125.trusted_registries` | List of trusted container registries                         |
| [DS031](https://github.com/aquasecurity/trivy-checks/blob/db2e49de5ff5fd5c8e5cd702b7891f9d9e971a65/checks/docker/leaked_secrets.rego#L135)                   | `ds031.included_envs`        | List of allowed environment variables (merged with defaults) |


Example of overriding trusted registries for `KSV0125`:

```yaml
ksv0125:
  trusted_registries:
    - "my-registry.example.com"
    - "registry.internal.local"
```
# Custom Data

Custom checks may require additional data in order to make a resolution. You can pass arbitrary data files to Trivy to be used when evaluating rego checks using the `--data` flag. 
Trivy recursively searches the specified data paths for JSON (`*.json`) and YAML (`*.yaml`) files.

For example, consider an allowed list of resources that can be created. 
Instead of hardcoding this information inside your policy, you can maintain the list in a separate file.

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
trivy config --config-check ./checks --data ./data --namespaces user ./configs
```

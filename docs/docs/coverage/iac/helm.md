# Helm
Trivy supports two types of Helm scanning, templates and packaged charts.
The following scanners are supported.

| Format   | [Misconfiguration] | [Secret] |
| -------- | :----------------: | :------: |
| Template |         ✓          |    ✓     |
| Chart    |         ✓          |    -     |

## Misconfiguration
Trivy recursively searches directories and scans all found Helm files.

It evaluates variables, functions, and other elements within Helm templates and resolve the chart to Kubernetes manifests then run the Kubernetes checks.
See [here](../../scanner/misconfiguration/policy/builtin.md) for more details on the built-in policies.

### Value overrides
There are a number of options for overriding values in Helm charts.
When override values are passed to the Helm scanner, the values will be used during the Manifest rendering process and will become part of the scanned artifact.

#### Setting inline value overrides
Overrides can be set inline on the command line

```bash
trivy conf --helm-set securityContext.runAsUser=0 ./charts/mySql
```

#### Setting value file overrides
Overrides can be in a file that has the key=value set.

```yaml
# Example override file (overrides.yaml)

securityContext:
  runAsUser: 0
```

```bash
trivy conf --helm-values overrides.yaml ./charts/mySql
``` 

#### Setting value as explicit string
the `--helm-set-string` is the same as `--helm-set` but explicitly retains the value as a string

```bash
trivy config --helm-set-string name=false ./infrastructure/tf
```

#### Setting specific values from files
Specific override values can come from specific files

```bash
trivy conf --helm-set-file environment=dev.values.yaml ./charts/mySql
```

## Secret
The secret scan is performed on plain text files, with no special treatment for Helm.
Secret scanning is not conducted on the contents of packaged Charts, such as tar or tar.gz.

[Misconfiguration]: ../../scanner/misconfiguration/index.md
[Secret]: ../../scanner/secret.md
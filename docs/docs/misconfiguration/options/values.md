# Value Overrides

Value files can be passed for supported scannable config files.

## Terraform value overrides
You can pass `tf-vars` files to Trivy to override default values found in the Terraform HCL code.

```bash
trivy conf --tf-vars dev.terraform.tfvars ./infrastructure/tf
```

## Helm value overrides
There are a number of options for overriding values in Helm charts. When override values are passed to the Helm scanner, the values will be used during the Manifest rendering process and will become part of the scanned artifact.

### Setting inline value overrides
Overrides can be set inline on the command line

```bash
trivy conf --helm-set securityContext.runAsUser=0 ./charts/mySql
```

### Setting value file overrides
Overrides can be in a file that has the key=value set. 

```yaml
# Example override file (overrides.yaml)

securityContext:
  runAsUser: 0
```

```bash
trivy conf --helm-values overrides.yaml ./charts/mySql
``` 

### Setting value as explicit string
the `--helm-set-string` is the same as `--helm-set` but explicitly retains the value as a string

```bash
trivy config --helm-set-string name=false ./infrastructure/tf
```

### Setting specific values from files
Specific override values can come from specific files

```bash
trivy conf --helm-set-file environment=dev.values.yaml ./charts/mySql
```
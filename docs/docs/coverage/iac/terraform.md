# Terraform
Trivy supports the scanners listed in the table below.

|     Scanner      | Supported |
| :--------------: | :-------: |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |

It supports the following formats:

|  Format   | Supported |
| :-------: | :-------: |
|   JSON    |     ✓     |
|    HCL    |     ✓     |
| Plan JSON |     ✓     |

Trivy can scan the results of `terraform plan`.
You can scan by passing the file generated as shown below to Trivy:

```
$ terraform plan --out tfplan.binary
$ terraform show -json tfplan.binary > tfplan.json
```

## Misconfiguration
Trivy recursively searches directories and scans all found Terraform files.
It also evaluates variables, imports, and other elements within Terraform files to detect misconfigurations.

### Value Overrides
You can provide `tf-vars` files to Trivy to override default values specified in the Terraform HCL code.

```bash
trivy conf --tf-vars dev.terraform.tfvars ./infrastructure/tf
```

### Exclude Downloaded Terraform Modules
By default, downloaded modules are also scanned.
If you don't want to scan modules downloaded into the `.terraform` directory, you can use the `--tf-exclude-downloaded-modules` flag.

```bash
trivy conf --tf-exclude-downloaded-modules ./configs
```

## Secret
The secret scan is performed on plain text files, with no special treatment for Terraform.
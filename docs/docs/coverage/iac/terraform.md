# Terraform
Trivy supports the scanners listed in the table below.

|     Scanner      | Supported |
|:----------------:|:---------:|
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |

It supports the following formats:

|     Format    | Supported |
|:-------------:|:---------:|
|     JSON      |     ✓     |
|      HCL      |     ✓     |
| Plan Snapshot |     ✓     |
|   Plan JSON   |     ✓     |

Trivy can scan Terraform Plan files (snapshots) or their JSON representations. To create a Terraform Plan and scan it, run the following command:
```bash
terraform plan --out tfplan
trivy conf tfplan
```

To scan a Terraform Plan representation in JSON format, run the following command:
```bash
terraform show -json tfplan > tfplan.json
trivy conf tfplan.json
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
If you don't want to scan them, you can use the `--tf-exclude-downloaded-modules` flag.

```bash
trivy conf --tf-exclude-downloaded-modules ./configs
```

## Secret
The secret scan is performed on plain text files, with no special treatment for Terraform.
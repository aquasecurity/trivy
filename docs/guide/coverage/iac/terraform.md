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
trivy config tfplan
```

To scan a Terraform Plan representation in JSON format, run the following command:
```bash
terraform show -json tfplan > tfplan.json
trivy config tfplan.json
```

## Misconfiguration
Trivy recursively searches directories and scans all found Terraform files.
It also evaluates variables, imports, and other elements within Terraform files to detect misconfigurations.

### Value Overrides
You can provide `tf-vars` files to Trivy to override default values specified in the Terraform HCL code.

```bash
trivy config --tf-vars dev.terraform.tfvars ./infrastructure/tf
```

### Exclude Downloaded Terraform Modules
By default, downloaded modules are also scanned.
If you don't want to scan them, you can use the `--tf-exclude-downloaded-modules` flag.

```bash
trivy config --tf-exclude-downloaded-modules ./configs
```

## Secret
The secret scan is performed on plain text files, with no special treatment for Terraform.

## Limitations

### Terraform Plan JSON

#### For each and count objects in expression

The plan created by Terraform does not provide complete information about references in expressions that use `each` or `count` objects. For this reason, in some situations it is not possible to establish references between resources that are needed for checks when detecting misconfigurations. An example of such a configuration is:

```hcl
locals {
  buckets = toset(["test"])
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket = each.key
}

resource "aws_s3_bucket_acl" "this" {
  for_each = local.buckets
  bucket = aws_s3_bucket.this[each.key].id
  acl    = "private"
}
```

With this configuration, the plan will not contain information about which attribute of the `aws_s3_bucket` resource is referenced by the `aws_s3_bucket_acl` resource.

See more [here](https://github.com/hashicorp/terraform/issues/30826).
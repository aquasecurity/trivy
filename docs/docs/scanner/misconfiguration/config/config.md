This page describes misconfiguration-specific configuration.

### Enabling a subset of misconfiguration scanners
It's possible to only enable certain misconfiguration scanners if you prefer.
You can do so by passing the `--misconfig-scanners` option.
This flag takes a comma-separated list of configuration scanner types.

```bash
trivy config --misconfig-scanners=terraform,dockerfile .
```

Will only scan for misconfigurations that pertain to Terraform and Dockerfiles.

### Loading custom checks
You can load check files or directories including your custom checks using the `--config-check` flag.
This can be repeated for specifying multiple files or directories.

```bash
trivy config --config-check custom-policy/policy --config-check combine/policy --config-check policy.rego --namespaces user myapp
```

You can load checks bundle as OCI Image from a Container Registry using the `--checks-bundle-repository` flag.

```bash
trivy config --checks-bundle-repository myregistry.local/mychecks --namespaces user myapp
```


### Passing custom data
You can pass directories including your custom data through `--data` option.
This can be repeated for specifying multiple directories.

```bash
cd examples/misconf/custom-data
trivy config --config-check ./my-check --data ./data --namespaces user ./configs
```

For more details, see [Custom Data](../custom/data.md).

### Passing namespaces
By default, Trivy evaluates checks defined in `builtin.*`.
If you want to evaluate custom checks in other packages, you have to specify package prefixes through `--namespaces` option.
This can be repeated for specifying multiple packages.

``` bash
trivy config --config-check ./my-check --namespaces main --namespaces user ./configs
```

### Private Terraform registries
Trivy can download Terraform code from private registries.
To pass credentials you must use the `TF_TOKEN_` environment variables.
You cannot use a `.terraformrc` or `terraform.rc` file, these are not supported by trivy yet.

From the Terraform [docs](https://developer.hashicorp.com/terraform/cli/config/config-file#environment-variable-credentials):

> Environment variable names should have the prefix TF_TOKEN_ added to the domain name, with periods encoded as underscores.
> For example, the value of a variable named `TF_TOKEN_app_terraform_io` will be used as a bearer authorization token when the CLI makes service requests to the hostname `app.terraform.io`.
>
> You must convert domain names containing non-ASCII characters to their punycode equivalent with an ACE prefix.
> For example, token credentials for `例えば.com` must be set in a variable called `TF_TOKEN_xn--r8j3dr99h_com`.
>
> Hyphens are also valid within host names but usually invalid as variable names and may be encoded as double underscores.
> For example, you can set a token for the domain name café.fr as TF_TOKEN_xn--caf-dma_fr or TF_TOKEN_xn____caf__dma_fr.

If multiple variables evaluate to the same hostname, Trivy will choose the environment variable name where the dashes have not been encoded as double underscores.

### Scan arbitrary JSON and YAML configurations
By default, scanning JSON and YAML configurations is disabled, since Trivy does not contain built-in checks for these configurations. To enable it, pass the `json` or `yaml` to `--misconfig-scanners`. See [Enabling a subset of misconfiguration scanners](#enabling-a-subset-of-misconfiguration-scanners) for more information. Trivy will pass each file as is to the checks input.


!!! example
```bash
$ cat iac/serverless.yaml
service: serverless-rest-api-with-pynamodb

frameworkVersion: ">=2.24.0"

plugins:
  - serverless-python-requirements
...

$ cat serverless.rego
# METADATA
# title: Serverless Framework service name not starting with "aws-"
# description: Ensure that Serverless Framework service names start with "aws-"
# schemas:
#   - input: schema["serverless-schema"]
# custom:
#   avd_id: AVD-SF-0001
#   severity: LOW
package user.serverless001

deny[res] {
    not startswith(input.service, "aws-")
    res := result.new(
        sprintf("Service name %q is not allowed", [input.service]),
        input.service
    )
}

$ trivy config --misconfig-scanners=json,yaml --config-check ./serverless.rego --check-namespaces user ./iac
serverless.yaml (yaml)

Tests: 4 (SUCCESSES: 3, FAILURES: 1)
Failures: 1 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

LOW: Service name "serverless-rest-api-with-pynamodb" is not allowed
═════════════════════════════════════════════════════════════════════════════════════════════════════════
Ensure that Serverless Framework service names start with "aws-"
```

!!! note
In the case above, the custom check specified has a metadata annotation for the input schema `input: schema["serverless-schema"]`. This allows Trivy to type check the input IaC files provided.

Optionally, you can also pass schemas using the `config-file-schemas` flag. Trivy will use these schemas for file filtering and type checking in Rego checks.

!!! example
```bash
$ trivy config --misconfig-scanners=json,yaml --config-check ./serverless.rego --check-namespaces user --config-file-schemas ./serverless-schema.json ./iac
```

If the `--config-file-schemas` flag is specified Trivy ensures that each input IaC config file being scanned is type-checked against the schema. If the input file does not match any of the passed schemas, it will be ignored.

If the schema is specified in the check metadata and is in the directory specified in the `--config-check` argument, it will be automatically loaded as specified [here](../custom/schema.md#custom-checks-with-custom-schemas), and will only be used for type checking in Rego.

!!! note
If a user specifies the `--config-file-schemas` flag, all input IaC config files are ensured that they pass type-checking. It is not required to pass an input schema in case type checking is not required. This is helpful for scenarios where you simply want to write a Rego check and pass in IaC input for it. Such a use case could include scanning for a new service which Trivy might not support just yet.

!!! tip
It is also possible to specify multiple input schemas with `--config-file-schema` flag as it can accept a comma separated list of file paths or a directory as input. In the case of multiple schemas being specified, all of them will be evaluated against all the input files.


### Filtering resources by inline comments

Trivy supports ignoring misconfigured resources by inline comments for Terraform, CloudFormation, Helm and Dockerfile configuration files only.

In cases where Trivy can detect comments of a specific format immediately adjacent to resource definitions, it is possible to ignore findings from a single source of resource definition (in contrast to `.trivyignore`, which has a directory-wide scope on all of the files scanned). The format for these comments is `trivy:ignore:<rule>` immediately following the format-specific line-comment [token](https://developer.hashicorp.com/terraform/language/syntax/configuration#comments).


!!!note
    Inline ignore rules only work for checks associated with an existing resource.
    Checks triggered by the absence of a resource (e.g., **AVD-DS-0002** when a Dockerfile lacks a `USER` instruction) cannot be ignored inline.  
    Use a [.trivyignore.yaml](../../../configuration/filtering.md#trivyignoreyaml) file to ignore such checks.


The ignore rule must contain one of the possible check IDs that can be found in its metadata: ID, short code or alias. The `id` from the metadata is not case-sensitive, so you can specify, for example, `AVD-AWS-0089` or `avd-aws-0089`.

For example, to ignore a misconfiguration ID `AVD-GCP-0051` in a Terraform HCL file:

```terraform
#trivy:ignore:AVD-GCP-0051
resource "google_container_cluster" "example" {
  name     = var.cluster_name
  location = var.region
}
```

You can add multiple ignores on the same comment line:
```terraform
#trivy:ignore:AVD-GCP-0051 trivy:ignore:AVD-GCP-0053
resource "google_container_cluster" "example" {
  name     = var.cluster_name
  location = var.region
}
```

You can also specify a long ID, which is formed as follows: `<provider>-<service>-<short-code>`.

As an example, consider the following check metadata:

```yaml
# custom:
  # id: AVD-AWS-0089
  # avd_id: AVD-AWS-0089
  # provider: aws
  # service: s3
  # severity: LOW
  # short_code: enable-logging
```
Long ID would look like the following: `aws-s3-enable-logging`.

Example for CloudFromation:
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
#trivy:ignore:*
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: test-bucket
```

!!!note
    Ignore rules for Helm files should be placed before the YAML object, since only it contains the location data needed for ignoring.

Example for Helm:
```yaml
      serviceAccountName: "testchart.serviceAccountName"
      containers:
        # trivy:ignore:KSV018
        - name: "testchart"
          securityContext:
            runAsUser: 1000
            runAsGroup: 3000
          image: "your-repository/your-image:your-tag"
          imagePullPolicy: "Always"
```
          
#### Expiration Date

You can specify the expiration date of the ignore rule in `yyyy-mm-dd` format. This is a useful feature when you want to make sure that an ignored issue is not forgotten and worth revisiting in the future. For example:
```tf
#trivy:ignore:aws-s3-enable-logging:exp:2024-03-10
resource "aws_s3_bucket" "example" {
  bucket = "test"
}
```

The `aws-s3-enable-logging` check will be ignored until `2024-03-10` until the ignore rule expires.

#### Ignoring by attributes

You can ignore a resource by its attribute value. This is useful when using the `for-each` meta-argument. For example:

```tf
locals {
  ports = ["3306", "5432"]
}

#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=3306]
resource "aws_security_group_rule" "example" {
  for_each                 = toset(local.ports)
  type                     = "ingress"
  from_port                = each.key
  to_port                  = each.key
  protocol                 = "TCP"
  cidr_blocks              = ["0.0.0.0/0"]
  security_group_id        = aws_security_group.example.id
  source_security_group_id = aws_security_group.example.id
}
```

The `aws-ec2-no-public-ingress-sgr` check will be ignored only for the `aws_security_group_rule` resource with port number `5432`. It is important to note that the ignore rule should not enclose the attribute value in quotes, despite the fact that the port is represented as a string.

If you want to ignore multiple resources on different attributes, you can specify multiple ignore rules:

```tf
#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=3306]
#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=5432]
```

You can also ignore a resource on multiple attributes in the same rule:
```tf
locals {
  rules = {
    first = {
      port = 1000
      type = "ingress"
    },
    second = {
      port = 1000
      type = "egress"
    }
  }
}

#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=1000,type=egress]
resource "aws_security_group_rule" "example" {
  for_each = { for k, v in local.rules : k => v }

  type                     = each.value.type
  from_port                = each.value.port
  to_port                  = each.value.port
  protocol                 = "TCP"
  cidr_blocks              = ["0.0.0.0/0"]
  security_group_id        = aws_security_group.example.id
  source_security_group_id = aws_security_group.example.id
}
```

Checks can also be ignored by nested attributes:

```tf
#trivy:ignore:*[logging_config.prefix=myprefix]
resource "aws_cloudfront_distribution" "example" {
  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }
}
```

#### Ignoring module issues

Issues in third-party modules cannot be ignored using the method described above, because you may not have access to modify the module source code. In such a situation you can add ignore rules above the module block, for example:

```tf
#trivy:ignore:aws-s3-enable-logging
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "my-s3-bucket"
}
```

An example of ignoring checks for a specific bucket in a module:
```tf
locals {
  bucket = ["test1", "test2"]
}

#trivy:ignore:*[bucket=test1]
module "s3_bucket" {
  for_each = toset(local.bucket)
  source   = "terraform-aws-modules/s3-bucket/aws"
  bucket   = each.value
}
```

#### Support for Wildcards

You can use wildcards in the `ws` (workspace) and `ignore` sections of the ignore rules.

```tf
# trivy:ignore:aws-s3-*:ws:dev-*
```

This example ignores all checks starting with `aws-s3-` for workspaces matching the pattern `dev-*`.

### Expiration Date

You can specify the expiration date of the ignore rule in `yyyy-mm-dd` format. This is a useful feature when you want to make sure that an ignored issue is not forgotten and worth revisiting in the future. For example:
```tf
#trivy:ignore:aws-s3-enable-logging:exp:2024-03-10
resource "aws_s3_bucket" "example" {
  bucket = "test"
}
```

The `aws-s3-enable-logging` check will be ignored until `2024-03-10` until the ignore rule expires.

#### Ignoring by attributes

You can ignore a resource by its attribute value. This is useful when using the `for-each` meta-argument. For example:

```tf
locals {
  ports = ["3306", "5432"]
}

#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=3306]
resource "aws_security_group_rule" "example" {
  for_each                 = toset(local.ports)
  type                     = "ingress"
  from_port                = each.key
  to_port                  = each.key
  protocol                 = "TCP"
  cidr_blocks              = ["0.0.0.0/0"]
  security_group_id        = aws_security_group.example.id
  source_security_group_id = aws_security_group.example.id
}
```

The `aws-ec2-no-public-ingress-sgr` check will be ignored only for the `aws_security_group_rule` resource with port number `5432`. It is important to note that the ignore rule should not enclose the attribute value in quotes, despite the fact that the port is represented as a string.

If you want to ignore multiple resources on different attributes, you can specify multiple ignore rules:

```tf
#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=3306]
#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=5432]
```

You can also ignore a resource on multiple attributes in the same rule:
```tf
locals {
  rules = {
    first = {
      port = 1000
      type = "ingress"
    },
    second = {
      port = 1000
      type = "egress"
    }
  }
}

#trivy:ignore:aws-ec2-no-public-ingress-sgr[from_port=1000,type=egress]
resource "aws_security_group_rule" "example" {
  for_each = { for k, v in local.rules : k => v }

  type                     = each.value.type
  from_port                = each.value.port
  to_port                  = each.value.port
  protocol                 = "TCP"
  cidr_blocks              = ["0.0.0.0/0"]
  security_group_id        = aws_security_group.example.id
  source_security_group_id = aws_security_group.example.id
}
```

Checks can also be ignored by nested attributes:

```tf
#trivy:ignore:*[logging_config.prefix=myprefix]
resource "aws_cloudfront_distribution" "example" {
  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }
}
```

#### Ignoring module issues

Issues in third-party modules cannot be ignored using the method described above, because you may not have access to modify the module source code. In such a situation you can add ignore rules above the module block, for example:

```tf
#trivy:ignore:aws-s3-enable-logging
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "my-s3-bucket"
}
```

An example of ignoring checks for a specific bucket in a module:
```tf
locals {
  bucket = ["test1", "test2"]
}

#trivy:ignore:*[bucket=test1]
module "s3_bucket" {
  for_each = toset(local.bucket)
  source   = "terraform-aws-modules/s3-bucket/aws"
  bucket   = each.value
}
```

#### Support for Wildcards

You can use wildcards in the `ws` (workspace) and `ignore` sections of the ignore rules.

```tf
# trivy:ignore:aws-s3-*:ws:dev-*
```

This example ignores all checks starting with `aws-s3-` for workspaces matching the pattern `dev-*`.

[custom]: custom/index.md

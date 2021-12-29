# Policy

## Pass custom policies
You can pass directories including your custom policies through `--policy` option.
This can be repeated for specifying multiple directories.

```bash
cd examplex/misconf/
trivy conf --policy custom-policy/policy --policy combine/policy --namespaces user misconf/mixed
```

For more details, see [Custom Policies](../custom/index.md).

!!! tip
    You also need to specify `--namespaces` option.

## Pass custom data
You can pass directories including your custom data through `--data` option.
This can be repeated for specifying multiple directories.

```bash
cd examples/misconf/custom-data
trivy conf --policy ./policy --data ./data --namespaces user ./configs
```

For more details, see [Custom Data](../custom/data.md).

## Pass namespaces
By default, Trivy evaluate policies defined in `appshield.*`.
If you want to evaluate custom policies in other packages, you have to specify package prefixes through `--namespaces` option.
This can be repeated for specifying multiple packages.

``` bash
trivy conf --policy ./policy --namespaces main --namespaces user ./configs
```

## Skip update of built-in policies
`Trivy` downloads built-in policies when it starts operating.
Then, it checks for updates every 24 hours.
You can use the `--skip-policy-update` option to skip it.
If you skip it the first time, the built-in policies will not be loaded.

!!! note
    Even if you specify the option the first time, it will be loaded as Terraform policies are written in Go.

```
trivy conf --skip-policy-update examples/misconf/mixed                                                                                           [~/src/github.com/aquasecurity/trivy]

```

<details>
<summary>Result</summary>

```
2021-07-10T18:04:19.083+0300    INFO    No builtin policies were loaded
2021-07-10T18:04:19.174+0300    INFO    Detected config files: 2

configs/main.tf (terraform)
===========================
Tests: 19 (SUCCESSES: 11, FAILURES: 8, EXCEPTIONS: 0)
Failures: 8 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 1)

+------------------------------------------+------------+------------------------------------------+----------+------------------------------------------+
|                   TYPE                   | MISCONF ID |                  CHECK                   | SEVERITY |                 MESSAGE                  |
+------------------------------------------+------------+------------------------------------------+----------+------------------------------------------+
|   Terraform Security Check powered by    |   AWS004   | Use of plain HTTP.                       | CRITICAL | Resource                                 |
|                  tfsec                   |            |                                          |          | 'aws_alb_listener.my-alb-listener'       |
|                                          |            |                                          |          | uses plain HTTP instead of HTTPS.        |
|                                          |            |                                          |          | -->tfsec.dev/docs/aws/AWS004/            |
+                                          +------------+------------------------------------------+----------+------------------------------------------+
|                                          |   AWS006   | An ingress security group rule allows    |  MEDIUM  | Resource                                 |
|                                          |            | traffic from /0.                         |          | 'aws_security_group_rule.my-rule'        |
|                                          |            |                                          |          | defines a fully open                     |
|                                          |            |                                          |          | ingress security group rule.             |
|                                          |            |                                          |          | -->tfsec.dev/docs/aws/AWS006/            |
+                                          +------------+------------------------------------------+----------+------------------------------------------+
|                                          |   AZU003   | Unencrypted managed disk.                |   HIGH   | Resource 'azurerm_managed_disk.source'   |
|                                          |            |                                          |          | defines an unencrypted managed disk.     |
|                                          |            |                                          |          | -->tfsec.dev/docs/azure/AZU003/          |
+------------------------------------------+------------+------------------------------------------+----------+------------------------------------------+

configs/variables.tf (terraform)
================================
Tests: 1 (SUCCESSES: 1, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```
</details>


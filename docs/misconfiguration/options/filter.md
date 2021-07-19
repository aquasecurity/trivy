# Filter Misconfigurations

## By Severity

Use `--severity` option.

```bash
trivy conf --severity HIGH,CRITICAL examples/misconf/mixed
```

<details>
<summary>Result</summary>

```bash
2021-07-10T17:37:13.267+0300    INFO    Detected config files: 4

configs/Dockerfile (dockerfile)
===============================
Tests: 23 (SUCCESSES: 21, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Specify at least 1 USER                  |
|                           |            |                      |          | command in Dockerfile with               |
|                           |            |                      |          | non-root user as argument                |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+

configs/deployment.yaml (kubernetes)
====================================
Tests: 28 (SUCCESSES: 14, FAILURES: 14, EXCEPTIONS: 0)
Failures: 14 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |   HIGH   | Deployment 'hello-kubernetes' should     |
|                           |            |                                     |          | not specify '/var/run/docker.socker' in  |
|                           |            |                                     |          | 'spec.template.volumes.hostPath.path'    |
|                           |            |                                     |          | -->avd.aquasec.com/appshield/ksv006      |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+

configs/main.tf (terraform)
===========================
Tests: 19 (SUCCESSES: 11, FAILURES: 8, EXCEPTIONS: 0)
Failures: 8 (HIGH: 6, CRITICAL: 1)

+------------------------------------------+------------+------------------------------------------+----------+--------------------------------------------------------+
|                   TYPE                   | MISCONF ID |                  CHECK                   | SEVERITY |                        MESSAGE                         |
+------------------------------------------+------------+------------------------------------------+----------+--------------------------------------------------------+
|   Terraform Security Check powered by    |   AWS003   | AWS Classic resource usage.              |   HIGH   | Resource                                               |
|                  tfsec                   |            |                                          |          | 'aws_db_security_group.my-group'                       |
|                                          |            |                                          |          | uses EC2 Classic. Use a VPC instead.                   |
|                                          |            |                                          |          | -->tfsec.dev/docs/aws/AWS003/                          |
+                                          +------------+------------------------------------------+----------+--------------------------------------------------------+
|                                          |   AWS004   | Use of plain HTTP.                       | CRITICAL | Resource                                               |
|                                          |            |                                          |          | 'aws_alb_listener.my-alb-listener'                     |
|                                          |            |                                          |          | uses plain HTTP instead of HTTPS.                      |
|                                          |            |                                          |          | -->tfsec.dev/docs/aws/AWS004/                          |
+                                          +------------+------------------------------------------+----------+--------------------------------------------------------+
|                                          |   AWS018   | Missing description for security         |   HIGH   | Resource                                               |
|                                          |            | group/security group rule.               |          | 'aws_security_group_rule.my-rule' should               |
|                                          |            |                                          |          | include a description for auditing                     |
|                                          |            |                                          |          | purposes. -->tfsec.dev/docs/aws/AWS018/                |
+                                          +------------+------------------------------------------+          +--------------------------------------------------------+
|                                          |   AWS025   | API Gateway domain name uses outdated    |          | Resource                                               |
|                                          |            | SSL/TLS protocols.                       |          | 'aws_api_gateway_domain_name.empty_security_policy'    |
|                                          |            |                                          |          | defines outdated SSL/TLS policies (not using           |
|                                          |            |                                          |          | TLS_1_2). -->tfsec.dev/docs/aws/AWS025/                |
+                                          +            +                                          +          +--------------------------------------------------------+
|                                          |            |                                          |          | Resource                                               |
|                                          |            |                                          |          | 'aws_api_gateway_domain_name.missing_security_policy'  |
|                                          |            |                                          |          | should include security_policy (defauls to outdated    |
|                                          |            |                                          |          | SSL/TLS policy). -->tfsec.dev/docs/aws/AWS025/         |
+                                          +            +                                          +          +--------------------------------------------------------+
|                                          |            |                                          |          | Resource                                               |
|                                          |            |                                          |          | 'aws_api_gateway_domain_name.outdated_security_policy' |
|                                          |            |                                          |          | defines outdated SSL/TLS policies (not using TLS_1_2). |
|                                          |            |                                          |          | -->tfsec.dev/docs/aws/AWS025/                          |
+                                          +------------+------------------------------------------+          +--------------------------------------------------------+
|                                          |   AZU003   | Unencrypted managed disk.                |          | Resource 'azurerm_managed_disk.source'                 |
|                                          |            |                                          |          | defines an unencrypted managed disk.                   |
|                                          |            |                                          |          | -->tfsec.dev/docs/azure/AZU003/                        |
+------------------------------------------+------------+------------------------------------------+----------+--------------------------------------------------------+

configs/variables.tf (terraform)
================================
Tests: 1 (SUCCESSES: 1, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)
```

</details>

## By Misconfiguration IDs

Use `.trivyignore`.

```bash
$ cat .trivyignore
# Accept the risk
AWS003
AWS018
AWS025

$ trivy conf --severity HIGH,CRITICAL examples/misconf/mixed
```

<details>
<summary>Result</summary>

```bash
2021-07-10T17:38:51.306+0300    INFO    Detected config files: 4

configs/Dockerfile (dockerfile)
===============================
Tests: 23 (SUCCESSES: 21, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Specify at least 1 USER                  |
|                           |            |                      |          | command in Dockerfile with               |
|                           |            |                      |          | non-root user as argument                |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+

configs/deployment.yaml (kubernetes)
====================================
Tests: 28 (SUCCESSES: 14, FAILURES: 14, EXCEPTIONS: 0)
Failures: 14 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV006   | docker.sock is mounted to container |   HIGH   | Deployment 'hello-kubernetes' should     |
|                           |            |                                     |          | not specify '/var/run/docker.socker' in  |
|                           |            |                                     |          | 'spec.template.volumes.hostPath.path'    |
|                           |            |                                     |          | -->avd.aquasec.com/appshield/ksv006      |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+

configs/main.tf (terraform)
===========================
Tests: 19 (SUCCESSES: 11, FAILURES: 8, EXCEPTIONS: 0)
Failures: 8 (HIGH: 1, CRITICAL: 1)

+------------------------------------------+------------+---------------------------+----------+------------------------------------------+
|                   TYPE                   | MISCONF ID |           CHECK           | SEVERITY |                 MESSAGE                  |
+------------------------------------------+------------+---------------------------+----------+------------------------------------------+
|   Terraform Security Check powered by    |   AWS004   | Use of plain HTTP.        | CRITICAL | Resource                                 |
|                  tfsec                   |            |                           |          | 'aws_alb_listener.my-alb-listener'       |
|                                          |            |                           |          | uses plain HTTP instead of HTTPS.        |
|                                          |            |                           |          | -->tfsec.dev/docs/aws/AWS004/            |
+                                          +------------+---------------------------+----------+------------------------------------------+
|                                          |   AZU003   | Unencrypted managed disk. |   HIGH   | Resource 'azurerm_managed_disk.source'   |
|                                          |            |                           |          | defines an unencrypted managed disk.     |
|                                          |            |                           |          | -->tfsec.dev/docs/azure/AZU003/          |
+------------------------------------------+------------+---------------------------+----------+------------------------------------------+

configs/variables.tf (terraform)
================================
Tests: 1 (SUCCESSES: 1, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)
```

</details>

## By Exceptions
See [Exceptions](../policy/exceptions.md)

## Show Successes and Exceptions
Use `--include-non-failures` option to show successes and exceptions as well as failures.

```bash
trivy conf --severity CRITICAL --include-non-failures examples/misconf/mixed
```

<details>
<summary>Result</summary>
```
2021-07-10T17:44:02.049+0300    INFO    Detected config files: 4

configs/Dockerfile (dockerfile)
===============================
Tests: 23 (SUCCESSES: 21, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (CRITICAL: 0)

+---------------------------+------------+------------------------------------------+----------+--------+-----------------+
|           TYPE            | MISCONF ID |                  CHECK                   | SEVERITY | STATUS |     MESSAGE     |
+---------------------------+------------+------------------------------------------+----------+--------+-----------------+
| Dockerfile Security Check |   DS006    | COPY '--from' refers to the current      | CRITICAL |  PASS  | No issues found |
|                           |            | image                                    |          |        |                 |
+                           +------------+------------------------------------------+          +        +                 +
|                           |   DS007    | Multiple ENTRYPOINT instructions are     |          |        |                 |
|                           |            | listed                                   |          |        |                 |
+                           +------------+------------------------------------------+          +        +                 +
|                           |   DS008    | Exposed port is out of range             |          |        |                 |
+                           +------------+------------------------------------------+          +        +                 +
|                           |   DS010    | 'sudo' is used                           |          |        |                 |
+                           +------------+------------------------------------------+          +        +                 +
|                           |   DS011    | COPY with more than two arguments is not |          |        |                 |
|                           |            | ending with slash                        |          |        |                 |
+                           +------------+------------------------------------------+          +        +                 +
|                           |   DS012    | Duplicate aliases are defined in         |          |        |                 |
|                           |            | different FROMs                          |          |        |                 |
+---------------------------+------------+------------------------------------------+----------+--------+-----------------+

...
```
</details>

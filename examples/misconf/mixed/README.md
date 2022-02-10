# Mixed config files
`configs` dir contains multiple types of IaC files.
Trivy identifies config types and passes the input to the appropriate policies.

## Scan
Filter misconfigurations by severity

``` bash
$ trivy conf --severity HIGH,CRITICAL configs
2021-07-09T23:18:00.020+0300    INFO    Detected config files: 4

Dockerfile (dockerfile)
=======================
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

deployment.yaml (kubernetes)
============================
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

main.tf (terraform)
===================
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
|                                          |            |                                          |          | should include security_policy (defaults to outdated   |
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

variables.tf (terraform)
========================
Tests: 1 (SUCCESSES: 1, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)
```


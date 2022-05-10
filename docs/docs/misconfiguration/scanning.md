# Misconfiguration Scanning
Trivy provides built-in policies to detect configuration issues in Docker, Kubernetes, Terraform and CloudFormation.
Also, you can write your own policies in [Rego][rego] to scan JSON, YAML, etc, like [Conftest][conftest].

![misconf](../../imgs/misconf.png)

## Quick start

Simply specify a directory containing IaC files such as Terraform, CloudFormation and Dockerfile.

``` bash
$ trivy config [YOUR_IaC_DIRECTORY]
```


!!! example
    ```
    $ ls build/
    Dockerfile
    $ trivy config ./build
    2021-07-09T10:06:29.188+0300    INFO    Need to update the built-in policies
    2021-07-09T10:06:29.188+0300    INFO    Downloading the built-in policies...
    2021-07-09T10:06:30.520+0300    INFO    Detected config files: 1
    
    Dockerfile (dockerfile)
    =======================
    Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
    Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)
    
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    |           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    | Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
    |                           |            |                      |          | Dockerfile should not be 'root'          |
    |                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    ```

You can also enable misconfiguration detection in container image, filesystem and git repository scanning via `--security-checks config`.

```bash
$ trivy image --security-checks config IMAGE_NAME
```

```bash
$ trivy fs --security-checks config /path/to/dir
```

!!! note
    Misconfiguration detection is not enabled by default in `image`, `fs` and `repo` subcommands.

Unlike the `config` subcommand, `image`, `fs` and `repo` subcommands can also scan for vulnerabilities and secrets at the same time. 
You can specify `--security-checks vuln,config,secret` to enable vulnerability and secret detection as well as misconfiguration detection.


!!! example
    ``` bash
    $ ls myapp/
    Dockerfile Pipfile.lock
    $ trivy fs --security-checks vuln,config,secret --severity HIGH,CRITICAL myapp/
    2021-07-09T12:03:27.564+0300    INFO    Number of language-specific files: 1
    2021-07-09T12:03:27.564+0300    INFO    Detecting pipenv vulnerabilities...
    2021-07-09T12:03:27.566+0300    INFO    Detected config files: 1
    
    Pipfile.lock (pipenv)
    =====================
    Total: 1 (HIGH: 1, CRITICAL: 0)
    
    +----------+------------------+----------+-------------------+---------------+---------------------------------------+
    | LIBRARY  | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
    +----------+------------------+----------+-------------------+---------------+---------------------------------------+
    | httplib2 | CVE-2021-21240   | HIGH     | 0.12.1            | 0.19.0        | python-httplib2: Regular              |
    |          |                  |          |                   |               | expression denial of                  |
    |          |                  |          |                   |               | service via malicious header          |
    |          |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-21240 |
    +----------+------------------+----------+-------------------+---------------+---------------------------------------+
    
    Dockerfile (dockerfile)
    =======================
    Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
    Failures: 1 (HIGH: 1, CRITICAL: 0)
    
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    |           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    | Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
    |                           |            |                      |          | Dockerfile should not be 'root'          |
    |                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
    +---------------------------+------------+----------------------+----------+------------------------------------------+
    ```

In the above example, Trivy detected vulnerabilities of Python dependencies and misconfigurations in Dockerfile.

## Type detection
The specified directory can contain mixed types of IaC files.
Trivy automatically detects config types and applies relevant policies.

For example, the following example holds IaC files for Terraform, CloudFormation, Kubernetes, and Dockerfile in the same directory.

``` bash
$ ls iac/
Dockerfile  deployment.yaml  main.tf
$ trivy conf --severity HIGH,CRITICAL ./iac
```

<details>
<summary>Result</summary>

```
2021-07-09T11:51:08.212+0300    INFO    Need to update the built-in policies
2021-07-09T11:51:08.212+0300    INFO    Downloading the built-in policies...
2021-07-09T11:51:09.527+0300    INFO    Detected config files: 3

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+

deployment.yaml (kubernetes)
============================
Tests: 28 (SUCCESSES: 15, FAILURES: 13, EXCEPTIONS: 0)
Failures: 13 (HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |           CHECK            | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV005   | SYS_ADMIN capability added |   HIGH   | Container 'hello-kubernetes' of          |
|                           |            |                            |          | Deployment 'hello-kubernetes'            |
|                           |            |                            |          | should not include 'SYS_ADMIN' in        |
|                           |            |                            |          | 'securityContext.capabilities.add'       |
|                           |            |                            |          | -->avd.aquasec.com/appshield/ksv005      |
+---------------------------+------------+----------------------------+----------+------------------------------------------+

main.tf (terraform)
===================
Tests: 23 (SUCCESSES: 14, FAILURES: 9, EXCEPTIONS: 0)
Failures: 9 (HIGH: 6, CRITICAL: 1)

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
```

    </details>

You can see the config type next to each file name.

!!! example
``` bash
Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

...

deployment.yaml (kubernetes)
============================
Tests: 28 (SUCCESSES: 15, FAILURES: 13, EXCEPTIONS: 0)
Failures: 13 (HIGH: 1, CRITICAL: 0)

...

main.tf (terraform)
===================
Tests: 23 (SUCCESSES: 14, FAILURES: 9, EXCEPTIONS: 0)
Failures: 9 (HIGH: 6, CRITICAL: 1)

...

bucket.yaml (cloudformation)
============================
Tests: 9 (SUCCESSES: 3, FAILURES: 6, EXCEPTIONS: 0)
Failures: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 2, HIGH: 4, CRITICAL: 0)
```

## Examples
See [here](https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/misconf/mixed)

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[conftest]: https://github.com/open-policy-agent/conftest/


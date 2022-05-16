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
    2022-05-16T13:29:29.952+0100	INFO	Detected config files: 1
    
    Dockerfile (dockerfile)
    =======================
    Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
    Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)
    
    MEDIUM: Specify a tag in the 'FROM' statement for image 'alpine'
    ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.
    
    See https://avd.aquasec.com/misconfig/ds001
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    Dockerfile:1
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    1 [ FROM alpine:latest
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
    2022-05-16T13:42:21.440+0100	INFO	Number of language-specific files: 1
    2022-05-16T13:42:21.440+0100	INFO	Detecting pipenv vulnerabilities...
    2022-05-16T13:42:21.440+0100	INFO	Detected config files: 1
    
    Pipfile.lock (pipenv)
    =====================
    Total: 1 (HIGH: 1, CRITICAL: 0)
    
    ┌──────────┬────────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────────────────────┐
    │ Library  │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                           Title                           │
    ├──────────┼────────────────┼──────────┼───────────────────┼───────────────┼───────────────────────────────────────────────────────────┤
    │ httplib2 │ CVE-2021-21240 │ HIGH     │ 0.12.1            │ 0.19.0        │ python-httplib2: Regular expression denial of service via │
    │          │                │          │                   │               │ malicious header                                          │
    │          │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2021-21240                │
    └──────────┴────────────────┴──────────┴───────────────────┴───────────────┴───────────────────────────────────────────────────────────┘
    
    Dockerfile (dockerfile)
    =======================
    Tests: 17 (SUCCESSES: 16, FAILURES: 1, EXCEPTIONS: 0)
    Failures: 1 (HIGH: 1, CRITICAL: 0)
    
    HIGH: Last USER command in Dockerfile should not be 'root'
    ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.
    
    See https://avd.aquasec.com/misconfig/ds002
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    Dockerfile:3
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    3 [ USER root
    ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
2022-05-16T13:46:31.115+0100	INFO	Detected config files: 3

Dockerfile (dockerfile)
=======================
Tests: 17 (SUCCESSES: 16, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

HIGH: Last USER command in Dockerfile should not be 'root'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:3
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   3 [ USER root
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



deployment.yaml (kubernetes)
============================
Tests: 8 (SUCCESSES: 8, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)


main.tf (terraform)
===================
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 0, CRITICAL: 1)

CRITICAL: Classic resources should not be used.
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

See https://avd.aquasec.com/misconfig/avd-aws-0081
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 main.tf:2-4
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   2 ┌ resource "aws_db_security_group" "sg" {
   3 │
   4 └ }
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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


# Misconfiguration Scanning
Trivy provides built-in checks to detect configuration issues in popular Infrastructure as Code files, such as: Docker, Kubernetes, Terraform, CloudFormation, and more. 
In addition to built-in checks, you can write your own custom checks, as you can see [here][custom].

## Quick start

Simply specify a directory containing IaC files such as Terraform, CloudFormation, Azure ARM templates, Helm Charts and Dockerfile.

```bash
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
    Tests: 23 (SUCCESSES: 22, FAILURES: 1)
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

You can also enable misconfiguration detection in container image, filesystem and git repository scanning via `--scanners misconfig`.

```bash
$ trivy image --scanners misconfig IMAGE_NAME
```

```bash
$ trivy fs --scanners misconfig /path/to/dir
```

!!! note
    Misconfiguration detection is not enabled by default in `image`, `fs` and `repo` subcommands.

Unlike the `config` subcommand, `image`, `fs` and `repo` subcommands can also scan for vulnerabilities and secrets at the same time. 
You can specify `--scanners vuln,misconfig,secret` to enable vulnerability and secret detection as well as misconfiguration detection.


!!! example
    ``` bash
    $ ls myapp/
    Dockerfile Pipfile.lock
    $ trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL myapp/
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
    Tests: 17 (SUCCESSES: 16, FAILURES: 1)
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
Trivy automatically detects config types and applies relevant checks.

For example, the following example holds IaC files for Terraform, CloudFormation, Kubernetes, Helm Charts, and Dockerfile in the same directory.

``` bash
$ ls iac/
Dockerfile  deployment.yaml  main.tf mysql-8.8.26.tar
$ trivy config --severity HIGH,CRITICAL ./iac
```

<details>
<summary>Result</summary>

```bash
2022-06-06T11:01:21.142+0100	INFO	Detected config files: 8

Dockerfile (dockerfile)

Tests: 21 (SUCCESSES: 20, FAILURES: 1)
Failures: 1 (MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Specify at least 1 USER command in Dockerfile with non-root user as argument
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



deployment.yaml (kubernetes)

Tests: 20 (SUCCESSES: 15, FAILURES: 5)
Failures: 5 (MEDIUM: 4, HIGH: 1, CRITICAL: 0)

MEDIUM: Container 'hello-kubernetes' of Deployment 'hello-kubernetes' should set 'securityContext.allowPrivilegeEscalation' to false
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 deployment.yaml:16-19
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌       - name: hello-kubernetes
  17 │         image: hello-kubernetes:1.5
  18 │         ports:
  19 └         - containerPort: 8080
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


HIGH: Deployment 'hello-kubernetes' should not specify '/var/run/docker.socker' in 'spec.template.volumes.hostPath.path'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Mounting docker.sock from the host can give the container full root access to the host.

See https://avd.aquasec.com/misconfig/ksv006
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 deployment.yaml:6-29
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   6 ┌   replicas: 3
   7 │   selector:
   8 │     matchLabels:
   9 │       app: hello-kubernetes
  10 │   template:
  11 │     metadata:
  12 │       labels:
  13 │         app: hello-kubernetes
  14 └     spec:
  ..   
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


MEDIUM: Container 'hello-kubernetes' of Deployment 'hello-kubernetes' should set 'securityContext.runAsNonRoot' to true
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 deployment.yaml:16-19
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  16 ┌       - name: hello-kubernetes
  17 │         image: hello-kubernetes:1.5
  18 │         ports:
  19 └         - containerPort: 8080
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


MEDIUM: Deployment 'hello-kubernetes' should not set 'spec.template.volumes.hostPath'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
HostPath volumes must be forbidden.

See https://avd.aquasec.com/misconfig/ksv023
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 deployment.yaml:6-29
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   6 ┌   replicas: 3
   7 │   selector:
   8 │     matchLabels:
   9 │       app: hello-kubernetes
  10 │   template:
  11 │     metadata:
  12 │       labels:
  13 │         app: hello-kubernetes
  14 └     spec:
  ..   
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


MEDIUM: Deployment 'hello-kubernetes' should set 'securityContext.sysctl' to the allowed values
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node.

See https://avd.aquasec.com/misconfig/ksv026
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 deployment.yaml:6-29
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   6 ┌   replicas: 3
   7 │   selector:
   8 │     matchLabels:
   9 │       app: hello-kubernetes
  10 │   template:
  11 │     metadata:
  12 │       labels:
  13 │         app: hello-kubernetes
  14 └     spec:
  ..   
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



mysql-8.8.26.tar:templates/primary/statefulset.yaml (helm)

Tests: 20 (SUCCESSES: 18, FAILURES: 2)
Failures: 2 (MEDIUM: 2, HIGH: 0, CRITICAL: 0)

MEDIUM: Container 'mysql' of StatefulSet 'mysql' should set 'securityContext.allowPrivilegeEscalation' to false
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.

See https://avd.aquasec.com/misconfig/ksv001
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 mysql-8.8.26.tar:templates/primary/statefulset.yaml:56-130
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  56 ┌         - name: mysql
  57 │           image: docker.io/bitnami/mysql:8.0.28-debian-10-r23
  58 │           imagePullPolicy: "IfNotPresent"
  59 │           securityContext:
  60 │             runAsUser: 1001
  61 │           env:
  62 │             - name: BITNAMI_DEBUG
  63 │               value: "false"
  64 └             - name: MYSQL_ROOT_PASSWORD
  ..   
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


MEDIUM: Container 'mysql' of StatefulSet 'mysql' should set 'securityContext.runAsNonRoot' to true
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.

See https://avd.aquasec.com/misconfig/ksv012
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 mysql-8.8.26.tar:templates/primary/statefulset.yaml:56-130
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  56 ┌         - name: mysql
  57 │           image: docker.io/bitnami/mysql:8.0.28-debian-10-r23
  58 │           imagePullPolicy: "IfNotPresent"
  59 │           securityContext:
  60 │             runAsUser: 1001
  61 │           env:
  62 │             - name: BITNAMI_DEBUG
  63 │               value: "false"
  64 └             - name: MYSQL_ROOT_PASSWORD
  ..   
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

</details>

You can see the config type next to each file name.

!!! example
``` bash
Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1)
Failures: 1 (HIGH: 1, CRITICAL: 0)

...

deployment.yaml (kubernetes)
============================
Tests: 28 (SUCCESSES: 15, FAILURES: 13)
Failures: 13 (MEDIUM: 4, HIGH: 1, CRITICAL: 0)

...

main.tf (terraform)
===================
Tests: 23 (SUCCESSES: 14, FAILURES: 9)
Failures: 9 (HIGH: 6, CRITICAL: 1)

...

bucket.yaml (cloudformation)
============================
Tests: 9 (SUCCESSES: 3, FAILURES: 6)
Failures: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 2, HIGH: 4, CRITICAL: 0)

...

mysql-8.8.26.tar:templates/primary/statefulset.yaml (helm)
==========================================================
Tests: 20 (SUCCESSES: 18, FAILURES: 2)
Failures: 2 (MEDIUM: 2, HIGH: 0, CRITICAL: 0)
```

## Scan raw configurations
IaC configurations from cloud providers such as Terraform, CloudFormation, and ARM are converted into a unified structure that is exported to Rego. Checks are developed only for the unified structure, not for each configuration type with its own structure. This avoids duplication and simplifies maintenance. Using the unified structure has a limitation: it is not possible to create checks for resources or attributes that are not exported.

The `--raw-config-scanners` flag allows scanning the raw configuration — that is, evaluated but not converted into the unified structure. Currently, only `terraform` is supported.

!!! note
    The raw configuration scanner does not work on its own. To use `--raw-config-scanners`, you must also specify the corresponding `--misconfig-scanners`. The report will include results from both scanners.

For more information on custom checks and exported data schemas, see [here](../misconfiguration/custom/index.md).

Example check:
```rego
# METADATA
# title: AWS required resource tags
# description: Ensure required tags are set on AWS resources
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id:  USR-TFRAW-0001
#   severity: CRITICAL
#   short_code: required-aws-resource-tags
#   recommended_actions: Add the required tags to AWS resources.
#   input:
#     selector:
#     - type: terraform-raw
package user.terraform.required_aws_tags

import rego.v1

resource_types_to_check := {"aws_s3_bucket"}

resources_to_check := {block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type in resource_types_to_check
}

required_tags := {"Access", "Owner"}

deny contains res if {
	some block in resources_to_check
	not block.attributes.tags
	res := result.new(
		sprintf("The resource %q does not contain the following required tags: %v", [block.type, required_tags]),
		block,
	)
}

deny contains res if {
	some block in resources_to_check
	tags_attr := block.attributes.tags
	tags := object.keys(tags_attr.value)
	missing_tags := required_tags - tags
	count(missing_tags) > 0
	res := result.new(
		sprintf("The resource %q does not contain the following required tags: %v", [block.type, missing_tags]),
		tags_attr,
	)
}
```

Running Trivy:
```bash
trivy conf main.tf \
  --check-namespaces user \
  --config-check examples/terraform-raw/required-aws-tags.rego \
  --misconfig-scanners terraform --raw-config-scanners terraform
```

Example output:
```bash
main.tf (terraform)

Tests: 10 (SUCCESSES: 0, FAILURES: 10)
Failures: 10 (UNKNOWN: 0, LOW: 2, MEDIUM: 1, HIGH: 6, CRITICAL: 1)

 (CRITICAL): The resource "aws_s3_bucket" does not contain the following required tags: {"Access"}
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Ensure required tags are set on AWS resources
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 main.tf:3-5
   via main.tf:1-6 (aws_s3_bucket.this)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   resource "aws_s3_bucket" "this" {
   2     bucket = "test"
   3 ┌   tags = {
   4 │     Owner: "user"
   5 └   }
   6   }
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## External connectivity
Trivy needs to connect to the internet to download the checks bundle. If you are running Trivy in an air-gapped environment, or an tightly controlled network, please refer to the [Advanced Network Scenarios document](../../advanced/air-gap.md).

## Configuration
More misconfiguration scanning specific configurations can be found [here](../misconfiguration/config/config.md).

[custom]: custom/index.md
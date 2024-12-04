# Built-in Compliance Reports

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy’s compliance flag lets you curate a specific set of checks into a report. In a typical Trivy scan, there are hundreds of different checks for many different components and configurations, but sometimes you already know which specific checks you are interested in. Often this would be an industry accepted set of checks such as CIS, or some vendor specific guideline, or your own organization policy that you want to comply with. These are all possible using the flexible compliance infrastructure that's built into Trivy. Compliance reports are defined as simple YAML documents that select checks to include in the report.

## Usage

Compliance report is currently supported in the following targets (trivy sub-commands):

- `trivy image`
- `trivy k8s`

Add the `--compliance` flag to the command line, and set it's value to desired report.
For example: `trivy k8s cluster --compliance k8s-nsa` (see below for built-in and custom reports)

### Options

The following flags are compatible with `--compliance` flag and allows customizing it's output:

| flag               | effect                                                                               |
|--------------------|--------------------------------------------------------------------------------------|
| `--report summary` | shows a summary of the results. for every control shows the number of failed checks. |
| `--report all`     | shows fully detailed results. for every control shows where it failed and why.       |
| `--format table`   | shows results in textual table format (good for human readability).                  |
| `--format json`    | shows results in json format (good for machine readability).                         |

## Built-in compliance

Trivy has a number of built-in compliance reports that you can asses right out of the box.
to specify a built-in compliance report, select it by ID like `trivy --compliance <compliance_id>`.

For the list of built-in compliance reports, please see the relevant section:

- [Docker compliance](../target/container_image.md#compliance)
- [Kubernetes compliance](../target/kubernetes.md#compliance)
- [AWS compliance](../target/aws.md#compliance)

## Contribute a Built-in Compliance Report

### Define a Compliance spec, based on CIS benchmark or other specs

Here is an example for CIS compliance report:

```yaml
---
spec:
  id: k8s-cis-1.23
  title: CIS Kubernetes Benchmarks v1.23
  description: CIS Kubernetes Benchmarks
  platform: k8s
  type: cis
  version: '1.23'
  relatedResources:
  - https://www.cisecurity.org/benchmark/kubernetes
  controls:
  - id: 1.1.1
    name: Ensure that the API server pod specification file permissions are set to
      600 or more restrictive
    description: Ensure that the API server pod specification file has permissions
      of 600 or more restrictive
    checks:
    - id: AVD-KCV-0073
    commands:
    - id: CMD-0001
    severity: HIGH

```

### Compliance ID

ID field is the name used to execute the compliance scan via trivy
example:

```sh
trivy k8s --compliance k8s-cis-1.23
```

ID naming convention: {platform}-{type}-{version}

### Compliance Platform

The platform field specifies the type of platform on which to run this compliance report.
Supported platforms:

- k8s (native kubernetes cluster)
- eks (elastic kubernetes service)
- aks (azure kubernetes service)
- gke (google kubernetes engine)
- rke2 (rancher kubernetes engine v2)
- ocp (OpenShift Container Platform)
- docker (docker engine)
- aws (amazon web services)

### Compliance Type

The type field specifies the kind compliance report.

- cis (Center for Internet Security)
- nsa (National Security Agency)
- pss (Pod Security Standards)

### Compliance Version

The version field specifies the version of the compliance report.

- 1.23

### Compliance Check ID

Specify the check ID that needs to be evaluated based on the information collected from the command data output to assess the control.

Example of how to define check data under [checks folder](https://github.com/aquasecurity/trivy-checks/tree/main/checks):

```sh
# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet.conf file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0073
#   avd_id: AVD-KCV-0073
#   severity: HIGH
#   short_code: ensure-kubelet.conf-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the kubelet.conf file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0073

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_file_permission(sp) := {"kubeletConfFilePermissions": violation} {
 sp.kind == "NodeInfo"
 sp.type == types[_]
 violation := {permission | permission = sp.info.kubeletConfFilePermissions.values[_]; permission > 600}
 count(violation) > 0
}

deny[res] {
 output := validate_kubelet_file_permission(input)
 msg := "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
 res := result.new(msg, output)
}
```

### Compliance Command ID

***Note:*** This field is not mandatory, it is relevant to k8s compliance report when node-collector is in use

Specify the command ID (#ref) that needs to be executed to collect the information required to evaluate the control.

Example of how to define command data under [commands folder](https://github.com/aquasecurity/trivy-checks/tree/main/commands)

```yaml
---
- id: CMD-0001
  key: kubeletConfFilePermissions
  title: kubelet.conf file permissions
  nodeType: worker
  audit: stat -c %a $kubelet.kubeconfig
  platfroms:
    - k8s
    - aks
```

#### Command ID

Find the next command ID by running the command on [trivy-checks project](https://github.com/aquasecurity/trivy-checks).

```sh
make command-id
```

#### Command Key

- Re-use an existing key or specifiy a new one (make sure key name has no spaces)

Note: The key value should match the key name evaluated by the Rego check.

### Command Title

Represent the purpose of the command

### Command NodeType

Specify the node type on which the command is supposed to run.

- worker
- master

### Command Audit

Specify here the shell command to be used please make sure to add error supression (2>/dev/null)

### Command Platforms

The list of platforms that support this command. Name should be taken from this list [Platforms](#compliance-platform)

### Command Config Files

The commands use a configuration file that helps obtain the paths to binaries and configuration files based on different platforms (e.g., Rancher, native Kubernetes, etc.).

For example:

```yaml
kubelet:
    bins:
      - kubelet
      - hyperkube kubelet
    confs:
      - /etc/kubernetes/kubelet-config.yaml
      - /var/lib/kubelet/config.yaml
```

### Commands Files Location

Currently checks files location are :`https://github.com/aquasecurity/trivy-checks/tree/main/checks`

Command files location: `https://github.com/aquasecurity/trivy-checks/tree/main/commands`
under command file

Note: command config files will be located under `https://github.com/aquasecurity/trivy-checks/tree/main/commands` as well

### Node-collector output

The node collector will read commands and execute each command, and incorporate the output into the NodeInfo resource.

example:

```json
{
  "apiVersion": "v1",
  "kind": "NodeInfo",
  "metadata": {
    "creationTimestamp": "2023-01-04T11:37:11+02:00"
  },
  "type": "master",
  "info": {
    "adminConfFileOwnership": {
      "values": [
        "root:root"
      ]
    },
    "adminConfFilePermissions": {
      "values": [
        600
      ]
    }
    ...
  }
}
```

## Custom compliance

You can create your own custom compliance report. A compliance report is a simple YAML document in the following format:

```yaml
spec:
  id: "k8s-myreport" # report unique identifier. this should not container spaces.
  title: "My custom Kubernetes report" # report title. Any one-line title.
  description: "Describe your report" # description of the report. Any text.
  relatedResources :
    - https://some.url # useful references. URLs only.
  version: "1.0" # spec version (string)
  controls:
    - name: "Non-root containers" # Name for the control (appears in the report as is). Any one-line name.
      description: 'Check that container is not running as root' # Description (appears in the report as is). Any text.
      id: "1.0" # control identifier (string)
      checks:   # list of existing Trivy checks that define the control
        - id: AVD-KSV-0012 # check ID. Must start with `AVD-` or `CVE-` 
      severity: "MEDIUM" # Severity for the control (note that checks severity isn't used)
    - name: "Immutable container file systems"
      description: 'Check that container root file system is immutable'
      id: "1.1"
      checks:
        - id: AVD-KSV-0014
      severity: "LOW"
```

The check id field (`controls[].checks[].id`) is referring to existing check by it's "AVD ID". This AVD ID is easily located in the check's source code metadata header, or by browsing [Aqua vulnerability DB](https://avd.aquasec.com/), specifically in the [Misconfigurations](https://avd.aquasec.com/misconfig/) and [Vulnerabilities](https://avd.aquasec.com/nvd) sections.

Once you have a compliance spec, you can select it by file path: `trivy --compliance @</path/to/compliance.yaml>` (note the `@` indicating file path instead of report id).

# Kubernetes

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

## CLI
The Trivy K8s CLI allows you to scan your Kubernetes cluster for 

- [Vulnerabilities](#vulnerability)
- [Misconfigurations](#misconfigurations)
- [Secrets](#secrets)
 
You can either run the CLI locally or integrate it into your CI/CD pipeline.
The difference to the Trivy CLI is that the Trivy K8s CLI allows you to scan running workloads directly within your cluster.

If you are looking for continuous cluster audit scanning, have a look at the Trivy K8s operator below.

Trivy uses your local kubectl configuration to access the API server to list artifacts.

### Commands

Scan a full cluster and generate a simple summary report:

```
$ trivy k8s --report=summary cluster
```

![k8s Summary Report](../../imgs/trivy-k8s.png)

The summary report is the default. To get all of the detail the output contains, use `--report all`.

Filter by severity:

```
$ trivy k8s --severity=CRITICAL --report=all cluster
```

Filter by scanners (Vulnerabilities, Secrets or Misconfigurations):

```
$ trivy k8s --scanners=secret --report=summary cluster
# or
$ trivy k8s --scanners=config --report=summary cluster
```

Scan a specific namespace:

```
$ trivy k8s -n kube-system --report=summary all
```

Use a specific kubeconfig file:

```
$ trivy k8s --kubeconfig ~/.kube/config2 -n kube-system --report=summary all
```

Scan a specific resource and get all the output:

```
$ trivy k8s deployment appname
```

Scan all deploys, or deploys and configmaps:

```
$ trivy k8s --report=summary deployment
$ trivy k8s --report=summary deployment,configmaps
```

If you want to pass in flags before scanning specific workloads, you will have to do it before the resource name.
For example, scanning a deployment in the app namespace of your Kubernetes cluster for critical vulnerabilities would be done through the following command:

```
$ trivy k8s -n app --severity=CRITICAL deployment/appname
```
This is specific to all Trivy CLI commands.

The supported formats are `table`, which is the default, and `json`.
To get a JSON output on a full cluster scan:

```
$ trivy k8s --format json -o results.json cluster
```

<details>
<summary>Result</summary>

```json
{
  "ClusterName": "minikube",
  "Vulnerabilities": [
    {
      "Namespace": "default",
      "Kind": "Deployment",
      "Name": "app",
      "Results": [
        {
          "Target": "ubuntu:latest (ubuntu 22.04)",
          "Class": "os-pkgs",
          "Type": "ubuntu",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2016-2781",
              "PkgName": "coreutils",
              "InstalledVersion": "8.32-4.1ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2781",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "coreutils: Non-privileged session can escape to the parent session in chroot",
              "Description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-20"
              ],
              "VendorSeverity": {
                "cbl-mariner": 2,
                "nvd": 2,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
                  "V2Score": 2.1,
                  "V3Score": 6.5
                },
                "redhat": {
                  "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                  "V2Score": 6.2,
                  "V3Score": 8.6
                }
              },
              "References": [
                "http://seclists.org/oss-sec/2016/q1/452",
                "http://www.openwall.com/lists/oss-security/2016/02/28/2",
                "http://www.openwall.com/lists/oss-security/2016/02/28/3",
                "https://access.redhat.com/security/cve/CVE-2016-2781",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2781",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                "https://lore.kernel.org/patchwork/patch/793178/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-2781"
              ],
              "PublishedDate": "2017-02-07T15:59:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            }
          ]
        }
      ]
    }
  ],
  "Misconfigurations": [
    {
      "Namespace": "default",
      "Kind": "Deployment",
      "Name": "app",
      "Results": [
        {
          "Target": "Deployment/app",
          "Class": "config",
          "Type": "kubernetes",
          "MisconfSummary": {
            "Successes": 20,
            "Failures": 19,
            "Exceptions": 0
          },
          "Misconfigurations": [
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV001",
              "Title": "Process can elevate its own privileges",
              "Description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.allowPrivilegeEscalation' to false",
              "Namespace": "builtin.kubernetes.KSV001",
              "Query": "data.builtin.kubernetes.KSV001.deny",
              "Resolution": "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv001",
              "References": [
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
                "https://avd.aquasec.com/misconfig/ksv001"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV003",
              "Title": "Default capabilities not dropped",
              "Description": "The container should drop all default capabilities and add only those that are needed for its execution.",
              "Message": "Container 'app' of Deployment 'app' should add 'ALL' to 'securityContext.capabilities.drop'",
              "Namespace": "builtin.kubernetes.KSV003",
              "Query": "data.builtin.kubernetes.KSV003.deny",
              "Resolution": "Add 'ALL' to containers[].securityContext.capabilities.drop.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv003",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
                "https://avd.aquasec.com/misconfig/ksv003"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            }
          ]
        }
      ]
    },
    {
      "Namespace": "default",
      "Kind": "ConfigMap",
      "Name": "kube-root-ca.crt"
    }
  ]
}

```

</details>



### Infra checks

Trivy by default scans kubernetes infra components (apiserver, controller-manager, scheduler and etcd)
if they exist under the `kube-system` namespace. For example, if you run a full cluster scan, or scan all
components under `kube-system` with commands:

```
$ trivy k8s cluster --report summary # full cluster scan
$ trivy k8s all -n kube-system --report summary # scan all components under kube-system
```

A table will be printed about misconfigurations found on kubernetes core components:

```
Summary Report for minikube
┌─────────────┬──────────────────────────────────────┬─────────────────────────────┐
│  Namespace  │               Resource               │ Kubernetes Infra Assessment │
│             │                                      ├────┬────┬────┬─────┬────────┤
│             │                                      │ C  │ H  │ M  │ L   │   U    │
├─────────────┼──────────────────────────────────────┼────┼────┼────┼─────┼────────┤
│ kube-system │ Pod/kube-apiserver-minikube          │    │    │ 1  │ 10  │        │
│ kube-system │ Pod/kube-controller-manager-minikube │    │    │    │ 3   │        │
│ kube-system │ Pod/kube-scheduler-minikube          │    │    │    │ 1   │        │
└─────────────┴──────────────────────────────────────┴────┴────┴────┴─────┴────────┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN
```

The infra checks are based on CIS Benchmarks recommendations for kubernetes.


If you want filter only for the infra checks, you can use the flag `--components` along with the `--scanners=config`

```
$ trivy k8s cluster --report summary --components=infra --scanners=config # scan only infra
```

Or, to filter for all other checks besides the infra checks, you can:

```
$ trivy k8s cluster --report summary --components=workload --scanners=config # scan all components besides infra
```

If you wish to exclude nodes from being scanned, you can use the flag `--exclude-nodes` with the node labels

```
trivy k8s cluster --report summary --exclude-nodes kubernetes.io/arch:arm6
```

### Compliance
This section describes Kubernetes specific compliance reports.
For an overview of Trivy's Compliance feature, including working with custom compliance, check out the [Compliance documentation](../compliance/compliance.md).

#### Built in reports

The following reports are available out of the box:

| Compliance                                   | Name for command     | More info                                                                                                           |
|----------------------------------------------|----------------------|---------------------------------------------------------------------------------------------------------------------|
| NSA, CISA Kubernetes Hardening Guidance v1.2 | `k8s-nsa`            | [Link](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) |
| CIS Benchmark for Kubernetes v1.23           | `k8s-cis`            | [Link](https://www.cisecurity.org/benchmark/kubernetes)                                                             |
| Pod Security Standards, Baseline             | `k8s-pss-baseline`   | [Link](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline)                               |
| Pod  Security Standards, Restricted          | `k8s-pss-restricted` | [Link](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)                             |

#### Examples

Scan a full cluster and generate a compliance summary report:

```
$ trivy k8s cluster --compliance=<compliance_id> --report summary
```

***Note*** : The `Issues` column represent the total number of failed checks for this control.


Get all of the detailed output for checks:

```
trivy k8s cluster --compliance=<compliance_id> --report all
```

Report result in JSON format:

```
trivy k8s cluster --compliance=<compliance_id> --report summary --format json
```

```
trivy k8s cluster --compliance=<compliance_id> --report all --format json
```

## Operator
Trivy has a native [Kubernetes Operator][operator] which continuously scans your Kubernetes cluster for security issues, and generates security reports as Kubernetes [Custom Resources][crd]. It does it by watching Kubernetes for state changes and automatically triggering scans in response to changes, for example initiating a vulnerability scan when a new Pod is created.

> Kubernetes-native security toolkit. ([Documentation][trivy-operator]).

<figure>
  <figcaption>Workload reconcilers discover K8s controllers, manage scan jobs, and create VulnerabilityReport and ConfigAuditReport objects.</figcaption>
</figure>

[operator]: https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
[crd]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[trivy-operator]: https://aquasecurity.github.io/trivy-operator/latest

## Scanners
### Vulnerability
#### OS packages
[OS packages](../scanner/vulnerability.md#os-packages) scanning is enabled by default.

#### Language-specific packages
[Language-specific packages](../scanner/vulnerability.md#language-specific-packages) scanning is enabled by default.

#### Kubernetes components (control plane, node and addons)
Currently only discovery from `KBOM` files is supported for [Kubernetes components](../scanner/vulnerability.md#kubernetes-components-control-plane-node-and-addons).

This means you need to get a report of your cluster in [KBOM format](#kbom).
After that, scan this file:
```shell
$ trivy k8s --format cyclonedx cluster -o kbom.json
$ trivy sbom kbom.json
2023-09-28T22:52:25.707+0300    INFO    Vulnerability scanning is enabled
2023-09-28T22:52:25.707+0300    INFO    Detected SBOM format: cyclonedx-json
2023-09-28T22:52:25.717+0300    WARN    No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.
2023-09-28T22:52:25.717+0300    WARN    e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"
2023-09-28T22:52:25.717+0300    INFO    Detected OS: debian gnu/linux
2023-09-28T22:52:25.717+0300    WARN    unsupported os : debian gnu/linux
2023-09-28T22:52:25.717+0300    INFO    Number of language-specific files: 3
2023-09-28T22:52:25.717+0300    INFO    Detecting kubernetes vulnerabilities...
2023-09-28T22:52:25.718+0300    INFO    Detecting gobinary vulnerabilities...

Kubernetes (kubernetes)

Total: 2 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

┌────────────────┬────────────────┬──────────┬────────┬───────────────────┬─────────────────────────────────┬──────────────────────────────────────────────────┐
│    Library     │ Vulnerability  │ Severity │ Status │ Installed Version │          Fixed Version          │                      Title                       │
├────────────────┼────────────────┼──────────┼────────┼───────────────────┼─────────────────────────────────┼──────────────────────────────────────────────────┤
│ k8s.io/kubelet │ CVE-2021-25749 │ HIGH     │ fixed  │ 1.24.0            │ 1.22.14, 1.23.11, 1.24.5        │ runAsNonRoot logic bypass for Windows containers │
│                │                │          │        │                   │                                 │ https://avd.aquasec.com/nvd/cve-2021-25749       │
│                ├────────────────┼──────────┤        │                   ├─────────────────────────────────┼──────────────────────────────────────────────────┤
│                │ CVE-2023-2431  │ LOW      │        │                   │ 1.24.14, 1.25.9, 1.26.4, 1.27.1 │ Bypass of seccomp profile enforcement            │
│                │                │          │        │                   │                                 │ https://avd.aquasec.com/nvd/cve-2023-2431        │
└────────────────┴────────────────┴──────────┴────────┴───────────────────┴─────────────────────────────────┴──────────────────────────────────────────────────┘
```

### Misconfigurations
It is enabled by default.
See [here](../scanner/misconfiguration/index.md) for the detail.

### Secrets
It is enabled by default.
See [here](../scanner/secret.md) for the detail.

## SBOM

Trivy supports the generation of Kubernetes Bill of Materials (KBOM) for kubernetes cluster control plane components, node components and addons.

## KBOM

KBOM, Kubernetes Bill of Materials, is a manifest of all the important components that make up your Kubernetes cluster – Control plane components, Node Components, and Addons, including their versions and images. Which “api-server” version are you currently running? Which flavor of “kubelet” is running on each node? What kind of etcd or storage are you currently using? And most importantly – are there any vulnerabilities known to affect these components? These are all questions that KBOM can help you answer.
Trivy can generate KBOM in CycloneDX format:

```sh
trivy k8s cluster --format cyclonedx
```
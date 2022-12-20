# Kubernetes Compliance

## NSA Compliance Report

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

The Trivy K8s CLI allows you to scan your Kubernetes cluster resources and generate the `NSA, CISA Kubernetes Hardening Guidance` report

[NSA, CISA Kubernetes Hardening Guidance v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) cybersecurity technical report is produced by trivy and validate the following control checks :

| NAME                                                     | DESCRIPTION                                                                                             |          |
|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------|---------------|
| Non-root containers                                      | Check that container is not running as root                                                       |
| Immutable container file systems                         | Check that container root file system is immutable                                                  |
| Preventing privileged containers                         | Controls whether Pods can run privileged containers                                                 |
| Share containers process namespaces                      | Controls whether containers can share process namespaces                                                 |
| Share host process namespaces                            | Controls whether share host process namespaces                                                 |
| Use the host network                                     | Controls whether containers can use the host network                                                    |
| Run with root privileges or with root group membership   | Controls whether container applications can run with <br/>root privileges or with root group membership                   |
| Restricts escalation to root privileges                  | Control check restrictions escalation to root privileges                                                 |
| Sets the SELinux context of the container                | Control checks if pod sets the SELinux context of the container                                                  |
| Restrict a container's access to resources with AppArmor | Control checks the restriction of containers access to resources with AppArmor                                    | 
| Sets the seccomp profile used to sandbox containers      | Control checks the sets the seccomp profile used to sandbox containers                                                 |
| Protecting Pod service account tokens                    | Control check whether disable secret token been mount ,automountServiceAccountToken: false                        | 
| Namespace kube-system should not be used by users        | Control check whether Namespace kube-system is not be used by users                                                      |
| Pod and/or namespace Selectors usage                     | Control check validate the pod and/or namespace Selectors usage                                                      |
| Use CNI plugin that supports NetworkPolicy API           | Control check whether check cni plugin installed                                                  |
| Use ResourceQuota policies to limit resources            | Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace                  | 
| Use LimitRange policies to limit resources               | Control check the use of LimitRange policy limit resource usage for namespaces or nodes                              |
| Control plan disable insecure port                       | Control check whether control plan disable insecure port                                                       |
| Encrypt etcd communication                               | Control check whether etcd communication is encrypted                                                  |
| Ensure kube config file permission                       | Control check whether kube config file permissions                                                |
| Check that encryption resource has been set              | Control checks whether encryption resource has been set                                                        |
| Check encryption provider                                | Control checks whether encryption provider has been set                                                        |
| Make sure anonymous-auth is unset                        | Control checks whether anonymous-auth is unset                                                      |
| Make sure -authorization-mode=RBAC                       | Control check whether RBAC permission is in use                                                        |
| Audit policy is configure                                | Control check whether audit policy is configure                                                  |
| Audit log path is configure                              | Control check whether audit log path is configure                                                  |
| Audit log aging                                          | Control check whether audit log aging is configure                                                  |

## CLI Commands

Scan a full cluster and generate a complliance NSA summary report:

```
$ trivy k8s cluster --compliance=nsa --report summary
```

![k8s Summary Report](../../../imgs/trivy-nsa-summary.png)

***Note*** : The `Issues` column represent the total number of failed checks for this control.


An additional report is supported to get all of the detail the output contains, use `--report all`
```
$ trivy k8s cluster --compliance=nsa --report all
```
Report also supported in json format examples :

```
$ trivy k8s cluster --compliance=nsa --report summary --format json
```

```
$ trivy k8s cluster --compliance=nsa --report all --format json
```

## Custom compliance report

The Trivy K8s CLI allows you to create a custom compliance specification and pass it to trivy for generating scan report .

The report is generated based on scanning result mapping between users define controls and trivy checks ID.
The supported checks are from two types and can be found at [Aqua vulnerability DB](https://avd.aquasec.com/):
- [misconfiguration](https://avd.aquasec.com/misconfig/)
- [vulnerabilities](https://avd.aquasec.com/nvd) 


### Compliance spec format

The compliance spec file format should look as follow :


```yaml
---
spec:
  id: "0001" # report unique identifier
  title: nsa # report title 
  description: National Security Agency - Kubernetes Hardening Guidance # description of the report
  relatedResources :
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/ # reference is related to public or internal spec
  version: "1.0" # spec version
  controls:
    - name: Non-root containers # short control naming
      description: 'Check that container is not running as root' # long control description
      id: '1.0' # control identifier 
      checks:   # list of trivy checks which associated to control
        - id: AVD-KSV-0012 # check ID (midconfiguration ot vulnerability) must start with `AVD-` or `CVE-` 
      severity: 'MEDIUM' # control severity
    - name: Immutable container file systems
      description: 'Check that container root file system is immutable'
      id: '1.1'
      checks:
        - id: AVD-KSV-0014
      severity: 'LOW'
```

## Custom report CLI Commands

To generate the custom report, an custom spec file path should be passed to the `--compliance` flag with `@` prefix as follow:


```
$ trivy k8s cluster --compliance=@/spec/my_complaince.yaml --report summary
```


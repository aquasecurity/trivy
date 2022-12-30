# Kubernetes Compliance

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

</details>
## CLI Commands
Scan a full cluster and generate a complliance NSA / CIS Kubernetes Benchmark summary report:
Supported spec IDs: `k8s-nsa` , `k8s-cis`
```
trivy k8s cluster --compliance=k8s-nsa --report summary
```

***Note*** : The `Issues` column represent the total number of failed checks for this control.

An additional report is supported to get all of the detail the output contains, use `--report all`

```
trivy k8s cluster --compliance=k8s-cis --report all
```

Report also supported in json format examples :

```
trivy k8s cluster --compliance=k8s-nsa --report summary --format json
```

```
trivy k8s cluster --compliance=k8s-cis --report all --format json
```

## Custom compliance report
The Trivy K8s CLI allows you to create a custom compliance specification and pass it to trivy for generating scan report .

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
trivy k8s cluster --compliance=@/spec/my_complaince.yaml --report summary
```

The Trivy K8s CLI allows you to scan your Kubernetes cluster resources and generate the `NSA, CISA Kubernetes Hardening Guidance` report

## NSA Compliance Report

[NSA, CISA Kubernetes Hardening Guidance v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) cybersecurity technical report is produced by trivy and validate the following control checks :

<details>
<summary>NSA Control Checks</summary>
```
| ID    | Name                                                                                                    |
|-------|---------------------------------------------------------------------------------------------------------|
| 1.0   | Check that container is not running as root                                                             |
| 1.1   | Check that container root file system is immutable                                                      |
| 1.2   | Controls whether Pods can run privileged containers                                                     |
| 1.3   | Controls whether containers can share process namespaces                                                |
| 1.4   | Controls whether share host process namespaces                                                          |
| 1.5   | Controls whether containers can use the host network                                                    |
| 1.6   | Controls whether container applications can run with <br/>root privileges or with root group membership |
| 1.7   | Control check restrictions escalation to root privileges                                                |
| 1.8   | Control checks if pod sets the SELinux context of the container                                         |
| 1.9   | Control checks the restriction of containers access to resources with AppArmor                          |
| 1.10  | Control checks the sets the seccomp profile used to sandbox containers                                  |
| 1.11  | Control check whether disable secret token been mount ,automountServiceAccountToken: false              |
| 1.12  | Control check whether Namespace kube-system is not be used by users                                     |
| 2.0   | Control check validate the pod and/or namespace Selectors usage                                         |
| 3.0   | Control check whether check cni plugin installed                                                        |
| 4.0   | Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace        |
| 4.1   | Control check the use of LimitRange policy limit resource usage for namespaces or nodes                 |
| 5.0   | Control check whether control plan disable insecure port                                                |
| 5.1   | Control check whether etcd communication is encrypted                                                   |
| 6.0   | Control check whether kube config file permissions                                                      |
| 6.1   | Control checks whether encryption resource has been set                                                 |
| 6.2   | Control checks whether encryption provider has been set                                                 |
| 7.0   | Control checks whether anonymous-auth is unset                                                          |
| 7.1   | Control check whether RBAC permission is in use                                                         |
| 8.0   | Control check whether audit policy is configure                                                         |
| 8.1   | Control check whether audit log path is configure                                                       |
| 8.2   | Control check whether audit log aging is configure                                                      |
```
</details>

## CIS Bebchmark Report

The Trivy K8s CLI allows you to scan your Kubernetes cluster resources and generate the `CIS Kubernetes Benchmark` report

[CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) report is produced by trivy and validate the following control checks :

<details>
<summary>CIS Benchmark Control Checks</summary>
```
| ID     | Name                                                                                                   |
| ------ | ------------------------------------------------------------------------------------------------------ |
| 1.2.1  | Ensure that the --anonymous-auth argument is set to false                                              | server                                                                                                            |
| 1.2.2  | Ensure that the --token-auth-file parameter is not set                                                 |
| 1.2.3  | Ensure that the --DenyServiceExternalIPs is not set                                                    |
| 1.2.4  | Ensure that the --kubelet-https argument is set to true                                                |
| 1.2.5  | Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set                |
| 1.2.6  | Ensure that the --kubelet-certificate-authority argument is set as appropriate                         |
| 1.2.7  | Ensure that the --authorization-mode argument is not set to AlwaysAllow                                |
| 1.2.8  | Ensure that the --authorization-mode argument includes Node                                            |
| 1.2.9  | Ensure that the --authorization-mode argument includes RBAC                                            |
| 1.2.10 | Ensure that the admission control plugin EventRateLimit is set                                         |
| 1.2.11 | Ensure that the admission control plugin AlwaysAdmit is not set                                        |
| 1.2.12 | Ensure that the admission control plugin AlwaysPullImages is set                                       |
| 1.2.13 | Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used   |
| 1.2.14 | Ensure that the admission control plugin ServiceAccount is set                                         |
| 1.2.15 | Ensure that the admission control plugin NamespaceLifecycle is set                                     |
| 1.2.16 | Ensure that the admission control plugin NodeRestriction is set                                        |
| 1.2.17 | Ensure that the --secure-port argument is not set to 0                                                 |
| 1.2.18 | Ensure that the --profiling argument is set to false                                                   |
| 1.2.19 | Ensure that the --audit-log-path argument is set                                                       |
| 1.2.20 | Ensure that the --audit-log-maxage argument is set to 30 or as appropriate                             |
| 1.2.21 | Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate                          |
| 1.2.22 | Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate                           |
| 1.2.24 | Ensure that the --service-account-lookup argument is set to true                                       |
| 1.2.25 | Ensure that the --service-account-key-file argument is set as appropriate                              |
| 1.2.26 | Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate                    |
| 1.2.27 | Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as                        |
| 1.2.28 | Ensure that the --client-ca-file argument is set appropriate                                           |
| 1.2.29 | Ensure that the --etcd-cafile argument is set as appropriate                                           |
| 1.2.30 | Ensure that the --encryption-provider-config argument is set as appropriate                            |
| 1.3.1  | Ensure that the --terminated-pod-gc-threshold argument is set as appropriate                           |
| 1.3.3  | Ensure that the --use-service-account-credentials argument is set to true                              |
| 1.3.4  | Ensure that the --service-account-private-key-file argument is set as appropriate                      |
| 1.3.5  | Ensure that the --root-ca-file argument is set as appropriate                                          |
| 1.3.6  | Ensure that the RotateKubeletServerCertificate argument is set                                         |
| 1.3.7  | Ensure that the --bind-address argument is set to 127.0.0.1                                            |
| 1.4.1  | Ensure that the --profiling argument is set to false                                                   |
| 1.4.2  | Ensure that the --bind-address argument is set to 127.0.0.1                                            |
| 2.1    | Ensure that the --cert-file and --key-file arguments are set as appropriate                            |
| 2.2    | Ensure that the --client-cert-auth argument is set to true                                             |
| 2.3    | Ensure that the --auto-tls argument is not set to true                                                 |
| 2.4    | Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate                  |
| 2.5    | Ensure that the --peer-client-cert-auth argument is set to true                                        |
| 2.6    | Ensure that the --peer-auto-tls argument is not set to true                                            |
| 3.1.1  | Client certificate authentication should not be used for users (Manual)                                |
| 3.2.1  | Ensure that a minimal audit policy is created (Manual)                                                 |
| 3.2.2  | Ensure that the audit policy covers key security concerns (Manual)                                     |
| 5.1.1  | Ensure that the cluster-admin role is only used where required                                         |
| 5.1.2  | Minimize access to secrets                                                                             |
| 5.1.3  | Minimize wildcard use in Roles and ClusterRoles                                                        |
| 5.1.6  | Ensure that Service Account Tokens are only mounted where necessary                                    |
| 5.1.8  | Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster                  |
| 5.2.2  | Minimize the admission of privileged containers                                                        |
| 5.2.3  | Minimize the admission of containers wishing to share the host process ID namespace                    |
| 5.2.4  | Minimize the admission of containers wishing to share the host IPC namespace                           |
| 5.2.5  | Minimize the admission of containers wishing to share the host network namespace                       |
| 5.2.6  | Minimize the admission of containers with allowPrivilegeEscalation                                     |
| 5.2.7  | Minimize the admission of root containers                                                              |
| 5.2.8  | Minimize the admission of containers with the NET_RAW capability                                       |
| 5.2.9  | Minimize the admission of containers with added capabilities                                           |
| 5.2.10 | Minimize the admission of containers with capabilities assigned                                        |
| 5.2.11 | Minimize the admission of containers with capabilities assigned                                        |
| 5.2.12 | Minimize the admission of HostPath volumes                                                             |
| 5.2.13 | Minimize the admission of containers which use HostPorts                                               |
| 5.3.1  | Ensure that the CNI in use supports Network Policies (Manual)                                          |
| 5.3.2  | Ensure that all Namespaces have Network Policies defined                                               |
| 5.4.1  | Prefer using secrets as files over secrets as environment variables (Manual)                           |
| 5.4.2  | Consider external secret storage (Manual)                                                              |
| 5.5.1  | Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)                      |
| 5.7.1  | Create administrative boundaries between resources using namespaces (Manual)                           |
| 5.7.2  | Ensure that the seccomp profile is set to docker/default in your pod definitions                       |
| 5.7.3  | Apply Security Context to Your Pods and Containers                                                     |
| 5.7.4  | The default namespace should not be used                                                               |
```
</details>

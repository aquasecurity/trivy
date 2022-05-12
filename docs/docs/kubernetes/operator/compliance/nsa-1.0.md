NSA, CISA Kubernetes Hardening Guidance v1.0 cybersecurity technical report is produced by starboard and validate the following control checks :

| NAME                                                     | DESCRIPTION                                                                                             | KINDS         |
|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------|---------------|
| Non-root containers                                      | Check that container is not running as root                                                             | Workload      |
| Immutable container file systems                         | Check that container root file system is immutable                                                      | Workload      |
| Preventing privileged containers                         | Controls whether Pods can run privileged containers                                                     | Workload      |
| Share containers process namespaces                      | Controls whether containers can share process namespaces                                                | Workload      |
| Share host process namespaces                            | Controls whether share host process namespaces                                                          | Workload      |
| Use the host network                                     | Controls whether containers can use the host network                                                    | Workload      |
| Run with root privileges or with root group membership   | Controls whether container applications can run with <br/>root privileges or with root group membership | Workload      |
| Restricts escalation to root privileges                  | Control check restrictions escalation to root privileges                                                | Workload      |
| Sets the SELinux context of the container                | Control checks if pod sets the SELinux context of the container                                         | Workload      |
| Restrict a container's access to resources with AppArmor | Control checks the restriction of containers access to resources with AppArmor                          | Workload      |
| Sets the seccomp profile used to sandbox containers      | Control checks the sets the seccomp profile used to sandbox containers                                  | Workload      |
| Protecting Pod service account tokens                    | Control check whether disable secret token been mount ,automountServiceAccountToken: false              | Node          |
| Namespace kube-system should not be used by users        | Control check whether Namespace kube-system is not be used by users                                     | NetworkPolicy |
| Pod and/or namespace Selectors usage                     | Control check validate the pod and/or namespace Selectors usage                                         | NetworkPolicy |
| Use CNI plugin that supports NetworkPolicy API           | Control check whether check cni plugin installed                                                        | Node          |
| Use ResourceQuota policies to limit resources            | Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace        | ResourceQuota |
| Use LimitRange policies to limit resources               | Control check the use of LimitRange policy limit resource usage for namespaces or nodes                 | LimitRange    |
| Control plan disable insecure port                       | Control check whether control plan disable insecure port                                                | Node          |
| Encrypt etcd communication                               | Control check whether etcd communication is encrypted                                                   | Node          |
| Ensure kube config file permission                       | Control check whether kube config file permissions                                                      | Node          |
| Check that encryption resource has been set              | Control checks whether encryption resource has been set                                                 | Node          |
| Check encryption provider                                | Control checks whether encryption provider has been set                                                 | Node          |
| Make sure anonymous-auth is unset                        | Control checks whether anonymous-auth is unset                                                          | Node          |
| Make sure -authorization-mode=RBAC                       | Control check whether RBAC permission is in use                                                         | Node          |
| Audit policy is configure                                | Control check whether audit policy is configure                                                         | Node          |
| Audit log path is configure                              | Control check whether audit log path is configure                                                       | Node          |
| Audit log aging                                          | Control check whether audit log aging is configure                                                      | Node          |


NSA, CISA Kubernetes Hardening Guidance v1.0 report will be generated every three hours by default.

The NSA compliance report is composed of two parts :

- `spec`: represents the NSA compliance control checks specification, check details, and the mapping to the security scanner

- `status`: represents the NSA compliance control checks results

Spec can be customized by amending the control checks `severity` or `cron` expression (report execution interval).
As an example, let's enter `vi` edit mode and change the `cron` expression.
```shell
kubectl edit compliance
```
Once the report has been generated, you can fetch and review its results section. As an example, let's fetch the compliance status report in JSON format

```shell
kubectl get compliance nsa  -o=jsonpath='{.status}' | jq .
```

If failures are found in the NSA report and additional investigation is required, you can fetch the nsa-details report for advance investigation.
As an example, let's fetch the report in JSON format
```shell
kubectl get compliancedetail nsa-details -o json
```

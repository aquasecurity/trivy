# ClusterComplianceReport

The ClusterComplianceReport is a cluster-scoped resource, which represents the latest compliance control checks results.
The report spec defines a mapping between pre-defined compliance control check ids to security scanners check ids.
Currently, only `kube-bench` and `config-audit` security scanners are supported.

The NSA compliance report is composed of two parts:

- `spec:` represents the compliance control checks specification, check details, and the mapping to the security scanner
  (this part is defined by the user)
- `status:` represents the compliance control checks (as defined by spec mapping) results extracted from the security
  scanners reports (this part is output by trivy-operator)

The following shows a sample ClusterComplianceReport NSA specification associated with the `cluster`:

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: ''
  creationTimestamp: '2022-03-27T07:03:29Z'
  generation: 2
  labels:
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/managed-by: kubectl
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/version: {{ git.tag[1:] }}
  name: nsa
  resourceVersion: '15745'
  uid: d11e8af1-daac-457d-96ea-45be4b043814
spec:
  controls:
    - description: Check that container is not running as root
      id: '1.0'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV012
        scanner: config-audit
      name: Non-root containers
      severity: MEDIUM
    - description: Check that container root file system is immutable
      id: '1.1'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV014
        scanner: config-audit
      name: Immutable container file systems
      severity: LOW
    - description: Controls whether Pods can run privileged containers
      id: '1.2'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV017
        scanner: config-audit
      name: Preventing privileged containers
      severity: HIGH
    - description: Controls whether containers can share process namespaces
      id: '1.3'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV008
        scanner: config-audit
      name: Share containers process namespaces
      severity: HIGH
    - description: Controls whether share host process namespaces
      id: '1.4'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV009
        scanner: config-audit
      name: Share host process namespaces.
      severity: HIGH
    - description: Controls whether containers can use the host network
      id: '1.5'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV010
        scanner: config-audit
      name: use the host network
      severity: HIGH
    - description: Controls whether container applications can run with root privileges
        or with root group membership
      id: '1.6'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV029
        scanner: config-audit
      name: Run with root privileges or with root group membership
      severity: LOW
    - description: Control check restrictions escalation to root privileges
      id: '1.7'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV001
        scanner: config-audit
      name: Restricts escalation to root privileges
      severity: MEDIUM
    - description: Control checks if pod sets the SELinux context of the container
      id: '1.8'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV002
        scanner: config-audit
      name: Sets the SELinux context of the container
      severity: MEDIUM
    - description: Control checks the restriction of containers access to resources
        with AppArmor
      id: '1.9'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV030
        scanner: config-audit
      name: Restrict a container's access to resources with AppArmor
      severity: MEDIUM
    - description: Control checks the sets the seccomp profile used to sandbox containers
      id: '1.10'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV030
        scanner: config-audit
      name: Sets the seccomp profile used to sandbox containers.
      severity: LOW
    - description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
      false'
      id: '1.11'
      kinds:
        - Workload
      mapping:
        checks:
          - id: KSV036
        scanner: config-audit
      name: Protecting Pod service account tokens
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check whether Namespace kube-system is not be used by users
      id: '1.12'
      kinds:
        - NetworkPolicy
      mapping:
        checks:
          - id: KSV037
        scanner: config-audit
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check validate the pod and/or namespace Selectors usage
      id: '2.0'
      kinds:
        - NetworkPolicy
      mapping:
        checks:
          - id: KSV038
        scanner: config-audit
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
    - description: "Control check whether check cni plugin installed\t"
      id: '3.0'
      kinds:
        - Node
      mapping:
        checks:
          - id: 5.3.1
        scanner: kube-bench
      name: Use CNI plugin that supports NetworkPolicy API
      severity: CRITICAL
    - defaultStatus: FAIL
      description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      id: '4.0'
      kinds:
        - ResourceQuota
      mapping:
        checks:
          - id: KSV040
        scanner: config-audit
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check the use of LimitRange policy limit resource usage for
        namespaces or nodes
      id: '4.1'
      kinds:
        - ResourceQuota
      mapping:
        checks:
          - id: KSV039
        scanner: config-audit
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
    - description: Control check whether control plan disable insecure port
      id: '5.0'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.19
        scanner: kube-bench
      name: Control plan disable insecure port
      severity: CRITICAL
    - description: Control check whether etcd communication is encrypted
      id: '5.1'
      kinds:
        - Node
      mapping:
        checks:
          - id: '2.1'
        scanner: kube-bench
      name: Encrypt etcd communication
      severity: CRITICAL
    - description: Control check whether kube config file permissions
      id: '6.0'
      kinds:
        - Node
      mapping:
        checks:
          - id: 4.1.3
          - id: 4.1.4
        scanner: kube-bench
      name: Ensure kube config file permission
      severity: CRITICAL
    - description: Control checks whether encryption resource has been set
      id: '6.1'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.31
          - id: 1.2.32
        scanner: kube-bench
      name: Check that encryption resource has been set
      severity: CRITICAL
    - description: Control checks whether encryption provider has been set
      id: '6.2'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.3
        scanner: kube-bench
      name: Check encryption provider
      severity: CRITICAL
    - description: Control checks whether anonymous-auth is unset
      id: '7.0'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.1
        scanner: kube-bench
      name: Make sure anonymous-auth is unset
      severity: CRITICAL
    - description: Control check whether RBAC permission is in use
      id: '7.1'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.7
          - id: 1.2.8
        scanner: kube-bench
      name: Make sure -authorization-mode=RBAC
      severity: CRITICAL
    - description: Control check whether audit policy is configure
      id: '8.0'
      kinds:
        - Node
      mapping:
        checks:
          - id: 3.2.1
        scanner: kube-bench
      name: Audit policy is configure
      severity: HIGH
    - description: Control check whether audit log path is configure
      id: '8.1'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.22
        scanner: kube-bench
      name: Audit log path is configure
      severity: MEDIUM
    - description: Control check whether audit log aging is configure
      id: '8.2'
      kinds:
        - Node
      mapping:
        checks:
          - id: 1.2.23
        scanner: kube-bench
      name: Audit log aging
      severity: MEDIUM
  cron: "* * * * *"
  description: National Security Agency - Kubernetes Hardening Guidance
  name: nsa
  version: '1.0'
status:
  controlCheck:
    - description: Controls whether Pods can run privileged containers
      failTotal: 0
      id: '1.2'
      name: Preventing privileged containers
      passTotal: 11
      severity: HIGH
    - description: Controls whether containers can share process namespaces
      failTotal: 0
      id: '1.3'
      name: Share containers process namespaces
      passTotal: 11
      severity: HIGH
    - description: Control checks whether anonymous-auth is unset
      failTotal: 0
      id: '7.0'
      name: Make sure anonymous-auth is unset
      passTotal: 0
      severity: CRITICAL
    - description: Control check restrictions escalation to root privileges
      failTotal: 6
      id: '1.7'
      name: Restricts escalation to root privileges
      passTotal: 5
      severity: MEDIUM
    - description: Control checks the restriction of containers access to resources
        with AppArmor
      failTotal: 0
      id: '1.9'
      name: Restrict a container's access to resources with AppArmor
      passTotal: 11
      severity: MEDIUM
    - description: Check that container is not running as root
      failTotal: 9
      id: '1.0'
      name: Non-root containers
      passTotal: 2
      severity: MEDIUM
    - description: Controls whether share host process namespaces
      failTotal: 0
      id: '1.4'
      name: Share host process namespaces.
      passTotal: 11
      severity: HIGH
    - description: Control checks whether encryption resource has been set
      failTotal: 0
      id: '6.1'
      name: Check that encryption resource has been set
      passTotal: 1
      severity: CRITICAL
    - description: "Control check whether check cni plugin installed\t"
      failTotal: 0
      id: '3.0'
      name: Use CNI plugin that supports NetworkPolicy API
      passTotal: 1
      severity: CRITICAL
    - description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      failTotal: 1
      id: '4.0'
      name: Use ResourceQuota policies to limit resources
      passTotal: 0
      severity: MEDIUM
    - description: Control check whether kube config file permissions
      failTotal: 0
      id: '6.0'
      name: Ensure kube config file permission
      passTotal: 1
      severity: CRITICAL
    - description: Control checks whether encryption provider has been set
      failTotal: 0
      id: '6.2'
      name: Check encryption provider
      passTotal: 1
      severity: CRITICAL
    - description: Control check whether RBAC permission is in use
      failTotal: 0
      id: '7.1'
      name: Make sure -authorization-mode=RBAC
      passTotal: 0
      severity: CRITICAL
    - description: Check that container root file system is immutable
      failTotal: 5
      id: '1.1'
      name: Immutable container file systems
      passTotal: 6
      severity: LOW
    - description: Control checks if pod sets the SELinux context of the container
      failTotal: 0
      id: '1.8'
      name: Sets the SELinux context of the container
      passTotal: 11
      severity: MEDIUM
    - description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
      false'
      failTotal: 1
      id: '1.11'
      name: Protecting Pod service account tokens
      passTotal: 10
      severity: MEDIUM
    - description: Control check the use of LimitRange policy limit resource usage for
        namespaces or nodes
      failTotal: 1
      id: '4.1'
      name: Use LimitRange policies to limit resources
      passTotal: 0
      severity: MEDIUM
    - description: Control check whether audit log aging is configure
      failTotal: 0
      id: '8.2'
      name: Audit log aging
      passTotal: 0
      severity: MEDIUM
    - description: Control check whether Namespace kube-system is not be used by users
      failTotal: 8
      id: '1.12'
      name: Namespace kube-system should not be used by users
      passTotal: 3
      severity: MEDIUM
    - description: Controls whether containers can use the host network
      failTotal: 0
      id: '1.5'
      name: use the host network
      passTotal: 11
      severity: HIGH
    - description: Controls whether container applications can run with root privileges
        or with root group membership
      failTotal: 1
      id: '1.6'
      name: Run with root privileges or with root group membership
      passTotal: 10
      severity: LOW
    - description: Control check whether audit log path is configure
      failTotal: 0
      id: '8.1'
      name: Audit log path is configure
      passTotal: 1
      severity: MEDIUM
    - description: Control checks the sets the seccomp profile used to sandbox containers
      failTotal: 0
      id: '1.10'
      name: Sets the seccomp profile used to sandbox containers.
      passTotal: 11
      severity: LOW
    - description: Control check validate the pod and/or namespace Selectors usage
      failTotal: 1
      id: '2.0'
      name: Pod and/or namespace Selectors usage
      passTotal: 0
      severity: MEDIUM
    - description: Control check whether control plan disable insecure port
      failTotal: 0
      id: '5.0'
      name: Control plan disable insecure port
      passTotal: 1
      severity: CRITICAL
    - description: Control check whether etcd communication is encrypted
      failTotal: 0
      id: '5.1'
      name: Encrypt etcd communication
      passTotal: 1
      severity: CRITICAL
    - description: Control check whether audit policy is configure
      failTotal: 0
      id: '8.0'
      name: Audit policy is configure
      passTotal: 1
      severity: HIGH
  summary:
    failCount: 33
    passCount: 113
  updateTimestamp: '2022-03-27T07:06:00Z'
```



# ClusterComplianceDetailReport

The ClusterComplianceDetailReport is a cluster-scoped resource, which represents the latest result of the Cluster Compliance Detail report.
The report data provide granular information on control checks failures that occur in `ClusterComplianceReport` for further investigation.

The compliance detail report provides granular information insight on control check failures:

- Failing resource kind
- Name of the failing resource
- Namespace of the failing resource
- Failure error message
- Remediation

The following listing shows a sample ClusterComplianceDetailReport for NSA specification associated with the `cluster`

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceDetailReport
metadata:
  creationTimestamp: '2022-03-27T07:04:21Z'
  generation: 6
  name: nsa-details
  resourceVersion: '15788'
  uid: 9d36889d-086a-4fb3-b660-a3a3ecffe3c6
report:
  controlCheck:
    - checkResults:
        - details:
            - msg: ReplicaSet 'coredns-96cc4f57d' should not be set with 'kube-system' namespace
              name: replicaset-coredns-96cc4f57d
              namespace: kube-system
              status: FAIL
            - msg: ReplicaSet 'coredns-5789895cd' should not be set with 'kube-system' namespace
              name: replicaset-coredns-5789895cd
              namespace: kube-system
              status: FAIL
            - msg: ReplicaSet 'traefik-56c4b88c4b' should not be set with 'kube-system'
                namespace
              name: replicaset-traefik-56c4b88c4b
              namespace: kube-system
              status: FAIL
            - msg: ReplicaSet 'metrics-server-ff9dbcb6c' should not be set with 'kube-system'
                namespace
              name: replicaset-metrics-server-ff9dbcb6c
              namespace: kube-system
              status: FAIL
            - msg: ReplicaSet 'local-path-provisioner-84bb864455' should not be set with
                'kube-system' namespace
              name: replicaset-local-path-provisioner-84bb864455
              namespace: kube-system
              status: FAIL
          id: KSV037
          objectType: ReplicaSet
        - details:
            - msg: DaemonSet 'svclb-traefik' should not be set with 'kube-system' namespace
              name: daemonset-svclb-traefik
              namespace: kube-system
              status: FAIL
          id: KSV037
          objectType: DaemonSet
        - details:
            - msg: Job 'helm-install-traefik-crd' should not be set with 'kube-system' namespace
              name: job-helm-install-traefik-crd
              namespace: kube-system
              status: FAIL
            - msg: Job 'helm-install-traefik' should not be set with 'kube-system' namespace
              name: job-helm-install-traefik
              namespace: kube-system
              status: FAIL
          id: KSV037
          objectType: Job
      description: Control check whether Namespace kube-system is not be used by users
      id: '1.12'
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Resource do not exist in cluster
              status: FAIL
          objectType: ResourceQuota
      description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      id: '4.0'
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Container 'traefik' of ReplicaSet 'traefik-56c4b88c4b' should set 'securityContext.allowPrivilegeEscalation'
                to false
              name: replicaset-traefik-56c4b88c4b
              namespace: kube-system
              status: FAIL
            - msg: Container 'local-path-provisioner' of ReplicaSet 'local-path-provisioner-84bb864455'
                should set 'securityContext.allowPrivilegeEscalation' to false
              name: replicaset-local-path-provisioner-84bb864455
              namespace: kube-system
              status: FAIL
          id: KSV001
          objectType: ReplicaSet
        - details:
            - msg: Container 'lb-port-443' of DaemonSet 'svclb-traefik' should set 'securityContext.allowPrivilegeEscalation'
                to false
              name: daemonset-svclb-traefik
              namespace: kube-system
              status: FAIL
          id: KSV001
          objectType: DaemonSet
        - details:
            - msg: Container 'helm' of Job 'helm-install-traefik-crd' should set 'securityContext.allowPrivilegeEscalation'
                to false
              name: job-helm-install-traefik-crd
              namespace: kube-system
              status: FAIL
            - msg: Container 'helm' of Job 'helm-install-traefik' should set 'securityContext.allowPrivilegeEscalation'
                to false
              name: job-helm-install-traefik
              namespace: kube-system
              status: FAIL
          id: KSV001
          objectType: Job
        - details:
            - msg: Container 'nginx' of Pod 'nginx-jr99v' should set 'securityContext.allowPrivilegeEscalation'
                to false
              name: pod-nginx-jr99v
              namespace: trivy-operator-itest
              status: FAIL
          id: KSV001
          objectType: Pod
      description: Control check restrictions escalation to root privileges
      id: '1.7'
      name: Restricts escalation to root privileges
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Resource do not exist in cluster
              status: FAIL
          objectType: ResourceQuota
      description: Control check the use of LimitRange policy limit resource usage for
        namespaces or nodes
      id: '4.1'
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Container 'local-path-provisioner' of ReplicaSet 'local-path-provisioner-84bb864455'
                should set 'securityContext.readOnlyRootFilesystem' to true
              name: replicaset-local-path-provisioner-84bb864455
              namespace: kube-system
              status: FAIL
          id: KSV014
          objectType: ReplicaSet
        - details:
            - msg: Container 'lb-port-443' of DaemonSet 'svclb-traefik' should set 'securityContext.readOnlyRootFilesystem'
                to true
              name: daemonset-svclb-traefik
              namespace: kube-system
              status: FAIL
          id: KSV014
          objectType: DaemonSet
        - details:
            - msg: Container 'helm' of Job 'helm-install-traefik-crd' should set 'securityContext.readOnlyRootFilesystem'
                to true
              name: job-helm-install-traefik-crd
              namespace: kube-system
              status: FAIL
            - msg: Container 'helm' of Job 'helm-install-traefik' should set 'securityContext.readOnlyRootFilesystem'
                to true
              name: job-helm-install-traefik
              namespace: kube-system
              status: FAIL
          id: KSV014
          objectType: Job
        - details:
            - msg: Container 'nginx' of Pod 'nginx-jr99v' should set 'securityContext.readOnlyRootFilesystem'
                to true
              name: pod-nginx-jr99v
              namespace: trivy-operator-itest
              status: FAIL
          id: KSV014
          objectType: Pod
      description: Check that container root file system is immutable
      id: '1.1'
      name: Immutable container file systems
      severity: LOW
    - checkResults:
        - details:
            - msg: ReplicaSet 'traefik-56c4b88c4b' should set 'spec.securityContext.runAsGroup',
                'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup'
                to integer greater than 0
              name: replicaset-traefik-56c4b88c4b
              namespace: kube-system
              status: FAIL
          id: KSV029
          objectType: ReplicaSet
      description: Controls whether container applications can run with root privileges
        or with root group membership
      id: '1.6'
      name: Run with root privileges or with root group membership
      severity: LOW
    - checkResults:
        - details:
            - msg: Container of Pod 'nginx-jr99v' should set 'spec.automountServiceAccountToken'
                to false
              name: pod-nginx-jr99v
              namespace: trivy-operator-itest
              status: FAIL
          id: KSV036
          objectType: Pod
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
      false'
      id: '1.11'
      name: Protecting Pod service account tokens
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Resource do not exist in cluster
              status: FAIL
          objectType: NetworkPolicy
      description: Control check validate the pod and/or namespace Selectors usage
      id: '2.0'
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
    - checkResults:
        - details:
            - msg: Container 'trivy-operator' of ReplicaSet 'trivy-operator-7cf866c47b'
                should set 'securityContext.runAsNonRoot' to true
              name: replicaset-trivy-operator-7cf866c47b
              namespace: trivy-operator-system
              status: FAIL
            - msg: Container 'coredns' of ReplicaSet 'coredns-96cc4f57d' should set 'securityContext.runAsNonRoot'
                to true
              name: replicaset-coredns-96cc4f57d
              namespace: kube-system
              status: FAIL
            - msg: Container 'coredns' of ReplicaSet 'coredns-5789895cd' should set 'securityContext.runAsNonRoot'
                to true
              name: replicaset-coredns-5789895cd
              namespace: kube-system
              status: FAIL
            - msg: Container 'trivy-operator' of ReplicaSet 'trivy-operator-c94dd56d'
                should set 'securityContext.runAsNonRoot' to true
              name: replicaset-trivy-operator-c94dd56d
              namespace: trivy-operator-system
              status: FAIL
            - msg: Container 'local-path-provisioner' of ReplicaSet 'local-path-provisioner-84bb864455'
                should set 'securityContext.runAsNonRoot' to true
              name: replicaset-local-path-provisioner-84bb864455
              namespace: kube-system
              status: FAIL
          id: KSV012
          objectType: ReplicaSet
        - details:
            - msg: Container 'lb-port-443' of DaemonSet 'svclb-traefik' should set 'securityContext.runAsNonRoot'
                to true
              name: daemonset-svclb-traefik
              namespace: kube-system
              status: FAIL
          id: KSV012
          objectType: DaemonSet
        - details:
            - msg: Container 'helm' of Job 'helm-install-traefik-crd' should set 'securityContext.runAsNonRoot'
                to true
              name: job-helm-install-traefik-crd
              namespace: kube-system
              status: FAIL
            - msg: Container 'helm' of Job 'helm-install-traefik' should set 'securityContext.runAsNonRoot'
                to true
              name: job-helm-install-traefik
              namespace: kube-system
              status: FAIL
          id: KSV012
          objectType: Job
        - details:
            - msg: Container 'nginx' of Pod 'nginx-jr99v' should set 'securityContext.runAsNonRoot'
                to true
              name: pod-nginx-jr99v
              namespace: trivy-operator-itest
              status: FAIL
          id: KSV012
          objectType: Pod
      description: Check that container is not running as root
      id: '1.0'
      name: Non-root containers
      severity: MEDIUM
  summary:
    failCount: 33
    passCount: 113
  type:
    description: national security agency - kubernetes hardening guidance
    name: nsa-details
    version: '1.0'
  updateTimestamp: '2022-03-27T07:09:00Z'
```


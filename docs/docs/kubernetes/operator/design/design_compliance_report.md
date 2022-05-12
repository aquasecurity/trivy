# Support Compliance Reports

## Overview

It is required to leverage trivy-operator security tools capabilities by adding the support for building compliance reports
example : NSA - Kubernetes Hardening Guidance

## Solution

### TL;DR;

- A cluster compliance resource ,nsa-1.0.yaml (example below), with spec definition only will be deployed to kubernetes cluster upon startup
- the spec definition wil include the control check , cron expression for periodical generation, and it's mapping to scanners (kube-bench and audit-config)
- a new cluster compliance reconcile loop wil be introduced to track this cluster compliance resource 
- when the cluster spec is reconcile  it check if cron expression match current time , if so it generates a compliance report and update the status section with report data
- if cron expression do not match the event will be requeue until next generation time 
- Two new CRDs will be introduced :
   - `ClusterComplianceReport` to provide summary of the compliance per control
   - `ClusterComplianceDetailReport` to provide more detail compliance report for further investigation
- It is assumed that all scanners (kube-bench / config-audit) are running by default all the time and producing raw data

### The Spec file :
- The spec will include the mapping (based on Ids) between the compliance report and tools(kube-bench and config-audit) which generate the raw data
- The spec file will be loaded from the file system

#### Example for spec  :

```yaml
---
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  name: nsa
spec:
  name: nsa
  description: National Security Agency - Kubernetes Hardening Guidance
  version: "1.0"
  cron: "0 */3 * * *"
  controls:
    - name: Non-root containers
      description: 'Check that container is not running as root'
      id: '1.0'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV012
      severity: 'MEDIUM'
    - name: Immutable container file systems
      description: 'Check that container root file system is immutable'
      id: '1.1'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV014
      severity: 'LOW'
    - name: Preventing privileged containers
      description: 'Controls whether Pods can run privileged containers'
      id: '1.2'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV017
      severity: 'HIGH'
    - name: Share containers process namespaces
      description: 'Controls whether containers can share process namespaces'
      id: '1.3'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV008
      severity: 'HIGH'
    - name: Share host process namespaces.
      description: 'Controls whether share host process namespaces'
      id: '1.4'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV009
      severity: 'HIGH'
    - name: use the host network
      description: 'Controls whether containers can use the host network'
      id: '1.5'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV010
      severity: 'HIGH'
    - name:  Run with root privileges or with root group membership
      description: 'Controls whether container applications can run with root privileges or with root group membership'
      id: '1.6'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV029
      severity: 'LOW'
    - name: Restricts escalation to root privileges
      description: 'Control check restrictions escalation to root privileges'
      id: '1.7'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV001
      severity: 'MEDIUM'
    - name: Sets the SELinux context of the container
      description: 'Control checks if pod sets the SELinux context of the container'
      id: '1.8'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV002
      severity: 'MEDIUM'
    - name: Restrict a container's access to resources with AppArmor
      description: 'Control checks the restriction of containers access to resources with AppArmor'
      id: '1.9'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV030
      severity: 'MEDIUM'
    - name: Sets the seccomp profile used to sandbox containers.
      description: 'Control checks the sets the seccomp profile used to sandbox containers'
      id: '1.10'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV030
      severity: 'LOW'
    - name: Protecting Pod service account tokens
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken: false'
      id: '1.11'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV036
      severity: 'MEDIUM'
    - name: Namespace kube-system should not be used by users
      description: 'Control check whether Namespace kube-system is not be used by users'
      id: '1.12'
      kinds:
        - NetworkPolicy
      mapping:
        scanner: config-audit
        checks:
          - id: KSV037
      severity: 'MEDIUM'
    - name: Pod and/or namespace Selectors usage
      description: 'Control check validate the pod and/or namespace Selectors usage'
      id: '2.0'
      kinds:
        - Workload
      mapping:
        scanner: config-audit
        checks:
          - id: KSV038
      severity: 'MEDIUM'
    - name: Use CNI plugin that supports NetworkPolicy API
      description: 'Control check whether check cni plugin installed	'
      id: '3.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 5.3.1
      severity: 'CRITICAL'
    - name: Use ResourceQuota policies to limit resources
      description: 'Control check the use of ResourceQuota policies to limit resources'
      id: '4.0'
      kinds:
        - ResourceQuota
      mapping:
        scanner: config-audit
        checks:
          - id: "<check need to be added>"
      severity: 'CRITICAL'
    - name: Control plan disable insecure port
      description: 'Control check whether control plan disable insecure port'
      id: '5.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.19
      severity: 'CRITICAL'
    - name: Encrypt etcd communication
      description: 'Control check whether etcd communication is encrypted'
      id: '5.1'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: '2.1'
      severity: 'CRITICAL'
    - name: Ensure kube config file permission
      description: 'Control check whether kube config file permissions'
      id: '6.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 4.1.3
          - id: 4.1.4
      severity: 'CRITICAL'
    - name: Check that encryption resource has been set
      description: 'Control checks whether encryption resource has been set'
      id: '6.1'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.31
          - id: 1.2.32
      severity: 'CRITICAL'
    - name: Check encryption provider
      description: 'Control checks whether encryption provider has been set'
      id: '6.2'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.3
      severity: 'CRITICAL'
    - name: Make sure anonymous-auth is unset
      description: 'Control checks whether anonymous-auth is unset'
      id: '7.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.1
      severity: 'CRITICAL'
    - name: Make sure -authorization-mode=RBAC
      description: 'Control check whether RBAC permission is in use'
      id: '7.1'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.7
          - id: 1.2.8
      severity: 'CRITICAL'
    - name: Audit policy is configure
      description: 'Control check whether audit policy is configure'
      id: '8.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 3.2.1
      severity: 'HIGH'
    - name: Audit log path is configure
      description: 'Control check whether audit log path is configure'
      id: '8.1'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.22
      severity: 'MEDIUM'
    - name: Audit log aging
      description: 'Control check whether audit log aging is configure'
      id: '8.2'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: 1.2.23
      severity: 'MEDIUM'
    - name: Service mesh is configure
      description: 'Control check whether service mesh is used in cluster'
      id: '9.0'
      kinds:
        - Node
      mapping:
        scanner: kube-bench
        checks:
          - id: "<check need to be added>"
      severity: 'MEDIUM'
  ....
 ``` 
### The logic :
Upon trivy-operator start cluster compliance reconcile loop will track the deployed spec file ,nsa-1.0 spec and evaluation the cron expression in spec file, 
if  the cron interval matches , trivy-operator will generate the compliance and compliance detail reports :
 -  `ClusterComplianceReport` status section will be updated with report data 
 - `ClusterComplianceDetailReport` will be generated by and saved to etcd

### The mapping
Once it is determined that a report need to be generated:
- all reports (cis-benchmark and audit config) raw data will be fetched by `tool` and `resource` types
- trivy-operator will iterate all fetched raw data and find a match by `ID`
- once the data has been mapped and aggregated 2 type of reports will be generated to present summary
  data and detailed data (in case further investigation need to be made)

### Note: once the report has been generated again to reconcile loop start again the process describe in logic

### The Reports:

#### Example: Compliance spec and status section (report data)
```json
{
  "kind": "ClusterComplianceReport",
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "metadata": {
    "name": "nsa",
    "resourceVersion": "1000",
    "creationTimestamp": null
  },
  "spec": {
    "kind": "compliance",
    "name": "nsa",
    "description": "National Security Agency - Kubernetes Hardening Guidance",
    "cron": "* * * * *",
    "version": "1.0",
    "controls": [
      {
        "id": "1.0",
        "name": "Non-root containers",
        "description": "",
        "resources": [
          "Workload"
        ],
        "mapping": {
          "tool": "config-audit",
          "checks": [
            {
              "id": "KSV012"
            }
          ]
        }
      },
      {
        "id": "8.2",
        "name": "Audit log aging",
        "description": "",
        "resources": [
          "Node"
        ],
        "mapping": {
          "tool": "kube-bench",
          "checks": [
            {
              "id": "1.2.23"
            }
          ]
        }
      }
    ]
  },
  "status": {
    "updateTimestamp": "2022-02-26T14:11:39Z",
    "summary": {
      "passCount": 3,
      "failCount": 3
    },
    "control_check": [
      {
        "id": "1.1",
        "name": "Immutable container file systems",
        "passTotal": 0,
        "failTotal": 3,
        "severity": ""
      }
    ]
  }
}
```

#### Compliance details report
```json
{
  "kind": "ClusterComplianceDetailReport",
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "metadata": {
    "name": "nsa-details",
    "resourceVersion": "1"
  },
  "report": {
    "updateTimestamp": "2022-02-26T14:05:29Z",
    "type": {
      "kind": "compliance",
      "name": "nsa-details",
      "description": "national security agency - kubernetes hardening guidance",
      "version": "1.0"
    },
    "summary": {
      "passCount": 3,
      "failCount": 3
    },
    "controlCheck": [
      {
        "id": "1.1",
        "name": "Immutable container file systems",
        "checkResults": [
          {
            "objectType": "Pod",
            "id": "KSV014",
            "remediation": "",
            "details": [
              {
                "name": "pod-rss-site",
                "namespace": "default",
                "msg": "Container 'front-end' of Pod 'rss-site' should set 'securityContext.readOnlyRootFilesystem' to true",
                "status": "fail"
              },
              {
                "name": "pod-rss-site",
                "namespace": "default",
                "msg": "Container 'rss-reader' of Pod 'rss-site' should set 'securityContext.readOnlyRootFilesystem' to true",
                "status": "fail"
              }
            ]
          },
          {
            "objectType": "ReplicaSet",
            "id": "KSV014",
            "remediation": "",
            "details": [
              {
                "name": "replicaset-memcached-sample-6c765df685",
                "namespace": "default",
                "msg": "Container 'memcached' of ReplicaSet 'memcached-sample-6c765df685' should set 'securityContext.readOnlyRootFilesystem' to true",
                "status": "fail"
              }
            ]
          }
        ]
      },
      {
        "id": "3.0",
        "name": "Use CNI plugin that supports NetworkPolicy API",
        "checkResults": [
          {
            "objectType": "Node",
            "id": "5.3.1",
            "remediation": "If the CNI plugin in use does not support network policies, consideration should be given to\nmaking use of a different plugin, or finding an alternate mechanism for restricting traffic\nin the Kubernetes cluster.\n",
            "details": [
              {
                "name": "local-control-plane",
                "namespace": "",
                "msg": "",
                "status": "warn"
              }
            ]
          }
        ]
      },
      {
        "id": "6.0",
        "name": "Ensure kube config file permission",
        "checkResults": [
          {
            "objectType": "Node",
            "id": "4.1.3",
            "remediation": "Run the below command (based on the file location on your system) on the each worker node.\nFor example,\nchmod 644 /etc/kubernetes/proxy.conf\n",
            "details": [
              {
                "name": "local-control-plane",
                "namespace": "",
                "msg": "",
                "status": "pass"
              }
            ]
          }
        ]
      },
      {
        "id": "6.0",
        "name": "Ensure kube config file permission",
        "checkResults": [
          {
            "objectType": "Node",
            "id": "4.1.4",
            "remediation": "Run the below command (based on the file location on your system) on the each worker node.\nFor example, chown root:root /etc/kubernetes/proxy.conf\n",
            "details": [
              {
                "name": "local-control-plane",
                "namespace": "",
                "msg": "",
                "status": "pass"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

### The CRDs
#### ClusterComplianceReport CRD :
- a new CRD `clustercompliancereports.crd.yaml` will be added to include compliance check report

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clustercompliancereports.aquasecurity.github.io
  labels:
    app.kubernetes.io/managed-by: trivy-operator
    app.kubernetes.io/version: "0.14.1"
spec:
  group: aquasecurity.github.io
  scope: Cluster
  versions:
    - name: v1alpha1
      served: true
      storage: true
      additionalPrinterColumns:
        - jsonPath: .metadata.creationTimestamp
          type: date
          name: Age
          description: The age of the report
        - jsonPath: .status.summary.failCount
          type: integer
          name: Fail
          priority: 1
          description: The number of checks that failed with Danger status
        - jsonPath: .status.summary.passCount
          type: integer
          name: Pass
          priority: 1
          description: The number of checks that passed
      schema:
        openAPIV3Schema:
          type: object
          required:
            - apiVersion
            - kind
            - metadata
            - spec
          properties:
            apiVersion:
              type: string
            kind:
              type: string
            metadata:
              type: object
            spec:
              type: object
              required:
                - name
                - description
                - version
                - cron
                - controls
              properties:
                name:
                  type: string
                description:
                  type: string
                version:
                  type: string
                cron:
                  type: string
                  pattern: '^(((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1-5]{1}){1}([0-9]{1}){1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1]{1}){1}([0-9]{1}){1}){1}|([2]{1}){1}([0-3]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))|(jan|feb|mar|apr|may|jun|jul|aug|sep|okt|nov|dec)) ((([\*]{1}){1})|((\*\/){0,1}(([0-7]{1}){1}))|(sun|mon|tue|wed|thu|fri|sat)))$'
                  description: 'cron define the intervals for report generation'
                controls:
                  type: array
                  items:
                    type: object
                    required:
                      - name
                      - id
                      - kinds
                      - mapping
                      - severity
                    properties:
                      name:
                        type: string
                      description:
                        type: string
                      id:
                        type: string
                        description: 'id define the control check id'
                      kinds:
                        type: array
                        items:
                          type: string
                          description: 'kinds define the list of kinds control check apply on , example: Node,Workload '
                      mapping:
                        type: object
                        required:
                          - scanner
                          - checks
                        properties:
                          scanner:
                            type: string
                            pattern: '^config-audit$|^kube-bench$'
                            description: 'scanner define the name of the scanner which produce data, currently only config-audit and kube-bench are supported'
                          checks:
                            type: array
                            items:
                              type: object
                              required:
                                - id
                              properties:
                                id:
                                  type: string
                                  description: 'id define the check id as produced by scanner'
                      severity:
                        type: string
                        description: 'define the severity of the control'
                        enum:
                          - CRITICAL
                          - HIGH
                          - MEDIUM
                          - LOW
                          - UNKNOWN
            status:
              x-kubernetes-preserve-unknown-fields: true
              type: object
      subresources:
        # status enables the status subresource.
        status: { }
  names:
    singular: clustercompliancereport
    plural: clustercompliancereports
    kind: ClusterComplianceReport
    listKind: ClusterComplianceReportList
    categories: [ ]
    shortNames:
      - compliance
```

#### ClusterComplianceDetailReport CRD :
- a new CRD `clustercompliancedetailreports.crd.yaml` will be added to include compliance detail check report

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clustercompliancedetailreports.aquasecurity.github.io
  labels:
    app.kubernetes.io/managed-by: trivy-operator
    app.kubernetes.io/version: "0.14.1"
spec:
  group: aquasecurity.github.io
  versions:
    - name: v1alpha1
      served: true
      storage: true
      additionalPrinterColumns:
        - jsonPath: .metadata.creationTimestamp
          type: date
          name: Age
          description: The age of the report
        - jsonPath: .report.summary.failCount
          type: integer
          name: Fail
          priority: 1
          description: The number of checks that failed with Danger status
        - jsonPath: .report.summary.passCount
          type: integer
          name: Pass
          priority: 1
          description: The number of checks that passed
      schema:
        openAPIV3Schema:
          x-kubernetes-preserve-unknown-fields: true
          type: object
  scope: Cluster
  names:
    singular: clustercompliancedetailreport
    plural: clustercompliancedetailreports
    kind: ClusterComplianceDetailReport
    listKind: ClusterComplianceDetailReportList
    categories: []
    shortNames:
      - compliancedetail 
```

### Permission changes:

it is required to update `02-trivy-operator.rbac.yaml` rules to include new permissions
to support the following tracked resources kind by NSA plugin with (get,list and watch):

 ```yaml
- apiGroups: ["networking.k8s.io"]
  resources:
    - networkpolicies
  verbs:
    - get
    - list
    - watch
```

```yaml
- apiGroups:
      - ""
    resources:
      - resourcequota
    verbs:
      - get
      - list
      - watch
```
### NSA Tool Analysis

| Test                                                                                          | Description                                                                                             | Kind                                                                        | Tool        | Test                                                                                                                          |
|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------|
| Non-root containers                                                                           | Check that container is not running as root                                                             | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield : <br/>kubernetes/policies/pss/restricted/3_runs_as_root.rego                                                       |
| Immutable container file systems                                                              | check that container root <br/>file system is immutable                                                 | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/general/file_system_not_read_only.rego                                                         |
| Scan container images vulnerabilities                                                         | scan container for vulnerabilities<br/> and misconfiguration                                            | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Trivy       | Trivy                                                                                                                         |
| Privileged container                                                                          | Controls whether Pods can run privileged containers.                                                    | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/2_privileged.rego                                                                 |
| hostIPC                                                                                       | Controls whether containers can share<br/> host process namespaces                                      | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/1_host_ipc.rego                                                                   |
| hostPID                                                                                       | Controls whether containers can share host process namespaces.                                          | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/1_host_pid.rego                                                                   |
| hostNetwork                                                                                   | Controls whether containers can use the host network.                                                   | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/1_host_network.rego                                                               |
| allowedHostPaths                                                                              | Limits containers to specific paths of the host file system.                                            | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | Need to be added to appshield :<br/> https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems |
| runAsUser , runAsGroup <br/>and supplementalGroups                                            | Controls whether container applications can run <br/>with root privileges or with root group membership | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/restricted/4_runs_with_a_root_gid.rego                                                     |
| allowPrivilegeEscalation                                                                      | Restricts escalation to root privileges.                                                                | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/restricted/2_can_elevate_its_own_privileges.rego                                           |
| seLinux                                                                                       | Sets the SELinux context of the container.                                                              | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/7_selinux_custom_options_set.rego                                                 |
| AppArmor annotations                                                                          | Sets the seccomp profile used to sandbox containers.                                                    | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/baseline/6_apparmor_policy_disabled.rego                                                   |
| seccomp annotations                                                                           | Sets the seccomp profile used to sandbox containers.                                                    | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/pss/restricted/5_runtime_default_seccomp_profile_not_set.rego                                  |
| Protecting Pod service account tokens                                                         | disable secret token been mount ,automountServiceAccountToken: false                                    | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/advance/protecting_pod_service_account_tokens.rego                                             |
| kube-system or kube-public                                                                    | namespace kube-system should should not be used by users                                                | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/advance/protect_core_components_namespace.rego                                                 |
| Use CNI plugin that supports NetworkPolicy API                                                | check cni plugin installed                                                                              | Node                                                                        | Kube-bench  | 5.3.1 Ensure that the CNI in use supports Network Policies (need to be fixed)                                                 |
| Create policies that select <br/>Pods using podSelector and/or the namespaceSelector          | Create policies that select Pods using podSelector<br/> and/or the namespaceSelector                    | Pod,ReplicationController,ReplicaSet,<br/>StatefulSet,DaemonSet,Job,CronJob | Conftest    | appshield: kubernetes/policies/advance/selector_usage_in_network_policies.rego                                                |
| use a default policy to deny all ingress and egress traffic                                   | check that network policy deny all exist                                                                | NetworkPolicy                                                               | Kube-bench  | Add logic to kube-bench <br/>https://kubernetes.io/docs/concepts/services-networking/network-policies/                        |
| Use LimitRange and ResourceQuota<br/> policies to limit resources on a namespace or Pod level | check the resource quota resource has been define                                                       | ResourceQuota                                                               | Kube-bench  | Add Logic to kube-bench <br/>https://kubernetes.io/docs/concepts/policy/limit-range/                                          |
| TLS encryption                                                                                | control plan disable insecure port                                                                      | Node                                                                        | Kube-bench  | 1.2.19 Ensure that the --insecure-port argument is set to 0                                                                   |
| Etcd encryption                                                                               | encrypt etcd communication                                                                              | Node                                                                        | Kube-bench  | 2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate                                               |
| Kubeconfig files                                                                              | ensure file permission                                                                                  | Node                                                                        | Kube-bench  | 4.1.3, 4.1.4                                                                                                                  |
| Worker node segmentation                                                                      | node segmentation                                                                                       | Node                                                                        | Kube-bench  | Note sure can be tested                                                                                                       |
| Encryption                                                                                    | check that encryption resource has been set                                                             | EncryptionConfiguration                                                     | Kube-bench  | Add Logic to kube-bench https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/                                     |
| Encryption / secrets                                                                          | check encryption provider                                                                               | Node                                                                        | Kube-bench  | 1.2.3 Ensure that the --encryption-provider-config argument is set as                                                         |
| authentication                                                                                | make sure anonymous-auth is unset                                                                       | Node                                                                        | Kube-bench  | 1.2.1 Ensure that the --anonymous-auth argument is set to false                                                               |~~
| Role-based access control                                                                     | make sure -authorization-mode=RBAC                                                                      | Node                                                                        | Kube-bench  | 1.2.7/1.2.8 Ensure that the --authorization-mode argument is not set to AlwaysAllow                                           |
| Audit policy file                                                                             | check that policy is configure                                                                          | Node                                                                        | Kube-bench  | 3.2.1 Ensure that a minimal audit policy is created                                                                           |
| Audit log path                                                                                | check that log path is configure                                                                        | Node                                                                        | Kube-bench  | 1.2.22 Ensure that the --audit-log-path argument is set                                                                       |
| Audit log max age                                                                             | check audit log aging                                                                                   | Node                                                                        | Kube-bench  | 1.2.23 Ensure that the --audit-log-maxage argument is set to 30 or as appropriate                                             |~~
| service mesh usage                                                                            | check service mesh is used in cluster                                                                   | Node                                                                        | Kube-bench  | Add Logic to kube-bench check service mesh existenace                                                                         |


## Open Items
- compliance support for CLI

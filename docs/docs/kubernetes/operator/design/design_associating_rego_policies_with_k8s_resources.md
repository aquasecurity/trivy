# Associating Rego Policies with Kubernetes Resources

## Overview

trivy-operator (with Conftest plugin) evaluates all policies on a given Kubernetes (K8s) resource, which is not efficient for
two reasons:

1. trivy-operator creates a scan Job to audit a K8s resource even if there are no Rego policies defined for its kind.
2. trivy-operator rescans all K8s resources even if the change in Rego policies is only related to a particular kind.

## Solution

### TL;DR;

Extend the configuration of the Conftest plugin to include information about K8s resource kinds (or GVK). This would
allow us to:

1. Group and filter Rego policies for a given resource kind to pass only relevant policies to a scan Job. In particular,
   skip creation of a scan Job for a given resource if there are no policies for its kind.
2. Calculate plugin config hash for a given resource kind to enable efficient rescanning by deleting only a subset of
   ConfigAuditReports and ClusterConfigAuditReports.

### Deep Dive

In the following example we'll consider a set of Rego policies that are applicable to different kinds of resources.

* K8s workload (Pod, ReplicationController, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob)
    * `file_system_not_read_only.rego`
    * `uses_image_tag_latest.rego`
* ConfigMap
    * `configmap_with_sensitive_data.rego`
    * `configmap_with_secret_data.rego`
* Service
    * `service_with_external_ip.rego`
* Any
    * `object_without_recommended_labels.rego`

There are also two modules with helper functions used throughout Rego policies.

* `kubernetes.rego`
* `utils.rego`

This is how we represent the example Rego policies as a Conftest configuration object. As you can see there's no mapping
between Rego policy and applicable kinds. It's also hard to distinguish helpers from regular policies.

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  namespace: trivy-operator
  name: trivy-operator-conftest-config
data:
  conftest.imageRef: openpolicyagent/conftest:v0.30.0
  conftest.resources.requests.cpu: 50
  conftest.resources.requests.memory: 50M
  conftest.resources.limits.cpu: 300m
  conftest.resources.limits.memory: 300M

  conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  conftest.policy.uses_image_tag_latest.rego: "{REGO CODE}"
  conftest.policy.configmap_with_sensitive_data.rego: "{REGO CODE}"
  conftest.policy.configmap_with_secret_data.rego: "{REGO CODE}"
  conftest.policy.service_with_external_ip.rego: "{REGO CODE}"
  conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"

  conftest.policy.kubernetes.rego: "{REGO CODE}"
  conftest.policy.utils.rego: "{REGO CODE}"
```

In the proposed solution each Rego policy code will be accompanied by the property that specifies one to many applicable
kinds (GVKs). For example, adding `conftest.policy.file_system_not_read_only.rego` policy will require specifying
resource kinds as a comma-separated values stored as `conftest.policy.file_system_not_read_only.kinds`.

If a Rego policy is applicable to any K8s workload, the kind can be express as `Workload`.  
If a Rego policy is applicable to any K8s resource, the kind can be expressed as wildcard (`*`) character.

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  namespace: trivy-operator
  name: trivy-operator-conftest-config
  annotations:
    # Introduce a way to version configuration schema.
    trivy-operator.plugin.config.version: "v2"
data:
  conftest.imageRef: openpolicyagent/conftest:v0.30.0
  conftest.resources.requests.cpu: 50
  conftest.resources.requests.memory: 50M
  conftest.resources.limits.cpu: 300m
  conftest.resources.limits.memory: 300M

  conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  conftest.policy.uses_image_tag_latest.rego: "{REGO CODE}"
  conftest.policy.configmap_with_sensitive_data.rego: "{REGO CODE}"
  conftest.policy.configmap_with_secret_data.rego: "{REGO CODE}"
  conftest.policy.service_with_external_ip.rego: "{REGO CODE}"
  conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"

  conftest.policy.file_system_not_read_only.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  # For each K8s workload type a config hash will be the same.
  # Therefore, we could support a "virtual" kind named `Workload`.
  conftest.policy.uses_image_tag_latest.kinds: Workload
  conftest.policy.configmap_with_sensitive_data.kinds: ConfigMap
  conftest.policy.configmap_with_secret_data.kinds: ConfigMap
  conftest.policy.service_with_external_id.kinds: Service
  # Use "*" to apply a policy to any kind.
  conftest.policy.object_without_recommended_labels.kinds: "*"

  # Distinguish libraries with the conftest.library.* prefix.
  conftest.library.kubernetes.rego: "{REGO CODE}"
  conftest.library.utils.rego: "{REGO CODE}"
```

To reconcile K8s resources and create ConfigAuditReports we calculate two hashes based on resource spec and Conftest
plugin config. These two hashes are set as `resource-spec-hash` and `plugin-config-hash` labels on each
ConfigAuditReport instance. The `resource-spec-hash` is used to rescan a resource when its spec has changed (e.g. update
container image tag), whereas the `plugin-config-hash` is used to rescan the resource when Conftest config has changed
(e.g. add new Rego policy or edit existing one).

> :bulb: Trivy operator has a dedicated controller to watch changes to the `trivy-operator-conftest-config` ConfigMap.
> Whenever there's a change the controller calculates a new hash and deletes all ConfigAuditReports, which do not have
> the same value of the `plugin-config-hash` label.

Currently, we calculate `plugin-config-hash` values based off of all Rego policies by filtering configuration keys with
the `conftest.policy.` prefix. In the proposed solution we'll group Rego policies by resource kind and then
calculate `N` hashes, where `N` is the number of different kinds. For example, a ConfigAuditReport associated with a
Service will have the `plugin-config-hash` label calculated based off of policies that are only applicable to Services,
i.e. `service_with_external_id.rego`, `object_without_recommended_labels.rego`, `kubernetes.rego`, and
`utils.rego`.

The following snippet shows which configuration keys and corresponding values (Rego code) will be considered to
calculate the plugin config hash for a specified kind.

```yaml
ConfigMap:
  - conftest.policy.configmap_with_sensitive_data.rego: "{REGO CODE}"
  - conftest.policy.configmap_with_secret_data.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  # Helper Rego functions may change the logic of any Rego policy
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
Service:
  - conftest.policy.service_with_external_id.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
Workload:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
Pod:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
ReplicationController:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
ReplicaSet:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
StatefulSet:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
DaemonSet:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
Job:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
CronJob:
  - conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
  - conftest.policy.uses_imag_tag_latest.rego: "{REGO CODE}"
  - conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"
  - conftest.library.kubernetes.rego: "{REGO CODE}"
  - conftest.library.utils.rego: "{REGO CODE}"
```

## Scenarios

> :bulb: Scenarios in this section are written in [Gherkin](https://cucumber.io/docs/gherkin/reference/).

```gherkin
Feature: Reconcile Kubernetes resources for configuration auditing

  These scenarios are applicable to ConfigAuditReports and ClusterConfigAuditReports.
  The only difference is the scope of the resource, i.e. namespace vs cluster.

  Scenario: Scan a K8s resource when there are applicable Rego policies

    Given a set of Rego policies applicable to ConfigMaps
    When a ConfigMap is discovered by the operator
    And there is no ConfigAuditReport associated with the ConfigMap
    Then the operator scans the ConfigMap
    And eventually, there is the ConfigAuditReport associated with the ConfigMap

  Scenario: Skip scanning a K8s resource when there are no applicable Rego policies

    Given a set of Rego policies not applicable to ConfigMaps
    When a ConfigMap is discovered by the operator
    And there is no ConfigAuditReport associated with the ConfigMap
    Then operator requeues (with delay) the reconciliation key for the ConfigMap

  Scenario: Delete (stale) ConfigAuditReport when applicable Rego policies are removed

    Given a set of Rego policies applicable to ConfigMaps
    And the ConfigAuditReport associated with a ConfigMap
    When Rego policies for ConfigMaps are removed
    Then operator deletes the ConfigAuditReport
    And the operator requeues (without delay) the reconciliation key for the ConfigMap

  Scenario: Rescan a K8s resource when applicable Rego policies are updated

    Given a set of Rego policies applicable to K8s workloads and ConfigMaps
    When Rego code applicable to ConfigMaps has changed
    Then operator deletes ConfigAuditReports associated with ConfigMaps
    But ConfigAuditReports associated with K8s resources other than ConfigMaps are left intact

  Scenario: Rescan all K8s resources when Rego helper functions have changed

    Given a set of Rego policies applicable to K8s workloads, ConfigMaps, and Services
    When Rego code of helper functions have changed
    Then the operator deletes all ConfigAuditReports
```

# Writing Custom Configuration Audit Policies

trivy-operator ships with a set of [Built-in Configuration Audit Policies] defined as OPA [Rego] policies. You can also
define custom policies and associate them with applicable Kubernetes resources to extend basic configuration audit
functionality.

This tutorial will walk through the process of creating and testing a new configuration audit policy that fails whenever
a Kubernetes resource doesn't specify `app.kubernetes.io/name` or `app.kubernetes.io/version` labels.

## Writing a Policy

To define such a policy, you must first define its metadata. This includes setting a unique identifier, title, severity
(`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), descriptive text, and remediation steps. In Rego it's defined as the
`__rego_metadata__` rule, which defines the following composite value:

```opa
package starboard.policy.k8s.custom

__rego_metadata__ := {
	"id": "recommended_labels",
	"title": "Recommended labels",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "A common set of labels allows tools to work interoperably, describing objects in a common manner that all tools can understand.",
	"recommended_actions": "Take full advantage of using recommended labels and apply them on every resource object.",
	"url": "https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/",
}
```

Note that the `recommended_labels` policy in scoped to the `starboard.policy.k8s.custom` package to avoid naming
collision with built-in policies that are pre-installed with trivy-operator.

Once we've got our metadata defined, we need to create the logic of the policy, which is done in the `deny` or `warn`
rule.

```opa
recommended_labels := [
	"app.kubernetes.io/name",
	"app.kubernetes.io/version",
]

deny[res] {
	provided := {label | input.metadata.labels[label]}
	required := {label | label := recommended_labels[_]}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("You must provide labels: %v", [missing])
	res := {"msg": msg}
}
```

These matches are essentially Rego assertions, so anyone familiar with writing rules for OPA or other tools that use
Rego should find the process familiar. In this case, it’s pretty straightforward. We subtract the set of labels
specified by the `input` resource object from the set of recommended labels. The resulting set is stored in the variable
called `missing`. Finally, we check if the `missing` set is empty. If not, the `deny` rule fails with the appropriate
message.

The `input` document is set by trivy-operator to a Kubernetes resource when the policy is evaluated. For pods, it would look
something like the following listing:

```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "nginx",
    "labels": {
      "run": "nginx"
    }
  },
  "spec": {
    "containers": [
      {
        "name": "nginx",
        "image": "nginx:1.16",
      }
    ]
  }
}
```

The labels set on the pod resource above can be retrieved with the following Rego expression:

```opa
provided := {label | input.metadata.labels[label]}
```

You can find the complete Rego code listing in [recommended_labels.rego](./recommended_labels.rego).

## Testing a Policy

Now that you've created the policy, you need to test it to make sure it works as intended. To do that, add policy code to
the `trivy-operator-policies-config` ConfigMap and associate it with any (`*`) Kubernetes resource kind:

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-operator-policies-config
  namespace: trivy-system
  labels:
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/version: "{{ git.tag[1:] }}"
    app.kubernetes.io/managed-by: kubectl
data:
  policy.recommended_labels.kinds: "*"
  policy.recommended_labels.rego: |
    package starboard.policy.k8s.custom

    __rego_metadata__ := {
    	"id": "recommended_labels",
    	"title": "Recommended labels",
    	"severity": "LOW",
    	"type": "Kubernetes Security Check",
    	"description": "A common set of labels allows tools to work interoperably, describing objects in a common manner that all tools can understand",
    	"recommended_actions": "Take full advantage of using recommended labels and apply them on every resource object.",
    	"url": "https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/",
    }

    recommended_labels := [
    	"app.kubernetes.io/name",
    	"app.kubernetes.io/version",
    ]

    deny[res] {
    	provided := {label | input.metadata.labels[label]}
    	required := {label | label := recommended_labels[_]}
    	missing := required - provided
    	count(missing) > 0
    	msg := sprintf("You must provide labels: %v", [missing])
    	res := {"msg": msg}
    }
```

In this example, to add a new policy, you must define two data entries in the `trivy-operator-policies-config`
ConfigMap:

1. The `policy.<your_policy_name>.kinds` entry is used to designate applicable Kubernetes resources as a comma separated
   list of Kubernetes kinds (e.g., `Pod,ConfigMap,NetworkPolicy`). There is also a special value (`Workload`) that you
   can use to select all Kubernetes workloads, and (`*`) to select all Kubernetes resources recognized by trivy-operator.
2. The `policy.<your_policy_name>.rego` entry holds the policy Rego code.

trivy-operator automatically detects policies added to the `trivy-operator-policies-config` ConfigMap and immediately rescans
applicable Kubernetes resources.

Let's create the `test` ConfigMap without recommended labels:

```console
$ kubectl create cm test --from-literal=foo=bar
configmap/test created
```

When you retrieve the corresponding configuration audit report, you'll see that there is one check with `LOW` severity
that's failing:

```console
$ kubectl get configauditreport configmap-test -o wide
NAME             SCANNER     AGE   CRITICAL  HIGH   MEDIUM   LOW
configmap-test   trivy-operator   24s   0         0      0        1
```

If you describe the report you'll see that it's failing because of our custom policy:

``` { .yaml .annotate }
apiVersion: aquasecurity.github.io/v1alpha1
kind: ConfigAuditReport
metadata:
  labels:
    trivy-operator.resource.kind: ConfigMap
    trivy-operator.resource.name: test
    trivy-operator.resource.namespace: default
    plugin-config-hash: df767ff5f
    resource-spec-hash: 7c96769cf
  name: configmap-test
  namespace: default
  ownerReferences:
  - apiVersion: v1
    blockOwnerDeletion: false
    controller: true
    kind: ConfigMap
    name: test
report:
  scanner:
    name: trivy-operator
    vendor: Aqua Security
    version: {{ git.tag }}
  summary:
    criticalCount: 0
    highCount: 0
    lowCount: 1
    mediumCount: 0
  checks:
  - checkID: recommended_labels  # (1)
    title: Recommended labels    # (2)
    severity: LOW                # (3)
    category: Kubernetes Security Check  # (4)
    description: |                       # (5)
      A common set of labels allows tools to work interoperably,
      describing objects in a common manner that all tools can
      understand.
    success: false  # (6)
    messages:       # (7)
    - 'You must provide labels: {"app.kubernetes.io/name", "app.kubernetes.io/version"}'
```

1. The `checkID` property corresponds to the policy identifier, i.e. `__rego_meatadata__.id`.
2. The `title` property as defined by the policy metadata in `__rego_metadata__.title`.
3. The `severity` property as defined by the policy metadata in `__rego_metadata__.severity`.
4. The `category` property as defined by the policy metadata in `__rego_metadata__.type`.
5. The `description` property as defined by the policy metadata in `__rego_metadata__.description`.
6. The flag indicating whether the configuration audit check has failed or passed.
7. The array of messages with details in case of failure.

[Built-in Configuration Audit Policies]: ./../configuration-auditing/built-in-policies.md
[Rego]: https://www.openpolicyagent.org/docs/latest/#rego
[recommended labels]: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels

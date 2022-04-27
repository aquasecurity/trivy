package appshield.kubernetes.KSV038

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV038",
	"avd_id": "AVD-KSV-0038",
	"title": "Selector usage in network policies",
	"short_code": "selector-usage-in-network-policies",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network",
	"recommended_actions": "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options",
	"url": "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	not hasSelector(input.spec)
	msg := "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "podSelector")
	kubernetes.has_field(spec.podSelector, "matchLabels")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "namespaceSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "podSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "namespaceSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "podSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "podSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "namespaceSelector")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.spec.podSelector == {}
	contains(input.spec.policyType, "Egress")
}

hasSelector(spec) {
	lower(kubernetes.kind) == "networkpolicy"
	kubernetes.spec.podSelector == {}
	contains(input.spec.policyType, "Ingress")
}

contains(arr, elem) {
	arr[_] = elem
}

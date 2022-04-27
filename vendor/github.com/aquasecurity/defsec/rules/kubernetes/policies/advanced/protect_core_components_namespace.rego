package appshield.kubernetes.KSV037

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV037",
	"avd_id": "AVD-KSV-0037",
	"title": "User Pods should not be placed in kube-system namespace",
	"short_code": "no-user-pods-in-system-namespace",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "ensure that User pods are not placed in kube-system namespace",
	"recommended_actions": "Deploy the use pods into a designated namespace which is not kube-system.",
	"url": "https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	systemNamespaceInUse(input.metadata, input.spec)
	msg := sprintf("%s '%s' should not be set with 'kube-system' namespace", [kubernetes.kind, kubernetes.name])
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

systemNamespaceInUse(metadata, spec) {
	kubernetes.namespace == "kube-system"
	not core_component(metadata, spec)
}

core_component(metadata, spec) {
	kubernetes.has_field(metadata.labels, "tier")
	metadata.labels.tier == "control-plane"
	kubernetes.has_field(spec, "priorityClassName")
	spec.priorityClassName == "system-node-critical"
	kubernetes.has_field(metadata.labels, "component")
	coreComponentLabels := ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"]
	metadata.labels.component = coreComponentLabels[_]
}

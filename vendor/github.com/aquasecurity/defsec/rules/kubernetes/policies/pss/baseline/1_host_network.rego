package appshield.kubernetes.KSV009

import data.lib.kubernetes

default failHostNetwork = false

__rego_metadata__ := {
	"id": "KSV009",
	"avd_id": "AVD-KSV-0009",
	"title": "Access to host network",
	"short_code": "no-host-network",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
	"recommended_actions": "Do not set 'spec.template.spec.hostNetwork' to true.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork {
	kubernetes.host_networks[_] == true
}

deny[res] {
	failHostNetwork

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostNetwork' to true", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

package appshield.kubernetes.KSV023

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume = false

__rego_metadata__ := {
	"id": "KSV023",
	"avd_id": "AVD-KSV-0023",
	"title": "hostPath volumes mounted",
	"short_code": "no-mounted-hostpath",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "HostPath volumes must be forbidden.",
	"recommended_actions": "Do not set 'spec.volumes[*].hostPath'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

failHostPathVolume {
	volumes := kubernetes.volumes
	utils.has_key(volumes[_], "hostPath")
}

deny[res] {
	failHostPathVolume

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.volumes.hostPath'", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

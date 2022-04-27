package appshield.kubernetes.KSV039

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV039",
	"avd_id": "AVD-KSV-0039",
	"title": "limit range usage",
	"short_code": "limit-range-usage",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "ensure limit range policy has configure in order to limit resource usage for namespaces or nodes",
	"recommended_actions": "create limit range policy with a default request and limit, min and max request, for each container.",
	"url": "https://kubernetes.io/docs/concepts/policy/limit-range/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	not limitRangeConfigure
	msg := "limit range policy with a default request and limit, min and max request, for each container should be configure"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

limitRangeConfigure {
	lower(input.kind) == "limitrange"
	input.spec[limits]
	kubernetes.has_field(input.spec.limits[_], "type")
	kubernetes.has_field(input.spec.limits[_], "max")
	kubernetes.has_field(input.spec.limits[_], "min")
	kubernetes.has_field(input.spec.limits[_], "default")
	kubernetes.has_field(input.spec.limits[_], "defaultRequest")
}

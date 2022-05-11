package builtin.kubernetes.KSV039

import data.lib.kubernetes
import data.lib.result
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

limitRangeConfigure {
	lower(input.kind) == "limitrange"
	kubernetes.has_field(input.spec, "limits")
	limit := input.spec.limits[_]
	kubernetes.has_field(limit, "type")
	kubernetes.has_field(limit, "max")
	kubernetes.has_field(limit, "min")
	kubernetes.has_field(limit, "default")
	kubernetes.has_field(limit, "defaultRequest")
}

deny[res] {
	not limitRangeConfigure
	msg := "limit range policy with a default request and limit, min and max request, for each container should be configure"
	res := result.new(msg, input.spec)
}

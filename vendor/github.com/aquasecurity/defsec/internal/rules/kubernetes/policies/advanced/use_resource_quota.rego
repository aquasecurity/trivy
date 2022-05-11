package builtin.kubernetes.KSV040

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV040",
	"avd_id": "AVD-KSV-0040",
	"title": "resource quota usage",
	"short_code": "resource-quota-usage",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "ensure resource quota policy has configure in order to limit aggregate resource usage within namespace",
	"recommended_actions": "create resource quota policy with mem and cpu quota per each namespace",
	"url": "https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

resourceQuotaConfigure {
	lower(input.kind) == "resourcequota"
	input.spec[hard]
	kubernetes.has_field(input.spec.hard, "requests.cpu")
	kubernetes.has_field(input.spec.hard, "requests.memory")
	kubernetes.has_field(input.spec.hard, "limits.cpu")
	kubernetes.has_field(input.spec.hard, "limits.memory")
}

deny[res] {
	not resourceQuotaConfigure
	msg := "resource quota policy with hard memory and cpu quota per namespace should be configure"
	res := result.new(msg, object.get(input.spec, "hard", input.spec))
}

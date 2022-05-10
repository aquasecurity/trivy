package builtin.kubernetes.KSV007

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV007",
	"avd_id": "AVD-KSV-0007",
	"title": "hostAliases is set",
	"short_code": "no-hostaliases",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started.",
	"recommended_actions": "Do not set 'spec.template.spec.hostAliases'.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failHostAliases is true if spec.hostAliases is set (on all controllers)
failHostAliases[spec] {
	spec := kubernetes.host_aliases[_]
	utils.has_key(spec, "hostAliases")
}

deny[res] {
	spec := failHostAliases[_]
	msg := kubernetes.format(sprintf("'%s' '%s' in '%s' namespace should not set spec.template.spec.hostAliases", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, spec)
}

package builtin.kubernetes.KSV011

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failLimitsCPU = false

__rego_metadata__ := {
	"id": "KSV011",
	"avd_id": "AVD-KSV-0011",
	"title": "CPU not limited",
	"short_code": "limit-cpu",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enforcing CPU limits prevents DoS via resource exhaustion.",
	"recommended_actions": "Set a limit value under 'containers[].resources.limits.cpu'.",
	"url": "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.limits, "cpu")
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers[container] {
	container := kubernetes.containers[_]
	not getLimitsCPUContainers[container]
}

deny[res] {
	output := getNoLimitsCPUContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.limits.cpu'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

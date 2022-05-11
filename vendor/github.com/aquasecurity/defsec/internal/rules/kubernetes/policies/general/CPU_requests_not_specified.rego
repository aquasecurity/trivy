package builtin.kubernetes.KSV015

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failRequestsCPU = false

__rego_metadata__ := {
	"id": "KSV015",
	"avd_id": "AVD-KSV-0015",
	"title": "CPU requests not specified",
	"short_code": "no-unspecified-cpu-requests",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.",
	"recommended_actions": "Set 'containers[].resources.requests.cpu'.",
	"url": "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getRequestsCPUContainers returns all containers which have set resources.requests.cpu
getRequestsCPUContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.requests, "cpu")
}

# getNoRequestsCPUContainers returns all containers which have not set
# resources.requests.cpu
getNoRequestsCPUContainers[container] {
	container := kubernetes.containers[_]
	not getRequestsCPUContainers[container]
}

deny[res] {
	output := getNoRequestsCPUContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.requests.cpu'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

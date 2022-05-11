package builtin.kubernetes.KSV016

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failRequestsMemory = false

__rego_metadata__ := {
	"id": "KSV016",
	"avd_id": "AVD-KSV-0016",
	"title": "Memory requests not specified",
	"short_code": "no-unspecified-memory-requests",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.",
	"recommended_actions": "Set 'containers[].resources.requests.memory'.",
	"url": "https://kubesec.io/basics/containers-resources-limits-memory/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getRequestsMemoryContainers returns all containers which have set resources.requests.memory
getRequestsMemoryContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.requests, "memory")
}

# getNoRequestsMemoryContainers returns all containers which have not set
# resources.requests.memory
getNoRequestsMemoryContainers[container] {
	container := kubernetes.containers[_]
	not getRequestsMemoryContainers[container]
}

deny[res] {
	output := getNoRequestsMemoryContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.requests.memory'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

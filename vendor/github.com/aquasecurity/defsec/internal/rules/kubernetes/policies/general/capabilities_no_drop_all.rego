package builtin.kubernetes.KSV003

import data.lib.kubernetes
import data.lib.result

default checkCapsDropAll = false

__rego_metadata__ := {
	"id": "KSV003",
	"avd_id": "AVD-KSV-0003",
	"title": "Default capabilities not dropped",
	"short_code": "drop-default-capabilities",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "The container should drop all default capabilities and add only those that are needed for its execution.",
	"recommended_actions": "Add 'ALL' to containers[].securityContext.capabilities.drop.",
	"url": "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# Get all containers which include 'ALL' in security.capabilities.drop
getCapsDropAllContainers[container] {
	allContainers := kubernetes.containers[_]
	lower(allContainers.securityContext.capabilities.drop[_]) == "all"
	container := allContainers.name
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getCapsNoDropAllContainers[container] {
	container := kubernetes.containers[_]
	not getCapsDropAllContainers[container.name]
}

deny[res] {
	container := getCapsNoDropAllContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should add 'ALL' to 'securityContext.capabilities.drop'", [container.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, container)
}

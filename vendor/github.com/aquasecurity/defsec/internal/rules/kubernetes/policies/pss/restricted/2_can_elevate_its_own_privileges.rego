package builtin.kubernetes.KSV001

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default checkAllowPrivilegeEscalation = false

__rego_metadata__ := {
	"id": "KSV001",
	"avd_id": "AVD-KSV-0001",
	"title": "Process can elevate its own privileges",
	"short_code": "no-self-privesc",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
	"recommended_actions": "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.allowPrivilegeEscalation == false
	container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
	containerName := kubernetes.containers[_].name
	not getNoPrivilegeEscalationContainers[containerName]
	container := kubernetes.containers[_]
}

deny[res] {
	output := getPrivilegeEscalationContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

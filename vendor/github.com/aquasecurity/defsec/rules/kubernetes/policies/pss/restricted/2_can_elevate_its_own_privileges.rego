package appshield.kubernetes.KSV001

import data.lib.kubernetes
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
	container := kubernetes.containers[_].name
	not getNoPrivilegeEscalationContainers[container]
}

# checkAllowPrivilegeEscalation is true if any container has
# securityContext.allowPrivilegeEscalation set to true or not set.
checkAllowPrivilegeEscalation {
	count(getPrivilegeEscalationContainers) > 0
}

deny[res] {
	checkAllowPrivilegeEscalation

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [getPrivilegeEscalationContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

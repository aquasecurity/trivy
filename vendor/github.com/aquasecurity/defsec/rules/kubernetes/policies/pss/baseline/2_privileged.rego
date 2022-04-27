package appshield.kubernetes.KSV017

import data.lib.kubernetes

default failPrivileged = false

__rego_metadata__ := {
	"id": "KSV017",
	"avd_id": "AVD-KSV-0017",
	"title": "Privileged container",
	"short_code": "no-privileged-containers",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.",
	"recommended_actions": "Change 'containers[].securityContext.privileged' to 'false'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getPrivilegedContainers returns all containers which have
# securityContext.privileged set to true.
getPrivilegedContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.privileged == true
	container := allContainers.name
}

# failPrivileged is true if there is ANY container with securityContext.privileged
# set to true.
failPrivileged {
	count(getPrivilegedContainers) > 0
}

deny[res] {
	failPrivileged

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.privileged' to false", [getPrivilegedContainers[_], kubernetes.kind, kubernetes.name]))
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

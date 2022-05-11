package builtin.kubernetes.KSV017

import data.lib.kubernetes
import data.lib.result

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
	container := kubernetes.containers[_]
	container.securityContext.privileged == true
}

deny[res] {
	output := getPrivilegedContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.privileged' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

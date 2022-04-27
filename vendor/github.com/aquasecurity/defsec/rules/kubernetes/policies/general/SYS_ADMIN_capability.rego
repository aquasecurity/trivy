package appshield.kubernetes.KSV005

import data.lib.kubernetes

default failCapsSysAdmin = false

__rego_metadata__ := {
	"id": "KSV005",
	"avd_id": "AVD-KSV-0005",
	"title": "SYS_ADMIN capability added",
	"short_code": "no-sysadmin-capability",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
	"recommended_actions": "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.",
	"url": "https://kubesec.io/basics/containers-securitycontext-capabilities-add-index-sys-admin/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysAdmin[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.capabilities.add[_] == "SYS_ADMIN"
	container := allContainers.name
}

# failCapsSysAdmin is true if securityContext.capabilities.add
# includes 'SYS_ADMIN'.
failCapsSysAdmin {
	count(getCapsSysAdmin) > 0
}

deny[res] {
	failCapsSysAdmin

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should not include 'SYS_ADMIN' in 'securityContext.capabilities.add'", [getCapsSysAdmin[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

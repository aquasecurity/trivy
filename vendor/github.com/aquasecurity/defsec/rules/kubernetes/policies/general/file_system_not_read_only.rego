package appshield.kubernetes.KSV014

import data.lib.kubernetes

default failReadOnlyRootFilesystem = false

__rego_metadata__ := {
	"id": "KSV014",
	"avd_id": "AVD-KSV-0014",
	"title": "Root file system is not read-only",
	"short_code": "use-readonly-filesystem",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
	"recommended_actions": "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.",
	"url": "https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyFilesystem set to true.
getReadOnlyRootFilesystemContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.readOnlyRootFilesystem == true
	container := allContainers.name
}

# getNotReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyRootFilesystem set to false or not set at all.
getNotReadOnlyRootFilesystemContainers[container] {
	container := kubernetes.containers[_].name
	not getReadOnlyRootFilesystemContainers[container]
}

# failReadOnlyRootFilesystem is true if ANY container sets
# securityContext.readOnlyRootFilesystem set to false or not set at all.
failReadOnlyRootFilesystem {
	count(getNotReadOnlyRootFilesystemContainers) > 0
}

deny[res] {
	failReadOnlyRootFilesystem

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.readOnlyRootFilesystem' to true", [getNotReadOnlyRootFilesystemContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

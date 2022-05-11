package builtin.kubernetes.KSV029

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failRootGroupId = false

__rego_metadata__ := {
	"id": "KSV029",
	"avd_id": "AVD-KSV-0029",
	"title": "A root primary or supplementary GID set",
	"short_code": "no-run-root-gid",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Containers should be forbidden from running with a root primary or supplementary GID.",
	"recommended_actions": "Set 'containers[].securityContext.runAsGroup' to a non-zero integer or leave undefined.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getContainersWithRootGroupId returns a list of containers
# with root group id set
getContainersWithRootGroupId[name] {
	container := kubernetes.containers[_]
	container.securityContext.runAsGroup == 0
	name := container
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
	pod := kubernetes.pods[_]
	pod.spec.securityContext.runAsGroup == 0
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
	pod := kubernetes.pods[_]
	utils.has_key(pod.spec.securityContext, "supplementalGroups")
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
	pod := kubernetes.pods[_]
	utils.has_key(pod.spec.securityContext, "fsGroup")
}

deny[res] {
	failRootGroupId

	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

deny[res] {
	output := getContainersWithRootGroupId[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'spec.securityContext.runAsGroup' to integer greater than  0", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

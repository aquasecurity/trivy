package appshield.kubernetes.KSV030

import data.lib.kubernetes
import data.lib.utils

default failSeccompProfileType = false

__rego_metadata__ := {
	"id": "KSV030",
	"avd_id": "AVD-KSV-0030",
	"title": "Default Seccomp profile not set",
	"short_code": "use-default-seccomp",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "The RuntimeDefault seccomp profile must be required, or allow specific additional profiles.",
	"recommended_actions": "Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# containers
getContainersWithDisallowedSeccompProfileType[name] {
	container := kubernetes.containers[_]
	type := container.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
	name := container.name
}

# pods
failSeccompProfileType {
	pod := kubernetes.pods[_]
	type := pod.spec.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
}

# annotations (Kubernetes pre-v1.19)
failSeccompAnnotation {
	annotations := kubernetes.annotations[_]
	val := annotations["seccomp.security.alpha.kubernetes.io/pod"]
	val != "runtime/default"
}

# annotations
deny[res] {
	failSeccompAnnotation

	msg := kubernetes.format(sprintf("%s '%s' should set 'seccomp.security.alpha.kubernetes.io/pod' to 'runtime/default'", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

# pods
deny[res] {
	failSeccompProfileType

	msg := kubernetes.format(sprintf("%s '%s' should set 'spec.securityContext.seccompProfile.type' to 'RuntimeDefault'", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

# containers
deny[res] {
	count(getContainersWithDisallowedSeccompProfileType) > 0

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'spec.containers[*].securityContext.seccompProfile.type' to 'RuntimeDefault'", [getContainersWithDisallowedSeccompProfileType[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

package builtin.kubernetes.KSV022

import data.lib.kubernetes
import data.lib.result

default failAdditionalCaps = false

__rego_metadata__ := {
	"id": "KSV022",
	"avd_id": "AVD-KSV-0022",
	"title": "Non-default capabilities added",
	"short_code": "no-non-default-capabilities",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Adding NET_RAW or capabilities beyond the default set must be disallowed.",
	"recommended_actions": "Do not set spec.containers[*].securityContext.capabilities.add and spec.initContainers[*].securityContext.capabilities.add",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# Add allowed capabilities to this set
allowed_caps = set()

# getContainersWithDisallowedCaps returns a list of containers which have
# additional capabilities not included in the allowed capabilities list
getContainersWithDisallowedCaps[container] {
	container := kubernetes.containers[_]
	set_caps := {cap | cap := container.securityContext.capabilities.add[_]}
	caps_not_allowed := set_caps - allowed_caps
	count(caps_not_allowed) > 0
}

# cap_msg is a string of allowed capabilities to be print as part of deny message
caps_msg = "" {
	count(allowed_caps) == 0
} else = msg {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_caps)])
}

deny[res] {
	output := getContainersWithDisallowedCaps[_]
	msg := sprintf("Container '%s' of %s '%s' should not set 'securityContext.capabilities.add'%s", [output.name, kubernetes.kind, kubernetes.name, caps_msg])
	res := result.new(msg, output)
}

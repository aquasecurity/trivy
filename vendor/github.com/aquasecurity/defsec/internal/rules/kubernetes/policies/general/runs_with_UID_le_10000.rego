package builtin.kubernetes.KSV020

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failRunAsUser = false

__rego_metadata__ := {
	"id": "KSV020",
	"avd_id": "AVD-KSV-0020",
	"title": "Runs with low user ID",
	"short_code": "use-high-uid",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.",
	"recommended_actions": "Set 'containers[].securityContext.runAsUser' to an integer > 10000.",
	"url": "https://kubesec.io/basics/containers-securitycontext-runasuser/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getUserIdContainers returns the names of all containers which have
# securityContext.runAsUser less than or equal to 100000.
getUserIdContainers[container] {
	container := kubernetes.containers[_]
	container.securityContext.runAsUser <= 10000
}

# getUserIdContainers returns the names of all containers which do
# not have securityContext.runAsUser set.
getUserIdContainers[container] {
	container := kubernetes.containers[_]
	not utils.has_key(container.securityContext, "runAsUser")
}

# getUserIdContainers returns the names of all containers which do
# not have securityContext set.
getUserIdContainers[container] {
	container := kubernetes.containers[_]
	not utils.has_key(container, "securityContext")
}

deny[res] {
	output := getUserIdContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.runAsUser' > 10000", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

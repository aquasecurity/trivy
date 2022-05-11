package builtin.kubernetes.KSV027

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failProcMount = false

__rego_metadata__ := {
	"id": "KSV027",
	"avd_id": "AVD-KSV-0027",
	"title": "Non-default /proc masks set",
	"short_code": "no-custom-proc-mask",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "The default /proc masks are set up to reduce attack surface, and should be required.",
	"recommended_actions": "Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.securityContext, "procMount")
}

deny[res] {
	output := failProcMountOpts[_]
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.containers[*].securityContext.procMount' or 'spec.initContainers[*].securityContext.procMount'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

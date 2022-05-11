package builtin.kubernetes.KSV010

import data.lib.kubernetes
import data.lib.result

default failHostPID = false

__rego_metadata__ := {
	"id": "KSV010",
	"avd_id": "AVD-KSV-0010",
	"title": "Access to host PID",
	"short_code": "no-host-pid",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.",
	"recommended_actions": "Do not set 'spec.template.spec.hostPID' to true.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID {
	kubernetes.host_pids[_] == true
}

deny[res] {
	failHostPID
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostPID' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}

package builtin.kubernetes.KSV008

import data.lib.kubernetes
import data.lib.result

default failHostIPC = false

__rego_metadata__ := {
	"id": "KSV008",
	"avd_id": "AVD-KSV-0008",
	"title": "Access to host IPC namespace",
	"short_code": "no-shared-ipc-namespace",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.",
	"recommended_actions": "Do not set 'spec.template.spec.hostIPC' to true.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failHostIPC is true if spec.hostIPC is set to true (on all resources)
failHostIPC {
	kubernetes.host_ipcs[_] == true
}

deny[res] {
	failHostIPC
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostIPC' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}

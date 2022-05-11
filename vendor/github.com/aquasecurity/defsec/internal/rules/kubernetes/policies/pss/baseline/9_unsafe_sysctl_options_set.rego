package builtin.kubernetes.KSV026

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failSysctls = false

__rego_metadata__ := {
	"id": "KSV026",
	"avd_id": "AVD-KSV-0026",
	"title": "Unsafe sysctl options set",
	"short_code": "no-unsafe-sysctl",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node.",
	"recommended_actions": "Do not set 'spec.securityContext.sysctls' or set to values in an allowed subset",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# Add allowed sysctls
allowed_sysctls = {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

# failSysctls is true if a disallowed sysctl is set
failSysctls {
	pod := kubernetes.pods[_]
	set_sysctls := {sysctl | sysctl := pod.spec.securityContext.sysctls[_].name}
	sysctls_not_allowed := set_sysctls - allowed_sysctls
	count(sysctls_not_allowed) > 0
}

deny[res] {
	failSysctls
	msg := kubernetes.format(sprintf("%s '%s' should set 'securityContext.sysctl' to the allowed values", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}

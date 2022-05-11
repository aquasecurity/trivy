package builtin.kubernetes.KSV024

import data.lib.kubernetes
import data.lib.result

default failHostPorts = false

__rego_metadata__ := {
	"id": "KSV024",
	"avd_id": "AVD-KSV-0024",
	"title": "Access to host ports",
	"short_code": "no-host-port-access",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "HostPorts should be disallowed, or at minimum restricted to a known list.",
	"recommended_actions": "Do not set spec.containers[*].ports[*].hostPort and spec.initContainers[*].ports[*].hostPort.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# Add allowed host ports to this set
allowed_host_ports = set()

# getContainersWithDisallowedHostPorts returns a list of containers which have
# host ports not included in the allowed host port list
getContainersWithDisallowedHostPorts[container] {
	allContainers := kubernetes.containers[_]
	set_host_ports := {port | port := allContainers.ports[_].hostPort}
	host_ports_not_allowed := set_host_ports - allowed_host_ports
	count(host_ports_not_allowed) > 0
	container := allContainers.name
}

# host_ports_msg is a string of allowed host ports to be print as part of deny message
host_ports_msg = "" {
	count(allowed_host_ports) == 0
} else = msg {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_host_ports)])
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getContainersWitNohDisallowedHostPorts[container] {
	container := kubernetes.containers[_]
	not getContainersWithDisallowedHostPorts[container]
}

deny[res] {
	output := getContainersWitNohDisallowedHostPorts[_]
	msg := sprintf("Container '%s' of %s '%s' should not set host ports, 'ports[*].hostPort'%s", [getContainersWithDisallowedHostPorts[_], kubernetes.kind, kubernetes.name, host_ports_msg])
	res := result.new(msg, output)
}

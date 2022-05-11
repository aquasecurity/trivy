package builtin.kubernetes.KSV006

import data.lib.kubernetes
import data.lib.result

name = input.metadata.name

default checkDockerSocket = false

__rego_metadata__ := {
	"id": "KSV006",
	"avd_id": "AVD-KSV-0006",
	"title": "hostPath volume mounted with docker.sock",
	"short_code": "no-docker-sock-mount",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Mounting docker.sock from the host can give the container full root access to the host.",
	"recommended_actions": "Do not specify /var/run/docker.socket in 'spec.template.volumes.hostPath.path'.",
	"url": "https://kubesec.io/basics/spec-volumes-hostpath-path-var-run-docker-sock/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# checkDockerSocket is true if volumes.hostPath.path is set to /var/run/docker.sock
# and is false if volumes.hostPath is set to some other path or not set.
checkDockerSocket {
	volumes := kubernetes.volumes
	volumes[_].hostPath.path == "/var/run/docker.sock"
}

deny[res] {
	checkDockerSocket
	msg := kubernetes.format(sprintf("%s '%s' should not specify '/var/run/docker.socker' in 'spec.template.volumes.hostPath.path'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}

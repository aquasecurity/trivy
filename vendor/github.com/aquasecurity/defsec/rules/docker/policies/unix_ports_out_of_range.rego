package appshield.dockerfile.DS008

import data.lib.docker

__rego_metadata__ := {
	"id": "DS008",
	"avd_id": "AVD-DS-0008",
	"title": "Exposed port out of range",
	"short_code": "port-out-of-range",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "UNIX ports outside the range 0-65535 are exposed.",
	"recommended_actions": "Use port number within range",
	"url": "https://docs.docker.com/engine/reference/builder/#expose",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

invalid_ports[output] {
	expose := docker.expose[_]
	port := to_number(split(expose.Value[_], "/")[0])
	port > 65535
	output := {
		"port": port,
		"cmd": expose,
	}
}

deny[res] {
	output := invalid_ports[_]
	msg := sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [output.port])
	res := docker.result(msg, output.cmd)
}

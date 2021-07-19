package user.dockerfile.ID002

import data.services

__rego_metadata__ := {
	"id": "ID002",
	"title": "Disallowed ports exposed",
	"severity": "HIGH",
	"type": "Docker Custom Check",
}

__rego_input__ := {"selector": [{"type": "dockerfile"}]}

deny[res] {
	expose := input.stages[_][_]
	expose.Cmd == "expose"
	exposed_port := expose.Value[_]

	disallowed_port := services.ports[_]

	exposed_port == disallowed_port
	res := sprintf("Port %s should not be exposed", [exposed_port])
}

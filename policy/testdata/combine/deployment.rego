package testdata.xyz_200

import data.services

__rego_metadata__ := {
	"id": "XYZ-200",
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

warn[msg] {
	input.kind == "Deployment"
	services.ports[_] == 22
	msg := sprintf("deny %s", [input.metadata.name])
}

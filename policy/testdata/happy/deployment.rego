package testdata.xyz_100

import data.services

__rego_metadata__ := {
	"id": "XYZ-100",
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"severity": "High",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[msg] {
	input.kind == "Deployment"
	services.ports[_] == 22
	msg := sprintf("deny %s", [input.metadata.name])
}

package testdata.xyz_100

import data.services

__rego_metadata__ := {
	"id": "XYZ-100",
	"title": "Bad Combined Deployment",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "kubernetes"}],
}

warn[res] {
	input[i].contents.kind == "Deployment"
	services.ports[_] == 22
	res := {"msg": sprintf("deny combined %s", [input[i].contents.metadata.name])}
}

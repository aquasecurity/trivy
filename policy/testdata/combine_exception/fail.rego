package testdata.xyz_300

import data.services

__rego_metadata__ := {
	"id": "XYZ-300",
	"title": "Always Fail",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	res := {
		"filepath": input[i].path,
		"msg": sprintf("deny combined %s", [input[i].contents.metadata.name]),
	}
}

package testdata.xyz_300

import data.services

__rego_metadata__ := {
	"id": "XYZ-300",
	"title": "Bad Dockerfile",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Docker Security Check",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	res := {
		"filepath": input[_].path,
		"msg": "bad",
	}
}

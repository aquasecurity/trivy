package testdata.xyz_200

__rego_metadata__ := {
	"id": "XYZ-200",
	"title": "Bad FROM",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Docker Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[msg] {
	msg := "bad Dockerfile"
}

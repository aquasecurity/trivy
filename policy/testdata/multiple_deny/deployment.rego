package testdata.xyz_100

__rego_metadata__ := {
	"id": "XYZ-100",
	"title": "Something Bad",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny %s", [input.metadata.name])
}

deny[msg] {
	input.kind == "Pod"
	msg := sprintf("deny %s", [input.metadata.name])
}

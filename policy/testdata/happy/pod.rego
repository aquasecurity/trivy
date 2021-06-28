package testdata.xyz_300

__rego_metadata__ := {
	"id": "XYZ-300",
	"title": "Bad Pod",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

deny[msg] {
	input.kind == "Pod"
	msg := sprintf("deny %s", [input.metadata.name])
}

package testdata.kubernetes.xyz_100

__rego_metadata__ := {
	"id": "XYZ-100",
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
}

deny_foo[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny foo %s", [input.metadata.name])
}

deny_bar[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny bar %s", [input.metadata.name])
}

exception[rules] {
	rules = ["foo"]
}

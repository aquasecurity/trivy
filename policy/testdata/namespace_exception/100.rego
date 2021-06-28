package testdata.kubernetes.xyz_100

__rego_metadata__ := {
	"id": "XYZ-100",
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
}

deny[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny 100 %s", [input.metadata.name])
}

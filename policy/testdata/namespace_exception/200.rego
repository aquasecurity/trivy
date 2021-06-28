package testdata.kubernetes.xyz_200

__rego_metadata__ := {
	"id": "XYZ-200",
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
}

deny[res] {
	input.kind == "Deployment"
	res := {"msg": sprintf("deny 200 %s", [input.metadata.name])}
}

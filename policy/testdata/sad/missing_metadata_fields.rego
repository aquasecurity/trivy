package testdata.kubernetes.xyz_100

__rego_metadata__ := {
	"title": "Bad Deployment",
	"version": "v1.0.0",
	"type": "Kubernetes Security Check",
}

deny[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny %s", [input.metadata.name])
}

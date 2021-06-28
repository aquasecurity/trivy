package testdata.kubernetes.xyz_100

__rego_metadata__ := "broken"

deny[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny %s", [input.metadata.name])
}

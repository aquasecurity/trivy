package testdata.kubernetes.xyz_100

deny[msg] {
	input.kind == "Deployment"
	msg := sprintf("deny %s", [input.metadata.name])
}

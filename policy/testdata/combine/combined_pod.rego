package testdata.xyz_400

__rego_metadata__ := {
	"id": "XYZ-400",
	"title": "Bad Combined Pod",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	input[i].contents.kind == "Pod"
	res := {
		"filepath": input[i].path,
		"msg": sprintf("deny combined %s", [input[i].contents.metadata.name]),
	}
}
